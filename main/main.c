#include <stdio.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <esp_system.h>
#include <nvs_flash.h>
#include <esp_wifi.h>
#include <esp_event_loop.h>
#include <esp_log.h>
#include <mdns.h>
#include <homekit/homekit.h>
#include <homekit/service.h>
#include <homekit/characteristics.h>
#include <PanicReporter.h>
#include <utils.h>
#include <esp_spiffs.h>
#include "debug.h"

#define FIRMWARE_VERSION "0.1"
#define DEVICE_MODEL     "SmartSwitch0"

#define STORAGE_PATH "/storage"
#define ACCESSORY_FILE_PATH STORAGE_PATH"/accessory.hka"

static const char *TAG = "SmartSwitch";

hk_accessory_t *accessory = NULL;

static void switch_change_handler(hk_accessory_t *ctx, hk_characteristic_t *ch)
{
    LOG_INFO("switch state changed: %s", ch->value);

    bool switch_on = atoi(ch->value);
    gpio_set_level(26, switch_on ? 1 : 0);
}

static esp_err_t wifi_event_handler(void *ctx, system_event_t *event)
{
    switch (event->event_id) {
    case SYSTEM_EVENT_STA_START:
        LOG_INFO("station start");
        break;

    case SYSTEM_EVENT_STA_CONNECTED:
        LOG_INFO("station connected");
        break;

    case SYSTEM_EVENT_STA_GOT_IP:
        LOG_INFO("station acquired IP %d.%d.%d.%d", IP2STR(&event->event_info.got_ip.ip_info.ip));
        break;

    case SYSTEM_EVENT_STA_DISCONNECTED:
        LOG_INFO("station disconnected");
        break;

    case SYSTEM_EVENT_STA_LOST_IP:
        LOG_INFO("station lost IP");
        esp_wifi_connect();
        break;

    default:
        break;
    }

    mdns_handle_system_event(ctx, event);

    return ESP_OK;
}

static void _fs_init(void)
{
    esp_vfs_spiffs_conf_t conf = {
        .base_path = STORAGE_PATH,
        .partition_label = NULL,
        .max_files = 5,
        .format_if_mount_failed = true,
    };

    esp_err_t err = esp_vfs_spiffs_register(&conf);
    if (err != ESP_OK) {
        if (err == ESP_FAIL) {
            LOG_ERROR("failed to mount or format filesystem");
        } else if (err == ESP_ERR_NOT_FOUND) {
            LOG_ERROR("storage partition not found");
        } else {
            LOG_ERROR("failed to initialize filesystem (%d)", err);
        }

        return;
    }

    LOG_INFO("filesystem mounted at %s", STORAGE_PATH);

    size_t total = 0, used = 0;
    err = esp_spiffs_info(NULL, &total, &used);
    if (err != ESP_OK) {
        LOG_ERROR("failed to calculate filesystem usage");
        return;
    }

    double usage = (double)(used / total);
    LOG_INFO("filesystem size total: %d used: %d (%0.1f%%)", total, used, usage);

}

static void _wifi_init(void)
{
    nvs_flash_init();
    tcpip_adapter_init();
    esp_event_loop_init(wifi_event_handler, NULL);

    wifi_init_config_t config = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&config);

    wifi_config_t wifi_config = {
        .sta = {
            .ssid = "SEGFAULT",
            .password = "trytocr4ckme",
        }
    };

    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config);
    esp_wifi_start();
    esp_wifi_connect();
}

static void _mdns_init(void)
{
    esp_err_t err = mdns_init();
    if (err != ESP_OK) {
        LOG_ERROR("error initializing mDNS service (%d)", err);
        return;
    }

    err = mdns_hostname_set("smartswitch");
    if (err != ESP_OK) {
        LOG_ERROR("failed to set mDNS hostname (%d)", err);
        return;
    }

    err = mdns_instance_name_set("SmartSwitch");
    if (err != ESP_OK) {
        LOG_ERROR("failed to set mDNS instance name (%d)", err);
        return;
    }

    err = mdns_service_add("SmartSwitch", HK_MDNS_SERVICE_TYPE, HK_MDNS_SERVICE_PROTO, HK_DEFAULT_IP_PORT, NULL, 0);
    if (err != ESP_OK) {
        LOG_ERROR("failed to add %s mDNS service (%d)", HK_MDNS_SERVICE_TYPE, err);
        return;
    }
}

// TODO: take in an hk_accessory_t
void hk_mdns_updater(char txts[][3][32], uint8_t entries)
{
    // we used to use mdns_service_txt_set to do all of these at once, but after looking at esp-idf
    // mdns.c, they pass the pointers to the key and value to the queue for updating, meaning
    // our pointers need to stick around until whenever they have processed the update, with no
    // clean way of freeing them once they are done.
    // Their mdns_service_txt_item_set on the other hand, does a strdup.
    for (int i = 0; i < entries; i++) {
        LOG_DEBUG("will set txt %s -> %s", txts[i][0], txts[i][1]);
        mdns_service_txt_item_set(HK_MDNS_SERVICE_TYPE, HK_MDNS_SERVICE_PROTO, txts[i][0], txts[i][1]);
    }
}

 static void _homekit_init(void)
 {
     char *setup_code = "376-01-938";
     LOG_INFO("HomeKit setup code is %s", setup_code);

    uint8_t mac[6];
    esp_err_t err = esp_read_mac(mac, ESP_MAC_WIFI_STA);
    if (err != ESP_OK) {
        LOG_ERROR("failed to read WiFi MAC address (%d)", err);
        return;
    }

    char mac_str[12];
    sprintf(mac_str, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    LOG_INFO("MAC address is %s", mac_str);

     accessory = hk_init(HK_ACCESSORY_CATEGORY_SWITCH, mac_str, "SampleDevice0,1");
     hk_set_setup_code(accessory, setup_code);

     hk_err_t hkerr = hk_set_storage_path(accessory, ACCESSORY_FILE_PATH);
     if (hkerr != HK_ERR_OK)
        LOG_ERROR("failed to initialize homekit storage (%d)", hkerr);

    hk_set_update_mdns_func(accessory, hk_mdns_updater);

    hk_service_t *info_service = hk_service_new_accessory_info();

    hk_characteristic_set_value(hk_service_get_characteristic(info_service, kHKCManufacturerId),
                                hk_characteristic_value_from_string("ESPHomekit-Sample"));
    hk_characteristic_set_value(hk_service_get_characteristic(info_service, kHKCModelId),
                                hk_characteristic_value_from_string("SmartSwitch0,1"));
    hk_characteristic_set_value(hk_service_get_characteristic(info_service, kHKCNameId),
                                hk_characteristic_value_from_string("SmartSwitch"));
    hk_characteristic_set_value(hk_service_get_characteristic(info_service, kHKCSerialNumberId),
                                hk_characteristic_value_from_string("1234567890"));
    hk_characteristic_set_value(hk_service_get_characteristic(info_service, kHKCFirmwareRevisionId),
                                hk_characteristic_value_from_string(FIRMWARE_VERSION));

    hk_service_t *switch_service = hk_service_new_switch();
    switch_service->is_primary = true;

    hk_characteristic_set_value(hk_service_get_characteristic(switch_service, kHKCNameId),
                                hk_characteristic_value_from_string("Switch"));

    hk_characteristic_t *on_ch = hk_service_get_characteristic(switch_service, kHKCOnId);
    on_ch->change_func = switch_change_handler;

    hk_add_service(accessory, info_service);
    hk_add_service(accessory, switch_service);

    hkerr = hk_ip_start(accessory, HK_DEFAULT_IP_PORT);
    if (hkerr != HK_ERR_OK) {
        LOG_ERROR("failed to start homekit IP server (%d)", err);
    }
 }

 static void _gpio_init(void)
 {
     gpio_config_t io_config;
     io_config.intr_type = GPIO_INTR_DISABLE;
     io_config.mode = GPIO_MODE_OUTPUT;
     io_config.pin_bit_mask = (1LL << 26);
     io_config.pull_down_en = 0;
     io_config.pull_up_en = 0;

     gpio_config(&io_config);
 }

 void _panic_reporter_init(void)
{
    uint8_t mac[6];
    esp_err_t err = esp_read_mac(mac, ESP_MAC_WIFI_STA);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "failed to read WiFi MAC address (%d)", err);
        return;
    }

    static char mac_str[13];
    sprintf(mac_str, "%02x%02x%02x%02x%02x%02x", MAC2STR(mac));

    static PR_Config_t panicReporterConfig = {
        .reportingURL = "http://factory.nikharris.com/panic/submit",
        .reportingPort = 80,
        .deviceModel = DEVICE_MODEL,
        .firmwareVersion = FIRMWARE_VERSION,
        .deviceId = mac_str,
        .maxRetries = 20,
        .retryIntervalSec = 10
    };

    PR_Error_t prErr = PR_StartPanicReporter(&panicReporterConfig);
    if (prErr != PR_ERR_OK) {
        ESP_LOGE(TAG, "failed to start Panic Reporter (%d)", prErr);
    }
}

void app_main()
{
    print_chip_info();
    init_heap_debugging_task();
    _gpio_init();
    _fs_init();
    _mdns_init();
    _wifi_init();
    _panic_reporter_init();
    _homekit_init();
}
