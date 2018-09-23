# homekit

A C library that implements the HomeKit Accessory Protocol (HAP) intended for embedded platforms.

Currently it is only tested on the ESP32 series of SoCs, but should cross compile for ARM and other embedded environments. The only external dependency is wolfcrypt for cryptographic routines.

### Structure

The project is structured as a standard ESP-IDF project, which has it's own application and dependent components:

```
- main
  - ...
- components
  - esp-homekit
  - esphttpd
  - wolfcrypt
```

`main` consist of what is currently an example implementation of a HomeKit-enabled ESP32 accessory. `components` consists of:

1. the main esp-homekit component which houses the HomeKit library
2. other libraries / components that esp-homekit depends on (esphttpd, mbedtls-csrp, etc). Some of these libraries are home grown for the purpose of this project, and some are other open source projects. The README in each component will provide more information.

### Usage

Using esp-homekit is as simple as copying the contents of the `components` directory into your projects components directory, and then implementing the required APIs. The sample implementation in `main` can be used as a reference.

Below is a simple example that implements a switch IP accessory using an ESP32 / esp-idf:

```c

// homekit requires device IDs to be in the format of a MAC address
uint8_t mac[6];
char mac_str[12];

esp_err_t err = esp_read_mac(mac, ESP_MAC_WIFI_STA);
if (err != ESP_OK) {
  LOG_ERROR("failed to read WiFi MAC address (%d)", err);
  return;
}

sprintf(mac_str, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

hk_accessory_t *accessory = hk_init(HK_ACCESSORY_CATEGORY_SWITCH, mac_str, "SampleDevice0,1");
hk_set_setup_code(accessory, "376-01-938");

// set the storage path where the accessory state will be persisted
hk_err_t hkerr = hk_set_storage_path(accessory, "/storage/switch.hka");
if (hkerr != HK_ERR_OK)
  LOG_ERROR("failed to initialize homekit storage (%d)", hkerr);

// homekit calls our hk_mdns_updater callback when mDNS TXT values need to be updated
hk_set_update_mdns_func(accessory, hk_mdns_updater);

// all accessories require an accessory info service
hk_service_t *info_service = hk_service_new_accessory_info();

hk_characteristic_set_value(hk_service_get_characteristic(info_service, kHKCManufacturerId),
                          hk_characteristic_value_from_string("ESPHomekit"));
hk_characteristic_set_value(hk_service_get_characteristic(info_service, kHKCModelId),
                          hk_characteristic_value_from_string("SampleDevice0,1"));
hk_characteristic_set_value(hk_service_get_characteristic(info_service, kHKCNameId),
                          hk_characteristic_value_from_string("Sample Switch Accessory"));
hk_characteristic_set_value(hk_service_get_characteristic(info_service, kHKCSerialNumberId),
                          hk_characteristic_value_from_string("1234567890"));
hk_characteristic_set_value(hk_service_get_characteristic(info_service, kHKCFirmwareRevisionId),
                          hk_characteristic_value_from_string("1.0.0"));

// the switch is the primary function of this accessory, so mark it as the primary
hk_service_t *switch_service = hk_service_new_switch();
switch_service->is_primary = true;

hk_characteristic_set_value(hk_service_get_characteristic(switch_service, kHKCNameId),
                          hk_characteristic_value_from_string("Switch"));

hk_characteristic_t *on_ch = hk_service_get_characteristic(switch_service, kHKCOnId);

// set a callback for when the switch state value is changed via homekit
on_ch->change_func = switch_change_handler;

hk_add_service(accessory, info_service);
hk_add_service(accessory, switch_service);

// start the homekit IP accessory server
hkerr = hk_ip_start(accessory, HK_DEFAULT_IP_PORT);
if (hkerr != HK_ERR_OK) {
  LOG_ERROR("failed to start homekit IP server (%d)", err);
}
```