#include <homekit/homekit.h>
#include "homekit/characteristics.h"
#include "homekit/service.h"

static const char *TAG = "esp-homekit-service";

char * const kHKSAccessoryInfoId               = "0000003E-0000-1000-8000-0026BB765291";
char * const kHKSFanId                         = "00000040-0000-1000-8000-0026BB765291";
char * const kHKSGarageDoorOpenerId            = "00000041-0000-1000-8000-0026BB765291";
char * const kHKSLightbulbId                   = "00000043-0000-1000-8000-0026BB765291";
char * const kHKSLockManagementId              = "00000044-0000-1000-8000-0026BB765291";
char * const kHKSLockMechanismId               = "00000045-0000-1000-8000-0026BB765291";
char * const kHKSOutletId                      = "00000047-0000-1000-8000-0026BB765291";
char * const kHKSSwitchId                      = "00000049-0000-1000-8000-0026BB765291";
char * const kHKSThermostatId                  = "0000004A-0000-1000-8000-0026BB765291";
char * const kHKSAirQualitySensorId            = "0000008D-0000-1000-8000-0026BB765291";
char * const kHKSSecuritySystemId              = "0000007E-0000-1000-8000-0026BB765291";
char * const kHKSCarbonMonoxSensorId           = "0000007F-0000-1000-8000-0026BB765291";
char * const kHKSContactSensorId               = "00000080-0000-1000-8000-0026BB765291";
char * const kHKSDoorId                        = "00000081-0000-1000-8000-0026BB765291";
char * const kHKSHumiditySensorId              = "00000082-0000-1000-8000-0026BB765291";
char * const kHKSLeakSensorId                  = "00000083-0000-1000-8000-0026BB765291";
char * const kHKSLightSensorId                 = "00000084-0000-1000-8000-0026BB765291";
char * const kHKSMotionSensorId                = "00000085-0000-1000-8000-0026BB765291";
char * const kHKSOccupancySensorId             = "00000086-0000-1000-8000-0026BB765291";
char * const kHKSSmokeSensorId                 = "00000087-0000-1000-8000-0026BB765291";
char * const kHKSStatelessProgrammableSwitchId = "00000089-0000-1000-8000-0026BB765291";
char * const kHKSTempSensorId                  = "0000008A-0000-1000-8000-0026BB765291";
char * const kHKSWindowId                      = "0000008B-0000-1000-8000-0026BB765291";
char * const kHKSWindowCoveringId              = "0000008C-0000-1000-8000-0026BB765291";
char * const kHKSBatteryServiceId              = "00000096-0000-1000-8000-0026BB765291";
char * const kHKSCarbonDioxSensorId            = "00000097-0000-1000-8000-0026BB765291";
char * const kHKSCameraRTPStreamMgmtId         = "00000110-0000-1000-8000-0026BB765291";
char * const kHKSMicrophoneId                  = "00000112-0000-1000-8000-0026BB765291";
char * const kHKSSpeakerId                     = "00000113-0000-1000-8000-0026BB765291";
char * const kHKSDoorbellId                    = "00000121-0000-1000-8000-0026BB765291";
char * const kHKSFanV2Id                       = "000000B7-0000-1000-8000-0026BB765291";
char * const kHKSSlatId                        = "000000B9-0000-1000-8000-0026BB765291";
char * const kHKSFilterMaintenanceId           = "000000BA-0000-1000-8000-0026BB765291";
char * const kHKSAirPurifierId                 = "000000BB-0000-1000-8000-0026BB765291";
char * const kHKSServiceLabelId                = "000000CC-0000-1000-8000-0026BB765291";

hk_service_t *hk_service_new(char *id)
{
    ASSERT(id == NULL);

    hk_service_t *service = malloc(sizeof(hk_service_t));
    if (service) {
        memset(service, 0, sizeof(hk_service_t));
        service->id = id;
    }

    return service;
}

void hk_service_set_characteristics(hk_service_t *service, hk_characteristic_t **chs, size_t count)
{
    ASSERT(service == NULL);
    ASSERT(chs == NULL);

    if (count) {
        service->characteristics = malloc(sizeof(hk_characteristic_t) * count);
        if (service->characteristics) {
            memcpy(service->characteristics, chs, sizeof(hk_characteristic_t) * count);
            service->characteristic_count = count;
        }
    }
}

void hk_service_add_characteristic(hk_service_t *service, hk_characteristic_t *ch)
{
    ASSERT(service == NULL);
    ASSERT(ch == NULL);

    hk_characteristic_t *existing_ch = hk_service_get_characteristic(service, ch->id);
    if (!existing_ch) {
        hk_characteristic_t **chs = realloc(service->characteristics,
                                    sizeof(hk_characteristic_t *) * ++service->characteristic_count);
        if (!chs) {
            LOG_DEBUG("error reallocating characteristics for service %p", service);
            return;
        }

        service->characteristics = chs;
        service->characteristics[service->characteristic_count - 1] = ch;
    }
}

void hk_service_free(hk_service_t *service)
{
    if (service) {
        for (size_t i = 0; i < service->characteristic_count; i++) {
            hk_characteristic_free(service->characteristics[i]);
        }

        free(service);
    }
}

hk_characteristic_t *hk_service_get_characteristic(hk_service_t *service, char *id)
{
    ASSERT(service == NULL);
    ASSERT(id == NULL);

    for (size_t i = 0; i < service->characteristic_count; i++) {
        if (!strcmp(service->characteristics[i]->id, id))
            return service->characteristics[i];
    }

    return NULL;
}

hk_service_t *hk_service_new_accessory_info(void)
{
    hk_service_t *service = hk_service_new(kHKSAccessoryInfoId);
    if (service) {
        hk_characteristic_t *identify_chr = hk_characteristic_new_identify();
        hk_characteristic_t *manuf_chr = hk_characteristic_new_manufacturer();
        hk_characteristic_t *model_chr = hk_characteristic_new_model();
        hk_characteristic_t *name_chr = hk_characteristic_new_name();
        hk_characteristic_t *serial_chr = hk_characteristic_new_serial_number();
        hk_characteristic_t *firmrev_chr = hk_characteristic_new_firmware_revision();

        hk_characteristic_t *chrs[6] = {
            identify_chr, manuf_chr, model_chr, name_chr, serial_chr, firmrev_chr
        };

        hk_service_set_characteristics(service, chrs, array_len(chrs));
    }


    return service;
}

hk_service_t *hk_service_new_switch(void)
{
    hk_service_t *service = hk_service_new(kHKSSwitchId);
    if (service) {
        hk_characteristic_t *on_chr = hk_characteristic_new_on();
        hk_characteristic_t *name_chr = hk_characteristic_new_name();

        hk_characteristic_t *chrs[2] = {on_chr, name_chr};
        hk_service_set_characteristics(service, chrs, array_len(chrs));
    }

    return service;
}

hk_service_t *hk_service_new_humidity_sensor(void)
{
    hk_service_t *service = hk_service_new(kHKSHumiditySensorId);
    if (service) {
        hk_characteristic_t * curr_hum_chr = hk_characteristic_new_current_humidity();

        hk_characteristic_t *chrs[1] = {curr_hum_chr};
        hk_service_set_characteristics(service, chrs, array_len(chrs));
    }

    return service;
}

hk_service_t *hk_service_new_temp_sensor(void)
{
    hk_service_t *service = hk_service_new(kHKSTempSensorId);
    if (service) {
        hk_characteristic_t * curr_temp_chr = hk_characteristic_new_current_temp();

        hk_characteristic_t *chrs[1] = {curr_temp_chr};
        hk_service_set_characteristics(service, chrs, array_len(chrs));
    }

    return service;
}
