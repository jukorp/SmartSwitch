#ifndef _HK_SERVICE_H_
#define _HK_SERVICE_H

#include "characteristics.h"

extern char * const kHKSAccessoryInfoId;
extern char * const kHKSFanId;
extern char * const kHKSGarageDoorOpenerId;
extern char * const kHKSLightbulbId;
extern char * const kHKSLockManagementId;
extern char * const kHKSLockMechanismId;
extern char * const kHKSOutletId;
extern char * const kHKSSwitchId;
extern char * const kHKSThermostatId;
extern char * const kHKSAirQualitySensorId;
extern char * const kHKSSecuritySystemId;
extern char * const kHKSCarbonMonoxSensorId;
extern char * const kHKSContactSensorId;
extern char * const kHKSDoorId;
extern char * const kHKSHumiditySensorId;
extern char * const kHKSLeakSensorId;
extern char * const kHKSLightSensorId;
extern char * const kHKSMotionSensorId;
extern char * const kHKSOccupancySensorId;
extern char * const kHKSSmokeSensorId;
extern char * const kHKSStatelessProgrammableSwitchId;
extern char * const kHKSTempSensorId;
extern char * const kHKSWindowId;
extern char * const kHKSWindowCoveringId;
extern char * const kHKSBatteryServiceId;
extern char * const kHKSCarbonDioxSensorId;
extern char * const kHKSCameraRTPStreamMgmtId;
extern char * const kHKSMicrophoneId;
extern char * const kHKSSpeakerId;
extern char * const kHKSDoorbellId;
extern char * const kHKSFanV2Id;
extern char * const kHKSSlatId;
extern char * const kHKSFilterMaintenanceId;
extern char * const kHKSAirPurifierId;
extern char * const kHKSServiceLabelId;

// hk_service_new allocates and returns a new hk_service_t.
hk_service_t *hk_service_new(char *id);

// hk_service_set_characteristics sets the characteristics for service to the array of
// characteristics in chs.
void hk_service_set_characteristics(hk_service_t *service, hk_characteristic_t **chs, size_t count);

// hk_service_add_characteristic adds characteristic ch to service.
void hk_service_add_characteristic(hk_service_t *service, hk_characteristic_t *ch);

// hk_service_free frees an hk_service_t that was originally allocated by hk_service_new.
void hk_service_free(hk_service_t *service);

// hk_service_get_characteristic returns the characteristic that matches type. This function is useful
// for getting a characteristic that was created by the homekit library (Apple-defined services).
// Returns NULL if there was no matching characteristic.
hk_characteristic_t *hk_service_get_characteristic(hk_service_t *service, char *id);

hk_service_t *hk_service_new_accessory_info(void);

hk_service_t *hk_service_new_switch(void);

hk_service_t *hk_service_new_humidity_sensor(void);

hk_service_t *hk_service_new_temp_sensor(void);

#endif
