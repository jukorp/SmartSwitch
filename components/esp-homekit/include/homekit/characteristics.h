#pragma once

#include "types.h"

// pre-defined characteristic type IDs
extern char * const kHKCAdminOnlyAccessId;
extern char * const kHKCAudioFeedbackId;
extern char * const kHKBrightnessId;
extern char * const kHKCCoolingThresholdTempId;
extern char * const kHKCCurrentDoorStateId;
extern char * const kHKCCurrentHeatingCoolingStateId;
extern char * const kHKCCurrentHumidityId;
extern char * const kHKCCurrentTempId;
extern char * const kHKCFirmwareRevisionId;
extern char * const kHKCHardwareRevisionId;
extern char * const kHKCHeatingThresholdTempId;
extern char * const kHKCHueId;
extern char * const kHKCIdentifyId;
extern char * const kHKCLockControlPointId;
extern char * const kHKCLockCurrentStateId;
extern char * const kHKCLockLastKnownActionId;
extern char * const kHKCLockMgmtAutoSecurityTimeoutId;
extern char * const kHKCLockTargetStateId;
extern char * const kHKCLogsId;
extern char * const kHKCManufacturerId;
extern char * const kHKCModelId;
extern char * const kHKCMotionDetectedId;
extern char * const kHKCNameId;
extern char * const kHKCObstructionDetectedId;
extern char * const kHKCOnId;
extern char * const kHKCOutletInUseId;
extern char * const kHKCRotationDirectionId;
extern char * const kHKCRotationSpeedId;
extern char * const kHKCSaturationId;
extern char * const kHKCSerialNumberId;
extern char * const kHKCTargetDoorStateId;
extern char * const kHKCTargetHeatingCoolingStateId;
extern char * const kHKCTargetHumidityId;
extern char * const kHKCTargetTempId;
extern char * const kHKCTempDisplayUnitsId;
extern char * const kHKCVersionId;
extern char * const kHKCAirPartSizeId;
extern char * const kHKCSecuritySysCurrentStateId;
extern char * const kHKCSecuritySysTargetStateId;
extern char * const kHKCBatteryLevelId;
extern char * const kHKCCarbonMonoxDetectedId;
extern char * const kHKContactSensorStateId;

char *hk_characteristic_format_to_string(hk_value_format_t fmt);
hk_value_format_t hk_characteristic_format_from_string(char *fmt);

char *hk_characteristic_unit_to_string(hk_value_unit_t unit);

char *hk_characteristic_value_from_bool(uint8_t val);
char *hk_characteristic_value_from_double(double val);
char *hk_characteristic_value_from_int(int val);
char *hk_characteristic_value_from_string(char *val);

// the hk_c_value_from functions return a characteristic value from a given type.
// the response should be set directly to the characteristics value member.
char *hk_characteristic_value_from_bool(uint8_t val);
char *hk_characteristic_value_from_double(double val);
char *hk_characteristic_value_from_int(int val);
char *hk_characteristic_value_from_string(char *val);

void hk_short_guid_from_guid(char *guid, char short_guid[10]);

// hk_c_set_value sets the value for a given characteristic. This function should always be
// used, and the characteristic value should NEVER be set manually. Users of the library should use
// hk_update_value instead of this.
void hk_characteristic_set_value(hk_characteristic_t *c, char *val);

// hk_characteristic_set_change_func sets the callback to be invoked when a characteristic value
// has been changed.
void hk_characteristic_set_change_func(hk_characteristic_t *ch, hk_characteristic_change_func_t func);

hk_characteristic_t *hk_characteristic_new(char *id, hk_value_format_t fmt,
                                           hk_permission_t perms, hk_value_unit_t unit);

void hk_characteristic_free(hk_characteristic_t *ch);

hk_characteristic_t *hk_characteristic_new_admin_only_access(void);

hk_characteristic_t *hk_characteristic_new_audio_feedback(void);

hk_characteristic_t *hk_characteristic_new_brightness(void);

hk_characteristic_t *hk_characteristic_new_cooling_threshold_temp(void);

hk_characteristic_t *hk_characteristic_new_current_door_state(void);

hk_characteristic_t *hk_characteristic_new_current_heating_cooling_state(void);

hk_characteristic_t *hk_characteristic_new_current_humidity(void);

hk_characteristic_t *hk_characteristic_new_current_temp(void);

hk_characteristic_t *hk_characteristic_new_firmware_revision(void);

hk_characteristic_t *hk_characteristic_new_hardware_revision(void);

hk_characteristic_t *hk_characteristic_new_heating_threshold_temp(void);

hk_characteristic_t *hk_characteristic_new_hue(void);

hk_characteristic_t *hk_characteristic_new_identify(void);

hk_characteristic_t *hk_characteristic_new_lock_control_point(void);

hk_characteristic_t *hk_characteristic_new_lock_current_state(void);

hk_characteristic_t *hk_characteristic_new_lock_last_known_action(void);

hk_characteristic_t *hk_characteristic_new_lock_mgmt_auto_security_timeout(void);

hk_characteristic_t *hk_characteristic_new_lock_target_state(void);

hk_characteristic_t *hk_characteristic_new_logs(void);

hk_characteristic_t *hk_characteristic_new_manufacturer(void);

hk_characteristic_t *hk_characteristic_new_model(void);

hk_characteristic_t *hk_characteristic_new_motion_detected(void);

hk_characteristic_t *hk_characteristic_new_name(void);

hk_characteristic_t *hk_characteristic_new_obstruction_detected(void);

hk_characteristic_t *hk_characteristic_new_on(void);

hk_characteristic_t *hk_characteristic_new_outlet_in_use(void);

hk_characteristic_t *hk_characteristic_new_rotation_direction(void);

hk_characteristic_t *hk_characteristic_new_rotation_speed(void);

hk_characteristic_t *hk_characteristic_new_saturation(void);

hk_characteristic_t *hk_characteristic_new_serial_number(void);

hk_characteristic_t *hk_characteristic_new_target_door_state(void);

hk_characteristic_t *hk_characteristic_new_target_heating_cooling_state(void);

hk_characteristic_t *hk_characteristic_new_target_humidity(void);

hk_characteristic_t *hk_characteristic_new_target_temp(void);

hk_characteristic_t *hk_characteristic_new_temp_display_units(void);

hk_characteristic_t *hk_characteristic_new_version(void);

hk_characteristic_t *hk_characteristic_new_air_part_size(void);

hk_characteristic_t *hk_characteristic_new_security_sys_current_state(void);

hk_characteristic_t *hk_characteristic_new_security_sys_target_state(void);

hk_characteristic_t *hk_characteristic_new_battery_level(void);

hk_characteristic_t *hk_characteristic_new_carbon_monox_detected(void);

hk_characteristic_t *hk_characteristic_new_contact_sensor_state(void);

