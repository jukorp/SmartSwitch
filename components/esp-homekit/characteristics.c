#include <string.h>
#include <stdlib.h>
#include <utils.h>

#include "homekit/types.h"
#include "homekit/characteristics.h"

char * const kHKCAdminOnlyAccessId             = "00000001-0000-1000-8000-0026BB765291";
char * const kHKCAudioFeedbackId               = "00000005-0000-1000-8000-0026BB765291";
char * const kHKCBrightnessId                  = "00000008-0000-1000-8000-0026BB765291";
char * const kHKCCoolingThresholdTempId        = "0000000D-0000-1000-8000-0026BB765291";
char * const kHKCCurrentDoorStateId            = "0000000E-0000-1000-8000-0026BB765291";
char * const kHKCCurrentHeatingCoolingStateId  = "0000000F-0000-1000-8000-0026BB765291";
char * const kHKCCurrentHumidityId             = "00000010-0000-1000-8000-0026BB765291";
char * const kHKCCurrentTempId                 = "00000011-0000-1000-8000-0026BB765291";
char * const kHKCFirmwareRevisionId            = "00000052-0000-1000-8000-0026BB765291";
char * const kHKCHardwareRevisionId            = "00000053-0000-1000-8000-0026BB765291";
char * const kHKCHeatingThresholdTempId        = "00000012-0000-1000-8000-0026BB765291";
char * const kHKCHueId                         = "00000013-0000-1000-8000-0026BB765291";
char * const kHKCIdentifyId                    = "00000014-0000-1000-8000-0026BB765291";
char * const kHKCLockControlPointId            = "00000019-0000-1000-8000-0026BB765291";
char * const kHKCLockCurrentStateId            = "0000001D-0000-1000-8000-0026BB765291";
char * const kHKCLockLastKnownActionId         = "0000001C-0000-1000-8000-0026BB765291";
char * const kHKCLockMgmtAutoSecurityTimeoutId = "0000001A-0000-1000-8000-0026BB765291";
char * const kHKCLockTargetStateId             = "0000001E-0000-1000-8000-0026BB765291";
char * const kHKCLogsId                        = "0000001F-0000-1000-8000-0026BB765291";
char * const kHKCManufacturerId                = "00000020-0000-1000-8000-0026BB765291";
char * const kHKCModelId                       = "00000021-0000-1000-8000-0026BB765291";
char * const kHKCMotionDetectedId              = "00000022-0000-1000-8000-0026BB765291";
char * const kHKCNameId                        = "00000023-0000-1000-8000-0026BB765291";
char * const kHKCObstructionDetectedId         = "00000026-0000-1000-8000-0026BB765291";
char * const kHKCOnId                          = "00000025-0000-1000-8000-0026BB765291";
char * const kHKCOutletInUseId                 = "00000024-0000-1000-8000-0026BB765291";
char * const kHKCRotationDirectionId           = "00000028-0000-1000-8000-0026BB765291";
char * const kHKCRotationSpeedId               = "00000029-0000-1000-8000-0026BB765291";
char * const kHKCSaturationId                  = "0000002F-0000-1000-8000-0026BB765291";
char * const kHKCSerialNumberId                = "00000030-0000-1000-8000-0026BB765291";
char * const kHKCTargetDoorStateId             = "00000032-0000-1000-8000-0026BB765291";
char * const kHKCTargetHeatingCoolingStateId   = "00000032-0000-1000-8000-0026BB765291";
char * const kHKCTargetHumidityId              = "00000034-0000-1000-8000-0026BB765291";
char * const kHKCTargetTempId                  = "00000035-0000-1000-8000-0026BB765291";
char * const kHKCTempDisplayUnitsId            = "00000036-0000-1000-8000-0026BB765291";
char * const kHKCVersionId                     = "00000037-0000-1000-8000-0026BB765291";
char * const kHKCAirPartSizeId                 = "00000065-0000-1000-8000-0026BB765291";
char * const kHKCSecuritySysCurrentStateId     = "00000066-0000-1000-8000-0026BB765291";
char * const kHKCSecuritySysTargetStateId      = "00000067-0000-1000-8000-0026BB765291";
char * const kHKCBatteryLevelId                = "00000068-0000-1000-8000-0026BB765291";
char * const kHKCCarbonMonoxDetectedId         = "00000069-0000-1000-8000-0026BB765291";
char * const kHKContactSensorStateId           = "0000006A-0000-1000-8000-0026BB765291";

char *hk_characteristic_format_to_string(hk_value_format_t fmt)
{
    switch (fmt) {
        case HK_VALUE_FORMAT_BOOL:   return "bool";
        case HK_VALUE_FORMAT_BYTES:  return "bytes";
        case HK_VALUE_FORMAT_FLOAT:  return "float";
        case HK_VALUE_FORMAT_INT:    return "int";
        case HK_VALUE_FORMAT_STRING: return "string";
        case HK_VALUE_FORMAT_TLV8:   return "tlv8";
        default:                     return "unknown";
    }
}

hk_value_format_t hk_characteristic_format_from_string(char *fmt)
{
    if      (!strcmp(fmt, "bool"))   return HK_VALUE_FORMAT_BOOL;
    else if (!strcmp(fmt, "bytes"))  return HK_VALUE_FORMAT_BYTES;
    else if (!strcmp(fmt, "float"))  return HK_VALUE_FORMAT_FLOAT;
    else if (!strcmp(fmt, "int"))    return HK_VALUE_FORMAT_INT;
    else if (!strcmp(fmt, "string")) return HK_VALUE_FORMAT_STRING;
    else if (!strcmp(fmt, "tlv8"))   return HK_VALUE_FORMAT_TLV8;
    else                             return HK_VALUE_FORMAT_UNKNOWN;
}

char *hk_characteristic_unit_to_string(hk_value_unit_t unit)
{
    switch (unit) {
        case HK_VALUE_UNIT_ARCDEGREES: return "arcdegrees";
        case HK_VALUE_UNIT_CELCIUS:    return "celcius";
        case HK_VALUE_UNIT_LUX:        return "lux";
        case HK_VALUE_UNIT_NONE:       return "none";
        case HK_VALUE_UNIT_PERCENTAGE: return "percentage";
        case HK_VALUE_UNIT_SECONDS:    return "seconds";
        default:                       return "unknown";
    }
}

char *hk_characteristic_value_from_bool(uint8_t val)
{
    return strdup(val ? "1" : "0");
}

char *hk_characteristic_value_from_double(double val)
{
    return alloc_sprintf("%f", val);
}

char *hk_characteristic_value_from_int(int val)
{
    return alloc_sprintf("%d", val);
}

char *hk_characteristic_value_from_string(char *val)
{
    return strdup(val);
}

// hk_characteristic_set_value sets the value for a given characteristic. This function should always be
// used, and the characteristic value should NEVER be set manually.
void hk_characteristic_set_value(hk_characteristic_t *c, char *val)
{
    ASSERT(c == NULL);
    ASSERT(val == NULL);

    if (c->value)
        free(c->value);

    c->value = val;
}

void hk_characteristic_set_change_func(hk_characteristic_t *ch, hk_characteristic_change_func_t func)
{
    ASSERT(ch == NULL);
    ASSERT(func == NULL);

    ch->change_func = func;
}

hk_characteristic_t *hk_characteristic_new(char *id, hk_value_format_t fmt,
                                           hk_permission_t perms, hk_value_unit_t unit)
{
    hk_characteristic_t *ch = malloc(sizeof(hk_characteristic_t));
    if (ch) {
        memset(ch, 0, sizeof(hk_characteristic_t));
        ch->id = id;
        ch->format = fmt;
        ch->perms = perms;
        ch->unit = unit;
    }

    return ch;
}

void hk_characteristic_free(hk_characteristic_t *ch)
{
    if (ch) {
        memset(ch, 0, sizeof(hk_characteristic_t));
        if (ch->type)        free(ch->type);
        if (ch->description) free(ch->description);
        if (ch->value)       free(ch->value);
        free(ch);
    }
}

hk_characteristic_t *hk_characteristic_new_admin_only_access(void)
{
    hk_characteristic_t *ch = (hk_characteristic_t *)malloc(sizeof(hk_characteristic_t));
    if (ch) {
        memset(ch, 0, sizeof(hk_characteristic_t));
        ch->id = kHKCAdminOnlyAccessId;
        ch->format = HK_VALUE_FORMAT_BOOL;
        ch->perms = HK_PERMISSION_READ | HK_PERMISSION_WRITE | HK_PERMISSION_NOTIFY;
        ch->unit = HK_VALUE_UNIT_NONE;
        hk_characteristic_set_value(ch, hk_characteristic_value_from_bool(0));
    }

    return ch;
}

hk_characteristic_t *hk_characteristic_new_audio_feedback(void)
{
    hk_characteristic_t *ch = (hk_characteristic_t *)malloc(sizeof(hk_characteristic_t));
    if (ch) {
        memset(ch, 0, sizeof(hk_characteristic_t));
        ch->id = kHKCAudioFeedbackId;
        ch->format = HK_VALUE_FORMAT_BOOL;
        ch->perms = HK_PERMISSION_READ | HK_PERMISSION_WRITE | HK_PERMISSION_NOTIFY;
        ch->unit = HK_VALUE_UNIT_NONE;
        hk_characteristic_set_value(ch, hk_characteristic_value_from_bool(0));
    }

    return ch;
}

hk_characteristic_t *hk_characteristic_new_brightness(void)
{
    hk_characteristic_t *ch = (hk_characteristic_t *)malloc(sizeof(hk_characteristic_t));
    if (ch) {
        memset(ch, 0, sizeof(hk_characteristic_t));
        ch->id = kHKCBrightnessId;
        ch->format = HK_VALUE_FORMAT_INT;
        ch->perms = HK_PERMISSION_READ | HK_PERMISSION_WRITE | HK_PERMISSION_NOTIFY;
        ch->unit = HK_VALUE_UNIT_PERCENTAGE;
        ch->min_value = 0;
        ch->max_value = 100;
        ch->step_value = 1;
        hk_characteristic_set_value(ch, hk_characteristic_value_from_int(0));
    }

    return ch;
}

hk_characteristic_t *hk_characteristic_new_cooling_threshold_temp(void)
{
    hk_characteristic_t *ch = (hk_characteristic_t *)malloc(sizeof(hk_characteristic_t));
    if (ch) {
        memset(ch, 0, sizeof(hk_characteristic_t));
        ch->id = kHKCCoolingThresholdTempId;
        ch->format = HK_VALUE_FORMAT_FLOAT;
        ch->perms = HK_PERMISSION_READ | HK_PERMISSION_WRITE | HK_PERMISSION_NOTIFY;
        ch->unit = HK_VALUE_UNIT_CELCIUS;
        ch->min_value = 10;
        ch->max_value = 35;
        ch->step_value = 0.1;
        hk_characteristic_set_value(ch, hk_characteristic_value_from_double(0));
    }

    return ch;
}

hk_characteristic_t *hk_characteristic_new_current_door_state(void)
{
    hk_characteristic_t *ch = (hk_characteristic_t *)malloc(sizeof(hk_characteristic_t));
    if (ch) {
        memset(ch, 0, sizeof(hk_characteristic_t));
        ch->id = kHKCCurrentDoorStateId;
        ch->format = HK_VALUE_FORMAT_INT;
        ch->perms = HK_PERMISSION_READ | HK_PERMISSION_WRITE | HK_PERMISSION_NOTIFY;
        ch->unit = HK_VALUE_UNIT_CELCIUS;
        ch->min_value = 0;
        ch->max_value = 4;
        ch->step_value = 1;
        hk_characteristic_set_value(ch, hk_characteristic_value_from_int(HK_CHARACTERISTIC_CURRENT_DOOR_STATE_OPEN));
    }

    return ch;
}

hk_characteristic_t *hk_characteristic_new_current_heating_cooling_state(void)
{
    hk_characteristic_t *ch = (hk_characteristic_t *)malloc(sizeof(hk_characteristic_t));
    if (ch) {
        memset(ch, 0, sizeof(hk_characteristic_t));
        ch->id = kHKCCurrentHeatingCoolingStateId;
        ch->format = HK_VALUE_FORMAT_INT;
        ch->perms = HK_PERMISSION_READ | HK_PERMISSION_WRITE | HK_PERMISSION_NOTIFY;
        ch->unit = HK_VALUE_UNIT_NONE;
        ch->min_value = 0;
        ch->max_value = 2;
        ch->step_value = 1;
        hk_characteristic_set_value(ch, hk_characteristic_value_from_int(HK_CHARACTERISTIC_CURRENT_HEATING_COOLING_STATE_OFF));
    }

    return ch;
}

hk_characteristic_t *hk_characteristic_new_current_humidity(void)
{
    hk_characteristic_t *ch = (hk_characteristic_t *)malloc(sizeof(hk_characteristic_t));
    if (ch) {
        memset(ch, 0, sizeof(hk_characteristic_t));
        ch->id = kHKCCurrentHumidityId;
        ch->format = HK_VALUE_FORMAT_FLOAT;
        ch->perms = HK_PERMISSION_READ | HK_PERMISSION_WRITE | HK_PERMISSION_NOTIFY;
        ch->unit = HK_VALUE_UNIT_PERCENTAGE;
        ch->min_value = 0;
        ch->max_value = 100;
        ch->step_value = 1;
        hk_characteristic_set_value(ch, hk_characteristic_value_from_double(0.0));
    }

    return ch;
}

hk_characteristic_t *hk_characteristic_new_current_temp(void)
{
    hk_characteristic_t *ch = (hk_characteristic_t *)malloc(sizeof(hk_characteristic_t));
    if (ch) {
        memset(ch, 0, sizeof(hk_characteristic_t));
        ch->id = kHKCCurrentTempId;
        ch->format = HK_VALUE_FORMAT_FLOAT;
        ch->perms = HK_PERMISSION_READ | HK_PERMISSION_WRITE | HK_PERMISSION_NOTIFY;
        ch->unit = HK_VALUE_UNIT_CELCIUS;
        ch->min_value = 0;
        ch->max_value = 100;
        ch->step_value = 0.1;
        hk_characteristic_set_value(ch, hk_characteristic_value_from_double(0.0));
    }

    return ch;
}

hk_characteristic_t *hk_characteristic_new_firmware_revision(void)
{
    hk_characteristic_t *ch = (hk_characteristic_t *)malloc(sizeof(hk_characteristic_t));
    if (ch) {
        memset(ch, 0, sizeof(hk_characteristic_t));
        ch->id = kHKCFirmwareRevisionId;
        ch->format = HK_VALUE_FORMAT_STRING;
        ch->perms = HK_PERMISSION_READ;
        ch->unit = HK_VALUE_UNIT_NONE;
        hk_characteristic_set_value(ch, hk_characteristic_value_from_string("0.0.0"));
    }

    return ch;
}

hk_characteristic_t *hk_characteristic_new_hardware_revision(void)
{
    hk_characteristic_t *ch = (hk_characteristic_t *)malloc(sizeof(hk_characteristic_t));
    if (ch) {
        memset(ch, 0, sizeof(hk_characteristic_t));
        ch->id = kHKCHardwareRevisionId;
        ch->format = HK_VALUE_FORMAT_STRING;
        ch->perms = HK_PERMISSION_READ;
        ch->unit = HK_VALUE_UNIT_NONE;
        hk_characteristic_set_value(ch, hk_characteristic_value_from_string("0.0.0"));
    }

    return ch;
}

hk_characteristic_t *hk_characteristic_new_heating_threshold_temp(void)
{
    hk_characteristic_t *ch = (hk_characteristic_t *)malloc(sizeof(hk_characteristic_t));
    if (ch) {
        memset(ch, 0, sizeof(hk_characteristic_t));
        ch->id = kHKCHeatingThresholdTempId;
        ch->format = HK_VALUE_FORMAT_FLOAT;
        ch->perms = HK_PERMISSION_READ | HK_PERMISSION_WRITE | HK_PERMISSION_NOTIFY;
        ch->unit = HK_VALUE_UNIT_CELCIUS;
        ch->min_value = 0;
        ch->max_value = 25;
        ch->step_value = 0.1;
        hk_characteristic_set_value(ch, hk_characteristic_value_from_double(ch->min_value));
    }

    return ch;
}

hk_characteristic_t *hk_characteristic_new_hue(void)
{
    hk_characteristic_t *ch = (hk_characteristic_t *)malloc(sizeof(hk_characteristic_t));
    if (ch) {
        memset(ch, 0, sizeof(hk_characteristic_t));
        ch->id = kHKCHueId;
        ch->format = HK_VALUE_FORMAT_FLOAT;
        ch->perms = HK_PERMISSION_READ | HK_PERMISSION_WRITE | HK_PERMISSION_NOTIFY;
        ch->unit = HK_VALUE_UNIT_ARCDEGREES;
        ch->min_value = 0;
        ch->max_value = 360;
        ch->step_value = 1;
        hk_characteristic_set_value(ch, hk_characteristic_value_from_double(ch->min_value));
    }

    return ch;
}

hk_characteristic_t *hk_characteristic_new_identify(void)
{
    hk_characteristic_t *ch = (hk_characteristic_t *)malloc(sizeof(hk_characteristic_t));
    if (ch) {
        memset(ch, 0, sizeof(hk_characteristic_t));
        ch->id = kHKCIdentifyId;
        ch->format = HK_VALUE_FORMAT_BOOL;
        ch->perms = HK_PERMISSION_WRITE;
        ch->unit = HK_VALUE_UNIT_NONE;
        hk_characteristic_set_value(ch, hk_characteristic_value_from_bool(0));
    }

    return ch;
}

// HAP page 152:
// The device accepts writes to this characteristic to perform vendor-specific actions as well as
// those defined by the Lock Management (page 218) of the Lock (page 237) . For example, user
// management related functions should be defined and performed using this characteristic.
hk_characteristic_t *hk_characteristic_new_lock_control_point(void)
{
    hk_characteristic_t *ch = (hk_characteristic_t *)malloc(sizeof(hk_characteristic_t));
    if (ch) {
        memset(ch, 0, sizeof(hk_characteristic_t));
        ch->id = kHKCLockControlPointId;
        ch->format = HK_VALUE_FORMAT_TLV8;
        ch->perms = HK_PERMISSION_WRITE;
        ch->unit = HK_VALUE_UNIT_NONE;
        hk_characteristic_set_value(ch, hk_characteristic_value_from_string(""));
    }

    return ch;
}

hk_characteristic_t *hk_characteristic_new_lock_current_state(void)
{
    hk_characteristic_t *ch = (hk_characteristic_t *)malloc(sizeof(hk_characteristic_t));
    if (ch) {
        memset(ch, 0, sizeof(hk_characteristic_t));
        ch->id = kHKCLockCurrentStateId;
        ch->format = HK_VALUE_FORMAT_INT;
        ch->perms = HK_PERMISSION_READ | HK_PERMISSION_WRITE | HK_PERMISSION_NOTIFY;
        ch->unit = HK_VALUE_UNIT_NONE;
        ch->min_value = 0;
        ch->max_value = 3;
        ch->step_value = 1;
        hk_characteristic_set_value(ch, hk_characteristic_value_from_int(HK_CHARACTERISTIC_LOCK_CURRENT_STATE_UNKNOWN));
    }

    return ch;
}

hk_characteristic_t *hk_characteristic_new_lock_last_known_action(void)
{
    hk_characteristic_t *ch = (hk_characteristic_t *)malloc(sizeof(hk_characteristic_t));
    if (ch) {
        memset(ch, 0, sizeof(hk_characteristic_t));
        ch->id = kHKCLockLastKnownActionId;
        ch->format = HK_VALUE_FORMAT_INT;
        ch->perms = HK_PERMISSION_READ | HK_PERMISSION_NOTIFY;
        ch->unit = HK_VALUE_UNIT_NONE;
        ch->min_value = 0;
        ch->max_value = 8;
        ch->step_value = 1;
        hk_characteristic_set_value(ch, hk_characteristic_value_from_int(HK_CHARACTERISTIC_LOCK_LAST_KNOWN_ACTION_SECURED_PHYSICAL_INTERIOR));
    }

    return ch;
}

hk_characteristic_t *hk_characteristic_new_lock_mgmt_auto_security_timeout(void)
{
    hk_characteristic_t *ch = (hk_characteristic_t *)malloc(sizeof(hk_characteristic_t));
    if (ch) {
        memset(ch, 0, sizeof(hk_characteristic_t));
        ch->id = kHKCLockMgmtAutoSecurityTimeoutId;
        ch->format = HK_VALUE_FORMAT_INT;
        ch->perms = HK_PERMISSION_READ | HK_PERMISSION_WRITE | HK_PERMISSION_NOTIFY;
        ch->unit = HK_VALUE_UNIT_SECONDS;
        ch->min_value = 0;
        ch->max_value = 0;
        ch->step_value = 1;
        hk_characteristic_set_value(ch, hk_characteristic_value_from_int(0));
    }

    return ch;
}

hk_characteristic_t *hk_characteristic_new_lock_target_state(void)
{
    hk_characteristic_t *ch = (hk_characteristic_t *)malloc(sizeof(hk_characteristic_t));
    if (ch) {
        memset(ch, 0, sizeof(hk_characteristic_t));
        ch->id = kHKCLockTargetStateId;
        ch->format = HK_VALUE_FORMAT_INT;
        ch->perms = HK_PERMISSION_READ | HK_PERMISSION_WRITE | HK_PERMISSION_NOTIFY;
        ch->unit = HK_VALUE_UNIT_SECONDS;
        ch->min_value = 0;
        ch->max_value = 1;
        ch->step_value = 1;
        hk_characteristic_set_value(ch, hk_characteristic_value_from_int(HK_CHARACTERISTIC_LOCK_TARGET_STATE_UNSECURED));
    }

    return ch;
}

hk_characteristic_t *hk_characteristic_new_logs(void)
{
    hk_characteristic_t *ch = (hk_characteristic_t *)malloc(sizeof(hk_characteristic_t));
    if (ch) {
        memset(ch, 0, sizeof(hk_characteristic_t));
        ch->id = kHKCLogsId;
        ch->format = HK_VALUE_FORMAT_TLV8;
        ch->perms = HK_PERMISSION_READ | HK_PERMISSION_NOTIFY;
        ch->unit = HK_VALUE_UNIT_NONE;
        hk_characteristic_set_value(ch, hk_characteristic_value_from_string(""));
    }

    return ch;
}

hk_characteristic_t *hk_characteristic_new_manufacturer(void)
{
    hk_characteristic_t *ch = (hk_characteristic_t *)malloc(sizeof(hk_characteristic_t));
    if (ch) {
        memset(ch, 0, sizeof(hk_characteristic_t));
        ch->id = kHKCManufacturerId;
        ch->format = HK_VALUE_FORMAT_STRING;
        ch->perms = HK_PERMISSION_READ;
        ch->unit = HK_VALUE_UNIT_NONE;
        ch->max_len = 64;
        hk_characteristic_set_value(ch, hk_characteristic_value_from_string(""));
    }

    return ch;
}

hk_characteristic_t *hk_characteristic_new_model(void)
{
    hk_characteristic_t *ch = (hk_characteristic_t *)malloc(sizeof(hk_characteristic_t));
    if (ch) {
        memset(ch, 0, sizeof(hk_characteristic_t));
        ch->id = kHKCModelId;
        ch->format = HK_VALUE_FORMAT_STRING;
        ch->perms = HK_PERMISSION_READ;
        ch->unit = HK_VALUE_UNIT_NONE;
        ch->max_len = 64;
        hk_characteristic_set_value(ch, hk_characteristic_value_from_string(""));
    }

    return ch;
}

hk_characteristic_t *hk_characteristic_new_motion_detected(void)
{
    hk_characteristic_t *ch = (hk_characteristic_t *)malloc(sizeof(hk_characteristic_t));
    if (ch) {
        memset(ch, 0, sizeof(hk_characteristic_t));
        ch->id = kHKCMotionDetectedId;
        ch->format = HK_VALUE_FORMAT_BOOL;
        ch->perms = HK_PERMISSION_READ | HK_PERMISSION_NOTIFY;
        ch->unit = HK_VALUE_UNIT_NONE;
        hk_characteristic_set_value(ch, hk_characteristic_value_from_bool(0));
    }

    return ch;
}

hk_characteristic_t *hk_characteristic_new_name(void)
{
    hk_characteristic_t *ch = (hk_characteristic_t *)malloc(sizeof(hk_characteristic_t));
    if (ch) {
        memset(ch, 0, sizeof(hk_characteristic_t));
        ch->id = kHKCNameId;
        ch->format = HK_VALUE_FORMAT_STRING;
        ch->perms = HK_PERMISSION_READ;
        ch->unit = HK_VALUE_UNIT_NONE;
        ch->max_len = 64;
        hk_characteristic_set_value(ch, hk_characteristic_value_from_string(""));
    }

    return ch;
}

hk_characteristic_t *hk_characteristic_new_obstruction_detected(void)
{
    hk_characteristic_t *ch = (hk_characteristic_t *)malloc(sizeof(hk_characteristic_t));
    if (ch) {
        memset(ch, 0, sizeof(hk_characteristic_t));
        ch->id = kHKCObstructionDetectedId;
        ch->format = HK_VALUE_FORMAT_BOOL;
        ch->perms = HK_PERMISSION_READ | HK_PERMISSION_NOTIFY;
        ch->unit = HK_VALUE_UNIT_NONE;
        hk_characteristic_set_value(ch, hk_characteristic_value_from_bool(0));
    }

    return ch;
}

hk_characteristic_t *hk_characteristic_new_on(void)
{
    hk_characteristic_t *ch = (hk_characteristic_t *)malloc(sizeof(hk_characteristic_t));
    if (ch) {
        memset(ch, 0, sizeof(hk_characteristic_t));
        ch->id = kHKCOnId;
        ch->format = HK_VALUE_FORMAT_BOOL;
        ch->perms = HK_PERMISSION_READ | HK_PERMISSION_WRITE | HK_PERMISSION_NOTIFY;
        hk_characteristic_set_value(ch, hk_characteristic_value_from_bool(0));
    }

    return ch;
}

hk_characteristic_t *hk_characteristic_new_outlet_in_use(void)
{
    hk_characteristic_t *ch = (hk_characteristic_t *)malloc(sizeof(hk_characteristic_t));
    if (ch) {
        memset(ch, 0, sizeof(hk_characteristic_t));
        ch->id = kHKCOutletInUseId;
        ch->format = HK_VALUE_FORMAT_BOOL;
        ch->perms = HK_PERMISSION_READ | HK_PERMISSION_NOTIFY;
        ch->unit = HK_VALUE_UNIT_NONE;
        hk_characteristic_set_value(ch, hk_characteristic_value_from_bool(0));
    }

    return ch;
}

hk_characteristic_t *hk_characteristic_new_rotation_direction(void)
{
    hk_characteristic_t *ch = (hk_characteristic_t *)malloc(sizeof(hk_characteristic_t));
    if (ch) {
        memset(ch, 0, sizeof(hk_characteristic_t));
        ch->id = kHKCRotationDirectionId;
        ch->format = HK_VALUE_FORMAT_INT;
        ch->perms = HK_PERMISSION_READ | HK_PERMISSION_WRITE | HK_PERMISSION_NOTIFY;
        ch->unit = HK_VALUE_UNIT_NONE;
        ch->min_value = 0;
        ch->max_value = 1;
        hk_characteristic_set_value(ch, hk_characteristic_value_from_int(HK_CHARACTERISTIC_ROTATION_DIRECTION_CLOCKWISE));
    }

    return ch;
}

hk_characteristic_t *hk_characteristic_new_rotation_speed(void)
{
    hk_characteristic_t *ch = (hk_characteristic_t *)malloc(sizeof(hk_characteristic_t));
    if (ch) {
        memset(ch, 0, sizeof(hk_characteristic_t));
        ch->id = kHKCRotationSpeedId;
        ch->format = HK_VALUE_FORMAT_FLOAT;
        ch->perms = HK_PERMISSION_READ | HK_PERMISSION_WRITE | HK_PERMISSION_NOTIFY;
        ch->unit = HK_VALUE_UNIT_PERCENTAGE;
        ch->min_value = 0;
        ch->max_value = 100;
        ch->step_value = 1;
        hk_characteristic_set_value(ch, hk_characteristic_value_from_double(0));
    }

    return ch;
}

hk_characteristic_t *hk_characteristic_new_saturation(void)
{
    hk_characteristic_t *ch = (hk_characteristic_t *)malloc(sizeof(hk_characteristic_t));
    if (ch) {
        memset(ch, 0, sizeof(hk_characteristic_t));
        ch->id = kHKCSaturationId;
        ch->format = HK_VALUE_FORMAT_FLOAT;
        ch->perms = HK_PERMISSION_READ | HK_PERMISSION_WRITE | HK_PERMISSION_NOTIFY;
        ch->unit = HK_VALUE_UNIT_PERCENTAGE;
        ch->min_value = 0;
        ch->max_value = 100;
        ch->step_value = 1;
        hk_characteristic_set_value(ch, hk_characteristic_value_from_double(0));
    }

    return ch;
}

hk_characteristic_t *hk_characteristic_new_serial_number(void)
{
    hk_characteristic_t *ch = (hk_characteristic_t *)malloc(sizeof(hk_characteristic_t));
    if (ch) {
        memset(ch, 0, sizeof(hk_characteristic_t));
        ch->id = kHKCSerialNumberId;
        ch->format = HK_VALUE_FORMAT_STRING;
        ch->perms = HK_PERMISSION_READ;
        ch->unit = HK_VALUE_UNIT_NONE;
        ch->max_len = 64;
        hk_characteristic_set_value(ch, hk_characteristic_value_from_string(""));
    }

    return ch;
}

hk_characteristic_t *hk_characteristic_new_target_door_state(void)
{
    hk_characteristic_t *ch = (hk_characteristic_t *)malloc(sizeof(hk_characteristic_t));
    if (ch) {
        memset(ch, 0, sizeof(hk_characteristic_t));
        ch->id = kHKCTargetDoorStateId;
        ch->format = HK_VALUE_FORMAT_INT;
        ch->perms = HK_PERMISSION_READ | HK_PERMISSION_WRITE | HK_PERMISSION_NOTIFY;
        ch->unit = HK_VALUE_UNIT_NONE;
        ch->min_value = 0;
        ch->max_value = 1;
        ch->step_value = 1;
        hk_characteristic_set_value(ch, hk_characteristic_value_from_int(HK_CHARACTERISTIC_TARGET_DOOR_STATE_OPEN));
    }

    return ch;
}

hk_characteristic_t *hk_characteristic_new_target_heating_cooling_state(void)
{
    hk_characteristic_t *ch = (hk_characteristic_t *)malloc(sizeof(hk_characteristic_t));
    if (ch) {
        memset(ch, 0, sizeof(hk_characteristic_t));
        ch->id = kHKCTargetHeatingCoolingStateId;
        ch->format = HK_VALUE_FORMAT_INT;
        ch->perms = HK_PERMISSION_READ | HK_PERMISSION_WRITE | HK_PERMISSION_NOTIFY;
        ch->unit = HK_VALUE_UNIT_NONE;
        ch->min_value = 0;
        ch->max_value = 3;
        ch->step_value = 1;
        hk_characteristic_set_value(ch, hk_characteristic_value_from_int(HK_CHARACTERISTIC_TARGET_HEATING_COOLING_STATE_OFF));
    }

    return ch;
}

hk_characteristic_t *hk_characteristic_new_target_humidity(void)
{
    hk_characteristic_t *ch = (hk_characteristic_t *)malloc(sizeof(hk_characteristic_t));
    if (ch) {
        memset(ch, 0, sizeof(hk_characteristic_t));
        ch->id = kHKCTargetHumidityId;
        ch->format = HK_VALUE_FORMAT_FLOAT;
        ch->perms = HK_PERMISSION_READ | HK_PERMISSION_WRITE | HK_PERMISSION_NOTIFY;
        ch->unit = HK_VALUE_UNIT_PERCENTAGE;
        ch->min_value = 0;
        ch->max_value = 100;
        ch->step_value = 1;
        hk_characteristic_set_value(ch, hk_characteristic_value_from_int(0));
    }

    return ch;
}

hk_characteristic_t *hk_characteristic_new_target_temp(void)
{
    hk_characteristic_t *ch = (hk_characteristic_t *)malloc(sizeof(hk_characteristic_t));
    if (ch) {
        memset(ch, 0, sizeof(hk_characteristic_t));
        ch->id = kHKCTargetTempId;
        ch->format = HK_VALUE_FORMAT_FLOAT;
        ch->perms = HK_PERMISSION_READ | HK_PERMISSION_WRITE | HK_PERMISSION_NOTIFY;
        ch->unit = HK_VALUE_UNIT_CELCIUS;
        ch->min_value = 10;
        ch->max_value = 38;
        ch->step_value = 0.1;
        hk_characteristic_set_value(ch, hk_characteristic_value_from_double(ch->min_value));
    }

    return ch;
}

hk_characteristic_t *hk_characteristic_new_temp_display_units(void)
{
    hk_characteristic_t *ch = (hk_characteristic_t *)malloc(sizeof(hk_characteristic_t));
    if (ch) {
        memset(ch, 0, sizeof(hk_characteristic_t));
        ch->id = kHKCTempDisplayUnitsId;
        ch->format = HK_VALUE_FORMAT_INT;
        ch->perms = HK_PERMISSION_READ | HK_PERMISSION_WRITE | HK_PERMISSION_NOTIFY;
        ch->unit = HK_VALUE_UNIT_NONE;
        ch->min_value = 0;
        ch->max_value = 1;
        ch->step_value = 1;
        hk_characteristic_set_value(ch, hk_characteristic_value_from_int(HK_CHARACTERISTIC_TEMP_DISPLAY_UNITS_CELCIUS));
    }

    return ch;
}

hk_characteristic_t *hk_characteristic_new_version(void)
{
    hk_characteristic_t *ch = (hk_characteristic_t *)malloc(sizeof(hk_characteristic_t));
    if (ch) {
        memset(ch, 0, sizeof(hk_characteristic_t));
        ch->id = kHKCVersionId;
        ch->format = HK_VALUE_FORMAT_STRING;
        ch->perms = HK_PERMISSION_READ;
        ch->unit = HK_VALUE_UNIT_NONE;
        ch->max_len = 64;
        hk_characteristic_set_value(ch, hk_characteristic_value_from_string("0.0.0"));
    }

    return ch;
}

hk_characteristic_t *hk_characteristic_new_air_part_size(void)
{
    hk_characteristic_t *ch = (hk_characteristic_t *)malloc(sizeof(hk_characteristic_t));
    if (ch) {
        memset(ch, 0, sizeof(hk_characteristic_t));
        ch->id = kHKCAirPartSizeId;
        ch->format = HK_VALUE_FORMAT_INT;
        ch->perms = HK_PERMISSION_READ | HK_PERMISSION_NOTIFY;
        ch->unit = HK_VALUE_UNIT_NONE;
        ch->min_value = 0;
        ch->max_value = 1;
        ch->step_value = 1;
        hk_characteristic_set_value(ch, hk_characteristic_value_from_int(HK_CHARACTERISTIC_AIR_PART_SIZE_2_5_UM));
    }

    return ch;
}

hk_characteristic_t *hk_characteristic_new_security_sys_current_state(void)
{
    hk_characteristic_t *ch = (hk_characteristic_t *)malloc(sizeof(hk_characteristic_t));
    if (ch) {
        memset(ch, 0, sizeof(hk_characteristic_t));
        ch->id = kHKCSecuritySysCurrentStateId;
        ch->format = HK_VALUE_FORMAT_INT;
        ch->perms = HK_PERMISSION_READ | HK_PERMISSION_NOTIFY;
        ch->unit = HK_VALUE_UNIT_NONE;
        ch->min_value = 0;
        ch->max_value = 4;
        ch->step_value = 1;
        hk_characteristic_set_value(ch, hk_characteristic_value_from_int(HK_CHARACTERISTIC_SECURITY_SYS_STATE_STAY_ARM));
    }

    return ch;
}

hk_characteristic_t *hk_characteristic_new_security_sys_target_state(void)
{
    hk_characteristic_t *ch = (hk_characteristic_t *)malloc(sizeof(hk_characteristic_t));
    if (ch) {
        memset(ch, 0, sizeof(hk_characteristic_t));
        ch->id = kHKCSecuritySysTargetStateId;
        ch->format = HK_VALUE_FORMAT_INT;
        ch->perms = HK_PERMISSION_READ | HK_PERMISSION_NOTIFY;
        ch->unit = HK_VALUE_UNIT_NONE;
        ch->min_value = 0;
        ch->max_value = 3;
        ch->step_value = 1;
        hk_characteristic_set_value(ch, hk_characteristic_value_from_int(HK_CHARACTERISTIC_SECURITY_SYS_STATE_STAY_ARM));
    }

    return ch;
}

hk_characteristic_t *hk_characteristic_new_battery_level(void)
{
    hk_characteristic_t *ch = (hk_characteristic_t *)malloc(sizeof(hk_characteristic_t));
    if (ch) {
        memset(ch, 0, sizeof(hk_characteristic_t));
        ch->id = kHKCBatteryLevelId;
        ch->format = HK_VALUE_FORMAT_INT;
        ch->perms = HK_PERMISSION_READ | HK_PERMISSION_WRITE | HK_PERMISSION_NOTIFY;
        ch->unit = HK_VALUE_UNIT_PERCENTAGE;
        ch->min_value = 0;
        ch->max_value = 100;
        ch->step_value = 1;
        hk_characteristic_set_value(ch, hk_characteristic_value_from_int(0));
    }

    return ch;
}

hk_characteristic_t *hk_characteristic_new_carbon_monox_detected(void)
{
    hk_characteristic_t *ch = (hk_characteristic_t *)malloc(sizeof(hk_characteristic_t));
    if (ch) {
        memset(ch, 0, sizeof(hk_characteristic_t));
        ch->id = kHKCCarbonMonoxDetectedId;
        ch->format = HK_VALUE_FORMAT_INT;
        ch->perms = HK_PERMISSION_READ | HK_PERMISSION_NOTIFY;
        ch->unit = HK_VALUE_UNIT_NONE;
        ch->min_value = 0;
        ch->max_value = 1;
        ch->step_value = 1;
        hk_characteristic_set_value(ch, hk_characteristic_value_from_int(HK_CHARACTERISTIC_CARBON_MONOX_DETECTED_NORMAL));
    }

    return ch;
}

hk_characteristic_t *hk_characteristic_new_contact_sensor_state(void)
{
    hk_characteristic_t *ch = (hk_characteristic_t *)malloc(sizeof(hk_characteristic_t));
    if (ch) {
        memset(ch, 0, sizeof(hk_characteristic_t));
        ch->id = kHKContactSensorStateId;
        ch->format = HK_VALUE_FORMAT_INT;
        ch->perms = HK_PERMISSION_READ | HK_PERMISSION_NOTIFY;
        ch->unit = HK_VALUE_UNIT_NONE;
        ch->min_value = 0;
        ch->max_value = 1;
        ch->step_value = 1;
        hk_characteristic_set_value(ch, hk_characteristic_value_from_int(HK_CHARACTERISTIC_CONTACT_SENSOR_STATE_NOT_DETECTED));
    }

    return ch;
}

