#pragma once

#include <stdint.h>
#include <sys/time.h>
#include <wolfssl/wolfcrypt/srp.h>
#include <wolfssl/wolfcrypt/chacha20_poly1305.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/curve25519.h>

// The homekit protocol version that this is current compliant with.
#define HK_PROTO_VERSION       1.1f

#define HK_DEFAULT_IP_PORT     7631

// The service type identifier for mDNS. This should be used when intializing / adding
// service to your mDNS server.
#define HK_MDNS_SERVICE_TYPE   "_hap"
#define HK_MDNS_SERVICE_PROTO  "_tcp"

#define HK_HTTP_ACCESSORIES_URI     "/accessories"
#define HK_HTTP_CHARACTERISTICS_URI "/characteristics"
#define HK_HTTP_IDENTIFY_URI        "/identify"
#define HK_HTTP_PAIR_SETUP_URI      "/pair-setup"
#define HK_HTTP_PAIR_VERIFY_URI     "/pair-verify"
#define HK_HTTP_PAIRINGS_URI        "/pairings"

#define HK_MAX_PATH             255
#define HK_MAX_PAIRING_ID_LEN   100

#define HK_CONTENT_TYPE_JSON "application/hap+json"

typedef void (*hk_update_mdns_txts_func)(char txts[][3][32], uint8_t entries);

typedef enum {
    HK_ACCESSORY_CATEGORY_OTHER,
    HK_ACCESSORY_CATEGORY_BRIDGE,
    HK_ACCESSORY_CATEGORY_FAN,
    HK_ACCESSORY_CATEGORY_GARAGE,
    HK_ACCESSORY_CATEGORY_LIGHTBULB,
    HK_ACCESSORY_CATEGORY_DOOR_LOCK,
    HK_ACCESSORY_CATEGORY_OUTLET,
    HK_ACCESSORY_CATEGORY_SWITCH,
    HK_ACCESSORY_CATEGORY_THERMOSTAT,
    HK_ACCESSORY_CATEGORY_SENSOR,
    HK_ACCESSORY_CATEGORY_SECURITY_SYSTEM,
    HK_ACCESSORY_CATEGORY_DOOR,
    HK_ACCESSORY_CATEGORY_WINDOW,
    HK_ACCESSORY_CATEGORY_WINDOW_COVER,
    HK_ACCESSORY_CATEGORY_PROGRAM_SWITCH,
    HK_ACCESSORY_CATEGORY_RANGE_EXTENDER,
    HK_ACCESSORY_CATEGORY_IPCAM,
    HK_ACCESSORY_CATEGORY_VIDEO_DOOR_BELL,
    HK_ACCESSORY_CATEGORY_AIR_PURIFIER,
    HK_ACCESSORY_CATEGORY_RESERVED_ABOVE
} hk_accessory_category_t;

typedef enum {
    HK_FEATURE_FLAG_SUPPORTS_HAP_PAIR = 1,
    HK_FEATURE_FLAG_RESERVED_ABOVE = 1 << 1
} hk_feature_flag_t;

typedef enum {
    HK_STATUS_FLAG_NOT_PAIRED = 1,
    HK_STATUS_FLAG_NO_NETWORK = 1 << 1,
    HK_STATUS_FLAG_PROBLEM = 1 << 2,
    HK_STATUS_FLAG_RESERVED_ABOVE = 1 << 3
} hk_status_flags_t;

typedef enum {
    HK_STATUS_CODE_REQUEST_DENIED = 0,
    HK_STATUS_CODE_INSUFFICIENT_PRIV = -70401,
    HK_STATUS_CODE_NO_COMM = -70402,
    HK_STATUS_CODE_BUSY = -70403,
    HK_STATUS_CODE_READONLY = -70404,
    HK_STATUS_CODE_WRITEONLY = -70405,
    HK_STATUS_CODE_NOTIF_NOT_SUPPORTED = -70406,
    HK_STATUS_CODE_NO_RESOURCES = -70407,
    HK_STATUS_CODE_OP_TIMEOUT = -70408,
    HK_STATUS_CODE_EXIST = -70409,
    HK_STATUS_CODE_INVALID_VALUE = -70410,
    HK_STATUS_CODE_INSUFFICIENT_AUTHORIZATION = -70411
} hk_status_code_t;

typedef enum {
    HK_PERMISSION_NONE = 0,
    HK_PERMISSION_READ = 1 << 0,
    HK_PERMISSION_WRITE = 1 << 1,
    HK_PERMISSION_NOTIFY = 1 << 2

} hk_permission_t;

typedef enum {
    HK_CHARACTERISTIC_FORMAT_BOOL
} hk_characteristic_format_t;

typedef enum {
    HK_VALUE_FORMAT_UNKNOWN,
    HK_VALUE_FORMAT_BOOL,
    HK_VALUE_FORMAT_INT,
    HK_VALUE_FORMAT_FLOAT,
    HK_VALUE_FORMAT_BYTES,
    HK_VALUE_FORMAT_STRING,
    HK_VALUE_FORMAT_TLV8
} hk_value_format_t;

typedef enum {
    HK_VALUE_UNIT_CELCIUS,
    HK_VALUE_UNIT_ARCDEGREES,
    HK_VALUE_UNIT_PERCENTAGE,
    HK_VALUE_UNIT_NONE,
    HK_VALUE_UNIT_LUX,
    HK_VALUE_UNIT_SECONDS
} hk_value_unit_t;

typedef enum {
    HK_ERR_OK = 0,
    HK_ERR_PERM,
    HK_ERR_MEM,
    HK_ERR_FS,
    HK_ERR_BAD_DATA,
    HK_ERR_BAD_ARG,
    HK_ERR_NOT_FOUND
} hk_err_t;

// hk_controller_pair_t is a structure for a controller <-> accessory pairing.
typedef struct hk_controller_pair_t {
    char controller_id[HK_MAX_PAIRING_ID_LEN];
    unsigned char pubkey[ED25519_PUB_KEY_SIZE];
    hk_permission_t perms;
    uint8_t is_admin;
    unsigned char current_session_key[32];
} hk_controller_pair_t;

// hk_session_context_t is associated with a connection (IP or BT) and is used to keep track
// of the pair setup or pair verify state. Once either processes are completed, the context
// is no longer needed, and pair state information will be stored in pairings.
typedef struct hk_session_context_t {
    uint8_t verified;
    struct hk_accessory_t *ctx;
    struct http_connection_state *httpd_state;
    curve25519_key keypair;
    unsigned char accessory_pubkey[CURVE25519_KEYSIZE];
    unsigned char controller_pubkey[CURVE25519_KEYSIZE];
    char controller_id[HK_MAX_PAIRING_ID_LEN];
    unsigned char shared_secret[64];
    size_t shared_secret_len;
    unsigned char session_key[32];
    hk_controller_pair_t *pair;
    unsigned char encryption_key[32];
    uint64_t encrypt_count;
    unsigned char decryption_key[32];
    uint64_t decrypt_count;
    struct hk_characteristic_t **notify_chrs;
    int notify_chrs_count;
} hk_session_context_t;

// hk_pair_context is a structure that contains the contextual information for pairing. It stores
// pair data to be used for the initial pair setup process, and long term pair keys.
typedef struct hk_pair_context_t {
    uint8_t paired;
    uint8_t pairing;

    Srp srp;
    unsigned char *salt;
    int salt_len;

    unsigned char *verification_key;
    size_t verification_key_len;

    unsigned char *accessory_pubkey;
    size_t accessory_pubkey_len;

    unsigned char *accessory_privatekey;
    size_t accessory_privatekey_len;

    unsigned char *ios_pubkey;
    size_t ios_pubkey_len;

    uint8_t ltpk_generated;
    unsigned char accessory_ltpk[ED25519_PUB_KEY_SIZE];
    unsigned char accessory_ltsk[ED25519_PRV_KEY_SIZE];

    unsigned char session_key[CHACHA20_POLY1305_AEAD_KEYSIZE];

    struct timeval last_pair_attempt;
    int attempts;

    hk_controller_pair_t **pairs;
    uint8_t pair_count;
} hk_pair_context_t;

typedef struct hk_accessory_t {
    struct hkhttpd *server;
    int instance_id;
    int next_instance_id;
    uint32_t category;
    uint32_t config;
    uint8_t status_flags;
    hk_update_mdns_txts_func mdns_update_func;
    char *setup_code;
    char device_id[100];
    char device_model_name[64];
    hk_pair_context_t pair;
    char storage_path[HK_MAX_PATH];
    struct hk_service_t **services;
    size_t services_count;
    hk_session_context_t **active_sessions;
    size_t active_session_count;
} hk_accessory_t;

typedef void (*hk_characteristic_change_func_t)(hk_accessory_t *ctx, struct hk_characteristic_t *ch);

typedef struct hk_characteristic_t {
    char * id;
    int instance_id;
    char *type;
    char *description;
    hk_permission_t perms;
    hk_value_format_t format;
    hk_value_unit_t unit;
    char *value;
    int max_len;
    double max_value;
    double min_value;
    double step_value;
    hk_characteristic_change_func_t change_func;
} hk_characteristic_t;

// hk_service_t is a struct that represents a homekit service.
typedef struct hk_service_t {
    char *id;
    int instance_id;
    bool is_primary;
    hk_characteristic_t **characteristics;
    size_t characteristic_count;
    struct hk_service_t **linked_services;
    size_t linked_services_count;
} hk_service_t;

typedef enum {
    HK_CHARACTERISTIC_CURRENT_DOOR_STATE_OPEN,
    HK_CHARACTERISTIC_CURRENT_DOOR_STATE_CLOSED,
    HK_CHARACTERISTIC_CURRENT_DOOR_STATE_OPENING,
    HK_CHARACTERISTIC_CURRENT_DOOR_STATE_CLOSING,
    HK_CHARACTERISTIC_CURRENT_DOOR_STATE_STOPPED,
    HK_CHARACTERISTIC_CURRENT_DOOR_STATE_RESERVED_ABOVE
} hk_c_current_door_state_value_t;

typedef enum {
    HK_CHARACTERISTIC_CURRENT_HEATING_COOLING_STATE_OFF,
    HK_CHARACTERISTIC_CURRENT_HEATING_COOLING_STATE_HEAT,
    HK_CHARACTERISTIC_CURRENT_HEATING_COOLING_STATE_COOL,
    HK_CHARACTERISTIC_CURRENT_HEATING_COOLING_STATE_RESERVED_ABOVE
} hk_c_current_heating_cooling_state_value_t;

typedef enum {
    HK_CHARACTERISTIC_LOCK_CURRENT_STATE_UNSECURED,
    HK_CHARACTERISTIC_LOCK_CURRENT_STATE_SECURED,
    HK_CHARACTERISTIC_LOCK_CURRENT_STATE_JAMMED,
    HK_CHARACTERISTIC_LOCK_CURRENT_STATE_UNKNOWN,
    HK_CHARACTERISTIC_LOCK_CURRENT_STATE_RESERVED_ABOVE
} hk_c_lock_current_state_value_t;

typedef enum {
    HK_CHARACTERISTIC_LOCK_LAST_KNOWN_ACTION_SECURED_PHYSICAL_INTERIOR,
    HK_CHARACTERISTIC_LOCK_LAST_KNOWN_ACTION_UNSECURED_PHYSICAL_INTERIOR,
    HK_CHARACTERISTIC_LOCK_LAST_KNOWN_ACTION_SECURED_PHYSICAL_EXTERIOR,
    HK_CHARACTERISTIC_LOCK_LAST_KNOWN_ACTION_UNSECURED_PHYSICAL_EXTERIOR,
    HK_CHARACTERISTIC_LOCK_LAST_KNOWN_ACTION_SECURED_KEYPAD,
    HK_CHARACTERISTIC_LOCK_LAST_KNOWN_ACTION_UNSECURED_KEYPAD,
    HK_CHARACTERISTIC_LOCK_LAST_KNOWN_ACTION_SECURED_REMOTELY,
    HK_CHARACTERISTIC_LOCK_LAST_KNOWN_ACTION_UNSECURED_REMOTELY,
    HK_CHARACTERISTIC_LOCK_LAST_KNOWN_ACTION_SECURED_AUTOMATIC_TIMEOUT,
    HK_CHARACTERISTIC_LOCK_LAST_KNOWN_ACTION_RESERVED_ABOVE
} hk_c_lock_last_known_action_value_t;

typedef enum {
    HK_CHARACTERISTIC_LOCK_TARGET_STATE_UNSECURED,
    HK_CHARACTERISTIC_LOCK_TARGET_STATE_SECURED,
    HK_CHARACTERISTIC_LOCK_TARGET_STATE_RESERVED_ABOVE
} hk_c_lock_target_state_value_t;

typedef enum {
    HK_CHARACTERISTIC_ROTATION_DIRECTION_CLOCKWISE,
    HK_CHARACTERISTIC_ROTATION_DIRECTION_COUNTER_CLOCKWISE,
    HK_CHARACTERISTIC_ROTATION_DIRECTION_RESERVED_ABOVE

} hk_c_rotation_direction_value_t;

typedef enum {
    HK_CHARACTERISTIC_TARGET_DOOR_STATE_OPEN,
    HK_CHARACTERISTIC_TARGET_DOOR_STATE_CLOSED,
    HK_CHARACTERISTIC_TARGET_DOOR_STATE_RESERVED_ABOVE
} hk_c_target_door_State_value_t;

typedef enum {
    HK_CHARACTERISTIC_TARGET_HEATING_COOLING_STATE_OFF,
    HK_CHARACTERISTIC_TARGET_HEATING_COOLING_STATE_HEAT,
    HK_CHARACTERISTIC_TARGET_HEATING_COOLING_STATE_COOL,
    HK_CHARACTERISTIC_TARGET_HEATING_COOLING_STATE_AUTO,
    HK_CHARACTERISTIC_TARGET_HEATING_COOLING_STATE_RESERVED_ABOVE
} hk_c_target_heating_cooling_state_value_t;

typedef enum {
    HK_CHARACTERISTIC_TEMP_DISPLAY_UNITS_CELCIUS,
    HK_CHARACTERISTIC_TEMP_DISPLAY_UNITS_FAHRENHEIT,
    HK_CHARACTERISTIC_TEMP_DISPLAY_UNITS_RESERVED_ABOVE
} homkit_c_temp_display_units_value_t;

typedef enum {
    HK_CHARACTERISTIC_AIR_PART_SIZE_2_5_UM,
    HK_CHARACTERISTIC_AIR_PART_SIZE_10_UM,
    HK_CHARACTERISTIC_AIR_PART_SIZE_RESERVED_ABOVE
} hk_c_air_part_size_value_t;

typedef enum {
    HK_CHARACTERISTIC_SECURITY_SYS_STATE_STAY_ARM,
    HK_CHARACTERISTIC_SECURITY_SYS_STATE_AWAY_ARM,
    HK_CHARACTERISTIC_SECURITY_SYS_STATE_NIGHT_ARM,
    HK_CHARACTERISTIC_SECURITY_SYS_STATE_DISARMED,
    HK_CHARACTERISTIC_SECURITY_SYS_STATE_ALARM_TRIGGERED,
    HK_CHARACTERISTIC_SECURITY_SYS_STATE_RESERVED
} hk_c_security_sys_state_value_t;

typedef enum {
    HK_CHARACTERISTIC_CARBON_MONOX_DETECTED_NORMAL,
    HK_CHARACTERISTIC_CARBON_MONOX_DETECTED_ABNORMAL
} hk_c_carbon_monox_detected_value_t;

typedef enum {
    HK_CHARACTERISTIC_CONTACT_SENSOR_STATE_DETECTED,
    HK_CHARACTERISTIC_CONTACT_SENSOR_STATE_NOT_DETECTED
} hk_c_contact_sensor_state_value_t;
