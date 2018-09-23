#pragma once

#include <homekit/homekit.h>
#include <stdint.h>

typedef enum {
    HK_PERSIST_TLV_CATEGORY = 1,
    HK_PERSIST_TLV_CONFIG,
    HK_PERSIST_TLV_STATUS_FLAGS,
    HK_PERSIST_TLV_LTPK,
    HK_PERSIST_TLV_LTSK,
    HK_PERSIST_TLV_PAIR_COUNT,
    HK_PERSIST_TLV_PAIRS,

    // HK_PERSIST_TLV_PAIRS contains the following three TLV items for every pair
    HK_PERSIST_TLV_PAIRS_CTRL_ID,
    HK_PERSIST_TLV_PAIRS_PUB_KEY,
    HK_PERSIST_TLV_PAIRS_PERMS,
    HK_PERSIST_TLV_PAIRS_IS_ADMIN
} hk_persist_tlv_type_t;

hk_err_t hk_write_accessory_config(hk_accessory_t *ctx);

hk_err_t hk_load_accessory_config(hk_accessory_t *ctx);

