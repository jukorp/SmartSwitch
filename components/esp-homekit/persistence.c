#include <stdio.h>
#include <string.h>
#include <freertos/FreeRTOS.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <unistd.h>
#include <esp_system.h>
#include <esp_log.h>
#include <utils.h>

#include <homekit/homekit.h>

#include "homekit/tlv8.h"
#include "persistence.h"

static const char *TAG = "homekit-persistence";

hk_err_t hk_write_accessory_config(hk_accessory_t *ctx)
{
    LOG_FUNCTION_ENTRY();
    ASSERT(ctx == NULL);

    struct tlv8_container *container = tlv8_container_new();
    if (!container) {
        LOG_DEBUG("failed to allocate tlv8 container");
        return HK_ERR_MEM;
    }

    if (tlv8_container_add_uint32(container, HK_PERSIST_TLV_CATEGORY, ctx->category) != TLV8_ERR_OK) {
        LOG_DEBUG("error adding category to accessory info tlv8 container");
        tlv8_container_free(container);
        return HK_ERR_MEM;
    }

    if (tlv8_container_add_uint32(container, HK_PERSIST_TLV_CONFIG, ctx->config) != TLV8_ERR_OK) {
        LOG_DEBUG("error adding config to accessory info tlv8 container");
        tlv8_container_free(container);
        return HK_ERR_MEM;
    }

    if (tlv8_container_add_uint8(container, HK_PERSIST_TLV_STATUS_FLAGS, ctx->status_flags) != TLV8_ERR_OK) {
        LOG_DEBUG("error adding status flags to accessory info tlv8 container");
        tlv8_container_free(container);
        return HK_ERR_MEM;
    }

    if (ctx->pair.paired) {

        LOG_DEBUG_HEX(ctx->pair.accessory_ltpk, ED25519_PUB_KEY_SIZE, "will write accessory LTPK");

        if (tlv8_container_add_binary(container, HK_PERSIST_TLV_LTPK, ctx->pair.accessory_ltpk,
                                    ED25519_PUB_KEY_SIZE) != TLV8_ERR_OK)
        {
            LOG_DEBUG("failed to add LTPK to accessory info tlv8 container");
            tlv8_container_free(container);
            return HK_ERR_MEM;
        }

        LOG_DEBUG_HEX(ctx->pair.accessory_ltsk, ED25519_PRV_KEY_SIZE, "will write accessory LTSK");

        if (tlv8_container_add_binary(container, HK_PERSIST_TLV_LTSK, ctx->pair.accessory_ltsk,
                                ED25519_PRV_KEY_SIZE) != TLV8_ERR_OK)
        {
            LOG_DEBUG("failed to add LTPK to accessory info tlv8 container");
            tlv8_container_free(container);
            return HK_ERR_MEM;
        }

        LOG_DEBUG("will write pair count %d", ctx->pair.pair_count);

        if (tlv8_container_add_uint8(container, HK_PERSIST_TLV_PAIR_COUNT, ctx->pair.pair_count) != TLV8_ERR_OK)
        {
            LOG_DEBUG("failed to add pair count to accessory info tlv8 container");
            tlv8_container_free(container);
            return HK_ERR_MEM;
        }

        if (ctx->pair.pair_count > 0) {
            struct tlv8_container *pairs_container = tlv8_container_new();
            if (!pairs_container) {
                LOG_DEBUG("failed to allocate pairs tlv8 container");
                tlv8_container_free(container);
                return HK_ERR_MEM;
            }

            for (size_t i = 0; i < ctx->pair.pair_count; i++) {
                if (tlv8_container_add_binary(pairs_container, HK_PERSIST_TLV_PAIRS_CTRL_ID,
                                        ctx->pair.pairs[i]->controller_id,
                                        strlen(ctx->pair.pairs[i]->controller_id)) != TLV8_ERR_OK)
                {
                    LOG_DEBUG("failed to add ctrl_id to pairs tlv8 container");
                    tlv8_container_free(pairs_container);
                    tlv8_container_free(container);
                    return HK_ERR_MEM;
                }

                if (tlv8_container_add_binary(pairs_container, HK_PERSIST_TLV_PAIRS_PUB_KEY,
                                        ctx->pair.pairs[i]->pubkey, ED25519_PUB_KEY_SIZE) != TLV8_ERR_OK)
                {
                    LOG_DEBUG("failed to add public key to pairs tlv8 container");
                    tlv8_container_free(pairs_container);
                    tlv8_container_free(container);
                    return HK_ERR_MEM;
                }

                if (tlv8_container_add_uint8(pairs_container, HK_PERSIST_TLV_PAIRS_PERMS,
                                            ctx->pair.pairs[i]->perms) != TLV8_ERR_OK)
                {
                    LOG_DEBUG("failed to add permissions to pairs tlv8 container");
                    tlv8_container_free(pairs_container);
                    tlv8_container_free(container);
                    return HK_ERR_MEM;
                }

                if (tlv8_container_add_uint8(pairs_container, HK_PERSIST_TLV_PAIRS_IS_ADMIN,
                                            ctx->pair.pairs[i]->is_admin) != TLV8_ERR_OK)
                {
                    LOG_DEBUG("failed to add admin bit to pairs tlv8 container");
                    tlv8_container_free(pairs_container);
                    tlv8_container_free(container);
                    return HK_ERR_MEM;
                }
            }

            void *pair_tlv_bytes = NULL;
            size_t pair_tlv_bytes_len = 0;
            if (tlv8_container_encode(pairs_container, &pair_tlv_bytes, &pair_tlv_bytes_len) != TLV8_ERR_OK) {
                LOG_DEBUG("failed to encode pairs tlv8 container");
                tlv8_container_free(pairs_container);
                tlv8_container_free(container);
                return HK_ERR_MEM;
            }

            tlv8_container_free(pairs_container);

            tlv8_container_add_binary(container, HK_PERSIST_TLV_PAIRS, pair_tlv_bytes, pair_tlv_bytes_len);
        }

    }

    void *data = NULL;
    size_t data_len = 0;
    if (tlv8_container_encode(container, &data, &data_len) != TLV8_ERR_OK) {
        LOG_DEBUG("failed to encode accessory info tlv8 container");
        tlv8_container_free(container);
        return HK_ERR_MEM;
    }

    tlv8_container_free(container);

    int fd = open(ctx->storage_path, O_WRONLY);
    if (fd == -1) {
        LOG_DEBUG("failed to open accessory info file path=%s err=%d", ctx->storage_path, errno);
        free(data);
        return HK_ERR_FS;
    }

    if(write(fd, data, data_len) == -1) {
        LOG_DEBUG("error writing accessory info data to accessory info file path=%s err=%d",
                  ctx->storage_path, errno);
        free(data);
        close(fd);
        return HK_ERR_FS;
    }

    free(data);
    close(fd);
    return HK_ERR_OK;
}

hk_err_t hk_load_accessory_config(hk_accessory_t *ctx)
{
    LOG_FUNCTION_ENTRY();
    ASSERT(ctx == NULL);

    unsigned char *contents = NULL;
    int fd;

    fd = open(ctx->storage_path, O_RDONLY);
    if (fd < 0) {
        // when the file doesn't exist we assume that this is the first time this accessory is being
        // initialized, so we create it and return success.
        if (errno == ENOENT) {
            fd = open(ctx->storage_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
            if (fd < 0) {
                LOG_DEBUG("error creating accessory info file path=%s err=%d",ctx->storage_path, errno);
                return HK_ERR_FS;
            }

            close(fd);
            return HK_ERR_OK;
        } else {
            LOG_DEBUG("error opening accessory storage file err=%d", errno);
            return HK_ERR_FS;
        }
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        LOG_DEBUG("fstat err=%d", errno);
        close(fd);
        return HK_ERR_FS;
    }

    if (st.st_size == 0) {
        LOG_DEBUG("accessory info file has no contents, returning OK");
        close(fd);
        return HK_ERR_OK;
    }

    contents = malloc(st.st_size);
    if (!contents) {
        LOG_DEBUG("failed to allocate accessory info buffer");
        close(fd);
        return 0;
    }

    if (read(fd, contents, st.st_size) != st.st_size) {
        LOG_DEBUG("failed to read accessory info file to end of buffer err=%d", errno);
        free(contents);
        close(fd);
        return HK_ERR_FS;
    }

    close(fd);

    struct tlv8 **tlvs = NULL;
    size_t tlvs_len = 0;
    tlv8_err_t tlv_err = 0;

    tlv_err = tlv8_decode(contents, st.st_size, &tlvs, &tlvs_len);
    if (tlv_err != TLV8_ERR_OK) {
        LOG_DEBUG("failed to decode persisted accessory info tlv data err=%d", tlv_err);
        free(contents);
        return HK_ERR_BAD_DATA;
    }

    free(contents);

    tlv8_lookup_uint32(tlvs, tlvs_len, HK_PERSIST_TLV_CATEGORY, &ctx->category);
    tlv8_lookup_uint32(tlvs, tlvs_len, HK_PERSIST_TLV_CONFIG, &ctx->config);
    tlv8_lookup_uint8(tlvs, tlvs_len, HK_PERSIST_TLV_STATUS_FLAGS, &ctx->status_flags);

    LOG_DEBUG("txt flags lookup category=%d config=%d status_flags=%02x",
              ctx->category, ctx->config, ctx->status_flags);

    void *ltpk = NULL, *ltsk = NULL, *pairs = NULL;
    size_t ltsk_len = 0, ltpk_len = 0, pairs_len = 0;

    tlv8_lookup_binary_all(tlvs, tlvs_len, HK_PERSIST_TLV_PAIRS, &pairs, &pairs_len);

    uint8_t pair_count = 0;
    tlv8_lookup_uint8(tlvs, tlvs_len, HK_PERSIST_TLV_PAIR_COUNT, &pair_count);
    tlv8_lookup_binary_all(tlvs, tlvs_len, HK_PERSIST_TLV_LTPK, &ltpk, &ltpk_len);
    tlv8_lookup_binary_all(tlvs, tlvs_len, HK_PERSIST_TLV_LTSK, &ltsk, &ltsk_len);

    tlv8_free_all(tlvs, tlvs_len);

    LOG_DEBUG("loaded pair count %d", pair_count);

    // if ltpk/ltsk are present then we assume status is paired
    if (ltpk && ltsk) {
        memcpy(ctx->pair.accessory_ltpk, ltpk, ED25519_PUB_KEY_SIZE);
        memcpy(ctx->pair.accessory_ltsk, ltsk, ED25519_PRV_KEY_SIZE);
        ctx->pair.paired = 1;

        free(ltpk);
        free(ltsk);

        LOG_DEBUG_HEX(ctx->pair.accessory_ltpk, ED25519_PUB_KEY_SIZE, "loaded accessory LTPK");
        LOG_DEBUG_HEX(ctx->pair.accessory_ltsk, ED25519_PRV_KEY_SIZE, "loaded accessory LTSK");
    }

    if (pair_count > 0) {
        LOG_DEBUG("will decode persisted pairs count=%d", pair_count);

        struct tlv8 **pair_tlvs = NULL;
        size_t pair_tlvs_len = 0;
        tlv8_decode(pairs, pairs_len, &pair_tlvs, &pair_tlvs_len);
        ASSERT(pair_tlvs_len != pair_count * 4);

        for(size_t i = 0; i < pair_count; i++) {
            int pair_offset = (i > 0) ? i * 4 : 0;

            struct tlv8 *ctrl_id_tlv = pair_tlvs[pair_offset];
            struct tlv8 *pubkey_tlv = pair_tlvs[pair_offset + 1];
            struct tlv8 *perms_tlv = pair_tlvs[pair_offset + 2];
            struct tlv8 *is_admin_tlv = pair_tlvs[pair_offset + 3];

            ASSERT(ctrl_id_tlv->type != HK_PERSIST_TLV_PAIRS_CTRL_ID);
            ASSERT(pubkey_tlv->type != HK_PERSIST_TLV_PAIRS_PUB_KEY);
            ASSERT(perms_tlv->type != HK_PERSIST_TLV_PAIRS_PERMS);
            ASSERT(is_admin_tlv->type != HK_PERSIST_TLV_PAIRS_IS_ADMIN);

            hk_controller_pair_t *pair = malloc(sizeof(hk_controller_pair_t));
            if (!pair) {
                LOG_DEBUG("failed to allocate new pair structure");
                break;
            }

            memset(pair, 0, sizeof(hk_controller_pair_t));

            strncpy(pair->controller_id, ctrl_id_tlv->value, ctrl_id_tlv->length);
            memcpy(pair->pubkey, pubkey_tlv->value, ED25519_PUB_KEY_SIZE);
            pair->perms = *((uint8_t *)perms_tlv->value);
            pair->is_admin = *((uint8_t *)is_admin_tlv->value);

            hk_controller_pair_t **new_pairs = realloc(ctx->pair.pairs,
                sizeof(struct hk_controller_pair *) * ++ctx->pair.pair_count);
            if (!new_pairs) {
                LOG_DEBUG("failed to reallocate accessory pairs");
                free(pair);
                break;
            }

            ctx->pair.pairs = new_pairs;
            ctx->pair.pairs[ctx->pair.pair_count - 1] = pair;

            LOG_DEBUG("added controller pairing:");
            LOG_DEBUG("controller_id: %s", pair->controller_id);
            LOG_DEBUG_HEX(pair->pubkey, 32, "pubkey");
            LOG_DEBUG("permissions: %d", pair->perms);
        }

        tlv8_free_all(pair_tlvs, pair_tlvs_len);
    }

    return HK_ERR_OK;
}
