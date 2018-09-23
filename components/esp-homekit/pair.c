#include <freertos/FreeRTOS.h>
#include <string.h>
#include <utils.h>
#include <wolfssl/wolfcrypt/srp.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/chacha20_poly1305.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include "homekit/homekit.h"
#include "homekit/types.h"
#include "homekit/pair.h"
#include "homekit/tlv8.h"
#include "persistence.h"

static const char *TAG = "esp-homekit-pairing";

// HAP spec section 4.6.1 (SRP modifications)
// https://tools.ietf.org/html/rfc5054 section 4 (3072-bit group)
#define HK_SRP_N_LEN 384
static const unsigned char HK_SRP_N[] = {
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc9, 0x0f, 0xda, 0xa2,
  0x21, 0x68, 0xc2, 0x34, 0xc4, 0xc6, 0x62, 0x8b, 0x80, 0xdc, 0x1c, 0xd1,
  0x29, 0x02, 0x4e, 0x08, 0x8a, 0x67, 0xcc, 0x74, 0x02, 0x0b, 0xbe, 0xa6,
  0x3b, 0x13, 0x9b, 0x22, 0x51, 0x4a, 0x08, 0x79, 0x8e, 0x34, 0x04, 0xdd,
  0xef, 0x95, 0x19, 0xb3, 0xcd, 0x3a, 0x43, 0x1b, 0x30, 0x2b, 0x0a, 0x6d,
  0xf2, 0x5f, 0x14, 0x37, 0x4f, 0xe1, 0x35, 0x6d, 0x6d, 0x51, 0xc2, 0x45,
  0xe4, 0x85, 0xb5, 0x76, 0x62, 0x5e, 0x7e, 0xc6, 0xf4, 0x4c, 0x42, 0xe9,
  0xa6, 0x37, 0xed, 0x6b, 0x0b, 0xff, 0x5c, 0xb6, 0xf4, 0x06, 0xb7, 0xed,
  0xee, 0x38, 0x6b, 0xfb, 0x5a, 0x89, 0x9f, 0xa5, 0xae, 0x9f, 0x24, 0x11,
  0x7c, 0x4b, 0x1f, 0xe6, 0x49, 0x28, 0x66, 0x51, 0xec, 0xe4, 0x5b, 0x3d,
  0xc2, 0x00, 0x7c, 0xb8, 0xa1, 0x63, 0xbf, 0x05, 0x98, 0xda, 0x48, 0x36,
  0x1c, 0x55, 0xd3, 0x9a, 0x69, 0x16, 0x3f, 0xa8, 0xfd, 0x24, 0xcf, 0x5f,
  0x83, 0x65, 0x5d, 0x23, 0xdc, 0xa3, 0xad, 0x96, 0x1c, 0x62, 0xf3, 0x56,
  0x20, 0x85, 0x52, 0xbb, 0x9e, 0xd5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6d,
  0x67, 0x0c, 0x35, 0x4e, 0x4a, 0xbc, 0x98, 0x04, 0xf1, 0x74, 0x6c, 0x08,
  0xca, 0x18, 0x21, 0x7c, 0x32, 0x90, 0x5e, 0x46, 0x2e, 0x36, 0xce, 0x3b,
  0xe3, 0x9e, 0x77, 0x2c, 0x18, 0x0e, 0x86, 0x03, 0x9b, 0x27, 0x83, 0xa2,
  0xec, 0x07, 0xa2, 0x8f, 0xb5, 0xc5, 0x5d, 0xf0, 0x6f, 0x4c, 0x52, 0xc9,
  0xde, 0x2b, 0xcb, 0xf6, 0x95, 0x58, 0x17, 0x18, 0x39, 0x95, 0x49, 0x7c,
  0xea, 0x95, 0x6a, 0xe5, 0x15, 0xd2, 0x26, 0x18, 0x98, 0xfa, 0x05, 0x10,
  0x15, 0x72, 0x8e, 0x5a, 0x8a, 0xaa, 0xc4, 0x2d, 0xad, 0x33, 0x17, 0x0d,
  0x04, 0x50, 0x7a, 0x33, 0xa8, 0x55, 0x21, 0xab, 0xdf, 0x1c, 0xba, 0x64,
  0xec, 0xfb, 0x85, 0x04, 0x58, 0xdb, 0xef, 0x0a, 0x8a, 0xea, 0x71, 0x57,
  0x5d, 0x06, 0x0c, 0x7d, 0xb3, 0x97, 0x0f, 0x85, 0xa6, 0xe1, 0xe4, 0xc7,
  0xab, 0xf5, 0xae, 0x8c, 0xdb, 0x09, 0x33, 0xd7, 0x1e, 0x8c, 0x94, 0xe0,
  0x4a, 0x25, 0x61, 0x9d, 0xce, 0xe3, 0xd2, 0x26, 0x1a, 0xd2, 0xee, 0x6b,
  0xf1, 0x2f, 0xfa, 0x06, 0xd9, 0x8a, 0x08, 0x64, 0xd8, 0x76, 0x02, 0x73,
  0x3e, 0xc8, 0x6a, 0x64, 0x52, 0x1f, 0x2b, 0x18, 0x17, 0x7b, 0x20, 0x0c,
  0xbb, 0xe1, 0x17, 0x57, 0x7a, 0x61, 0x5d, 0x6c, 0x77, 0x09, 0x88, 0xc0,
  0xba, 0xd9, 0x46, 0xe2, 0x08, 0xe2, 0x4f, 0xa0, 0x74, 0xe5, 0xab, 0x31,
  0x43, 0xdb, 0x5b, 0xfc, 0xe0, 0xfd, 0x10, 0x8e, 0x4b, 0x82, 0xd1, 0x20,
  0xa9, 0x3a, 0xd2, 0xca, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

#define HK_SRP_G_LEN 1
static const unsigned char HK_SRP_G[] = {0x05};

static hk_controller_pair_t *_get_pairing(hk_accessory_t *ctx, char *ctrl_id)
{
    ASSERT(ctx == NULL);

    LOG_DEBUG("looking up pairing controller_id=%s", ctrl_id);

    for (size_t i = 0; i < ctx->pair.pair_count; i++) {
        LOG_DEBUG("comparing ctrl_id=%s paired_ctrl_id=%s", ctrl_id, ctx->pair.pairs[i]->controller_id);
        if (strcmp(ctx->pair.pairs[i]->controller_id, ctrl_id) == 0) {
            return ctx->pair.pairs[i];
        }
    }

    return NULL;
}

static hk_err_t _add_pairing(hk_accessory_t *ctx, char *ctrl_id,
    unsigned char pubkey[ED25519_PUB_KEY_SIZE], hk_permission_t perms, uint8_t is_admin)
{
    ASSERT(ctx == NULL);
    ASSERT(ctrl_id == NULL);
    ASSERT(pubkey == NULL);

    LOG_DEBUG("adding pairing ctrl_id=%s pubkey=%p perms=%02x", ctrl_id, pubkey, perms);

    hk_controller_pair_t *pair = _get_pairing(ctx, ctrl_id);
    if (pair) {
        LOG_DEBUG("pairing with controller pairing ID %s already exists", ctrl_id);
        return 1;
    }

    pair = malloc(sizeof(hk_controller_pair_t));
    memset(pair, 0, sizeof(hk_controller_pair_t));
    memcpy(pair->controller_id, ctrl_id, strlen(ctrl_id));
    memcpy(pair->pubkey, pubkey, ED25519_PUB_KEY_SIZE);
    pair->perms = perms;
    pair->is_admin = is_admin;

    hk_controller_pair_t **pairs =
        realloc(ctx->pair.pairs, ++ctx->pair.pair_count * (sizeof(struct hk_controller_pair *)));
    if (!pairs) {
        LOG_DEBUG("failed to reallocate context pairings");
        return 0;
    }

    pairs[ctx->pair.pair_count - 1] = pair;
    ctx->pair.pairs = pairs;

    hk_set_paired_status(ctx, true);

    return hk_write_accessory_config(ctx);
}

static hk_err_t _update_pairing(hk_accessory_t *ctx, char *ctrl_id, hk_permission_t perms, uint8_t is_admin)
{
    ASSERT(ctx == NULL);
    ASSERT(ctrl_id == NULL);

    hk_controller_pair_t *pair = _get_pairing(ctx, ctrl_id);
    if (!pair) {
        LOG_DEBUG("pair not found controller_id=%s", ctrl_id);
        return HK_ERR_NOT_FOUND;
    }

    pair->perms = perms;
    pair->is_admin = is_admin;

    return hk_write_accessory_config(ctx);
}

static hk_err_t _remove_pairing(hk_accessory_t *ctx, char *ctrl_id)
{
    ASSERT(ctx == NULL);
    ASSERT(ctrl_id == NULL);

    int index = -1;
    for (int i = 0; i < ctx->pair.pair_count; i++) {
        if (!strcmp(ctx->pair.pairs[i]->controller_id, ctrl_id)) {
            index = i;
        }
    }

    if (index == -1) {
        LOG_DEBUG("pairing for controller ID %s not found", ctrl_id);
        return HK_ERR_OK;
    }

    hk_controller_pair_t *pair = ctx->pair.pairs[index];

    // if it's the last one in the list we have nothing to move
    if (index != ctx->pair.pair_count - 1) {
        size_t mv_size = sizeof(hk_controller_pair_t *) * (ctx->pair.pair_count - index - 1);
        memmove(&ctx->pair.pairs[index], &ctx->pair.pairs[index + 1], mv_size);
    }

    if (ctx->pair.pair_count - 1 == 0) {
        free(ctx->pair.pairs);
        ctx->pair.pairs = NULL;
        ctx->pair.pair_count = 0;
        hk_set_paired_status(ctx, false);
    } else {
        hk_controller_pair_t **pairs = realloc(ctx->pair.pairs,
            sizeof(hk_controller_pair_t *) * --ctx->pair.pair_count);
        if (pairs)
            ctx->pair.pairs = pairs;
    }

    // TODO: kill all active sessions with this controller
    //       A complication of this is that it's possible that the remove request is coming from
    //       the controller to be removed. We might need to have a separate task that we can trigger
    //       once 1) this request is fulfilled, and 2) we have responded to the request, that will
    //       actually kill off the session.

    free(pair);

    return hk_write_accessory_config(ctx);
}

// _pair_setup_has_timed_out is used to determine whether or not a new pair request that appears
// to be unrelated to a pre-existing pair state should be honored.
static uint8_t _pair_setup_has_timed_out(hk_accessory_t *ctx)
{
    if (ctx->pair.last_pair_attempt.tv_sec == 0) {
        LOG_INFO("last pair attempt is not set, assuming initial pair setup request");
        return 1;
    }

    struct timeval current_time;
    if (gettimeofday(&current_time, NULL) != 0) {
        LOG_ERROR("failed to get time");
        return 1;
    }

    LOG_DEBUG("checking for pair timeout current=%lu last_attempt=%lu threshold=%d",
        current_time.tv_sec, ctx->pair.last_pair_attempt.tv_sec, HK_PAIR_TIMEOUT_SEC);

    return (current_time.tv_sec - ctx->pair.last_pair_attempt.tv_sec > HK_PAIR_TIMEOUT_SEC);
}

static void _pair_setup_set_error_response(hk_tlv_pair_state_t pair_state, hk_pair_err_t err,
    void **response, size_t *len)
{
    struct tlv8 *state = tlv8_from_uint8(HK_PAIR_TLV_STATE, pair_state);
    struct tlv8 *error = tlv8_from_uint8(HK_PAIR_TLV_ERROR, err);
    struct tlv8 *tlvs[] = {state, error};
    if (tlv8_encode(tlvs, array_len(tlvs), response, len) != TLV8_ERR_OK) {
        LOG_ERROR("error encoding pair setup error TLV response");
    }
}

static void _pair_setup_set_http_code(int code, int *http_code)
{
    if (http_code)
        *http_code = code;
}

static char *hk_pair_state_to_string(hk_tlv_pair_state_t state)
{
    switch (state) {
        case HK_TLV_PAIR_STATE_NONE:              return "none";
        case HK_TLV_PAIR_STATE_START_REQUEST:     return "start request";
        case HK_TLV_PAIR_STATE_START_RESPONSE:    return "start response";
        case HK_TLV_PAIR_STATE_VERIFY_REQUEST:    return "verify request";
        case HK_TLV_PAIR_STATE_VERIFY_RESPONSE:   return "verify response";
        case HK_TLV_PAIR_STATE_EXCHANGE_REQUEST:  return "exchange request";
        case HK_TLV_PAIR_STATE_EXCHANGE_RESPONSE: return "exchange response";
        default:                                       return "unknown";
    }
}

static char *hk_pair_verify_state_to_string(hk_tlv_pair_verify_state_t state)
{
    switch (state) {
        case HK_TLV_PAIR_VERIFY_STATE_NONE:            return "none";
        case HK_TLV_PAIR_VERIFY_STATE_START_REQUEST:   return "start request";
        case HK_TLV_PAIR_VERIFY_STATE_START_RESPONSE:  return "start response";
        case HK_TLV_PAIR_VERIFY_STATE_FINISH_REQUEST:  return "finish request";
        case HK_TLV_PAIR_VERIFY_STATE_FINISH_RESPONSE: return "finish response";
        default:                                       return "unknown";
    }
}

uint8_t hk_session_encrypt_response(hk_session_context_t *ctx, void **response, size_t *len)
{
    ASSERT(ctx == NULL);
    ASSERT(response == NULL);
    ASSERT(len == NULL);
    ASSERT(*len == 0);

    size_t new_len = *len + HK_SESSION_REQUEST_LEN_SIZE + CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE;
    void *buff = malloc(new_len);
    if (!buff)
        return 0;

    memcpy(buff, len, sizeof(uint16_t));

    unsigned char nonce[12] = {0};
    memcpy(nonce + 12 - sizeof(uint64_t), &ctx->encrypt_count, sizeof(uint64_t));
    ctx->encrypt_count++;

    LOG_DEBUG_HEX(ctx->encryption_key, 32, "will encrypt payload session=%p key=", ctx);

    wc_ChaCha20Poly1305_Encrypt(ctx->encryption_key, nonce, (unsigned char *)len,
                                HK_SESSION_REQUEST_LEN_SIZE, *response, *len,
                                buff + HK_SESSION_REQUEST_LEN_SIZE,
                                buff + HK_SESSION_REQUEST_LEN_SIZE + *len);

    void *new_response = realloc(*response, new_len);
    if (!new_response) {
        free(buff);
        return 0;
    }

    memcpy(new_response, buff, new_len);
    free(buff);

    *response = new_response;
    *len = new_len;
    return 1;
}

uint8_t hk_session_decrypt_request(hk_session_context_t *ctx, void *request, size_t *len)
{
    ASSERT(ctx == NULL);
    ASSERT(request == NULL);
    ASSERT(len == NULL);
    ASSERT(*len == 0);

    unsigned char *decrypted = malloc(*len);
    if (!decrypted)
        return 0;

    LOG_DEBUG("encrypted data length is %d", *((uint16_t *)request));

    // I've seen some implementations increment the nonce for each decrypt, but the HAP spec
    // doesn't mention this anywhere. So if this fails, that's probably why :(
    unsigned char nonce[12] = {0};
    memcpy(nonce + 12 - sizeof(uint64_t), &ctx->decrypt_count, sizeof(uint64_t));
    ctx->decrypt_count++;

    unsigned char *authtag = request + *len - CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE;
    *len = *len - HK_SESSION_REQUEST_LEN_SIZE - CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE;

    LOG_DEBUG_HEX(ctx->decryption_key, 32, "will decrypt payload session=%p key=", ctx);

    int result = wc_ChaCha20Poly1305_Decrypt(ctx->decryption_key, nonce, request,
                                             HK_SESSION_REQUEST_LEN_SIZE,
                                             request + HK_SESSION_REQUEST_LEN_SIZE,
                                             *len, authtag, decrypted);

    if (result != 0) {
        LOG_DEBUG("session request decrypt failed err=%d", result);
        free(decrypted);
        return 0;
    }

    memcpy(request, decrypted, *len);
    free(decrypted);

    return 1;
}

static uint8_t _generate_long_term_keys(hk_accessory_t *ctx)
{
    if (ctx->pair.ltpk_generated) {
        LOG_DEBUG("LTPK and LTSK already generated");
        return 1;
    } else {
        int r;
        ed25519_key key;
        WC_RNG rng;

        r = wc_InitRng(&rng);
        if (r != 0) {
            LOG_DEBUG("failed to initialize RNG err=%d", r);
            return 0;
        }

        r = wc_ed25519_init(&key);
        if (r != 0) {
            LOG_DEBUG("failed to initialize ed25519 key err=%d", r);
            return 0;
        }

        r = wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &key);
        if (r != 0) {
            LOG_DEBUG("failed to make ed25519 key err=%d", r);
            wc_ed25519_free(&key);
            return 0;
        }

        size_t ltpk_len = ED25519_PUB_KEY_SIZE;
        r = wc_ed25519_export_public(&key, ctx->pair.accessory_ltpk, &ltpk_len);
        if (r != 0) {
            LOG_DEBUG("failed to export ed25519 public key err=%d", r);
            wc_ed25519_free(&key);
            return 0;
        }

        LOG_DEBUG_HEX(ctx->pair.accessory_ltpk, ltpk_len, "generated device long term public key (%d)", ltpk_len);

        size_t ltsk_len = ED25519_PRV_KEY_SIZE;
        r = wc_ed25519_export_private(&key, ctx->pair.accessory_ltsk, &ltsk_len);
        if (r != 0) {
            LOG_DEBUG("failed to export ed25519 private key err=%d", r);
            wc_ed25519_free(&key);
            return 0;
        }

        LOG_DEBUG_HEX(ctx->pair.accessory_ltsk, ltsk_len, "generated long term secret key (%d)", ltsk_len);

        hk_err_t err = hk_write_accessory_config(ctx);
        if (err != HK_ERR_OK) {
            LOG_ERROR("failed to write accessory config after LT key generation (%d)", err);
        }

        ctx->pair.ltpk_generated = 1;
        return 1;
    }
}

static uint8_t _generate_session_encryption_keys(hk_session_context_t *ctx)
{
    int result = wc_HKDF(SHA512, ctx->shared_secret, ctx->shared_secret_len, (unsigned char *)HK_SESSION_CTRL_SALT,
                    strlen(HK_SESSION_CTRL_SALT), (unsigned char *)HK_SESSION_ENCRYPT_CTRL_READ_INFO,
                    strlen(HK_SESSION_ENCRYPT_CTRL_READ_INFO), ctx->encryption_key, 32);

    if (result != 0) {
        LOG_DEBUG("failed to derrive session encryption key pair_ctx=%p err=%d", ctx, result);
        return 0;
    }

    LOG_DEBUG_HEX(ctx->encryption_key, 32, "generated encryption key session=%p encryption_key=", ctx);

    result = wc_HKDF(SHA512, ctx->shared_secret, ctx->shared_secret_len, (unsigned char *)HK_SESSION_CTRL_SALT,
                strlen(HK_SESSION_CTRL_SALT), (unsigned char *)HK_SESSION_DECRYPT_CTRL_WRITE_INFO,
                strlen(HK_SESSION_DECRYPT_CTRL_WRITE_INFO), ctx->decryption_key, 32);

    if (result != 0) {
        LOG_DEBUG("failed to derrive session decryption key pair_ctx=%p err=%d", ctx, result);
        return 0;
    }

    LOG_DEBUG_HEX(ctx->decryption_key, 32, "generated decryption key session=%p decryption_key=", ctx);

    return 1;
}

void _list_pairings_request(hk_session_context_t *ctx, struct tlv8 **tlvs, size_t tlv_count,
                            void **response, size_t *resp_len, int *http_code)
{
    if (!ctx->pair->is_admin) {
        LOG_ERROR("controller %s not an admin, denying list pairings request", ctx->pair->controller_id);
        _pair_setup_set_error_response(HK_TLV_PAIR_STATE_START_RESPONSE,
                                       HK_PAIR_ERR_AUTHENTICATION, response, resp_len);
        _pair_setup_set_http_code(200, http_code);
        return;
    }

    struct tlv8_container *container = tlv8_container_new();
    tlv8_container_add_uint8(container, HK_PAIR_TLV_STATE, HK_TLV_PAIR_STATE_START_RESPONSE);

    LOG_DEBUG("will build response for list pairings request with %d total pairs", ctx->ctx->pair.pair_count);

    for(size_t i = 0; i < ctx->ctx->pair.pair_count; i++) {
        hk_controller_pair_t *pair = ctx->ctx->pair.pairs[i];

        LOG_DEBUG("adding pairing to list pairing response controller_id=%s", pair->controller_id);

        tlv8_container_add_binary(container, HK_PAIR_TLV_IDENTIFIER,
                                  pair->controller_id, strlen(pair->controller_id));
        tlv8_container_add_binary(container, HK_PAIR_TLV_PUBLIC_KEY, pair->pubkey, 32);
        tlv8_container_add_uint8(container, HK_PAIR_TLV_PERMISSIONS, pair->perms);

        if (ctx->ctx->pair.pair_count != i + 1) {
            tlv8_container_add_zero_length(container, HK_PAIR_TLV_SEPARATOR);
        }
    }

    void *payload = NULL;
    size_t payload_len = 0;
    if (tlv8_container_encode(container, &payload, &payload_len) != TLV8_ERR_OK) {
        LOG_ERROR("failed to encode list pairings TLV response");
        _pair_setup_set_error_response(HK_TLV_PAIR_STATE_START_RESPONSE,
                                       HK_PAIR_ERR_UNKNOWN, response, resp_len);
        _pair_setup_set_http_code(500, http_code);
        tlv8_container_free(container);
        return;
    }

    tlv8_container_free(container);

    *response = payload;
    *resp_len = payload_len;
    _pair_setup_set_http_code(200, http_code);
}

char *hk_pairings_request_method_to_string(hk_pair_method_t method)
{
    switch (method) {
        case HK_PAIR_METHOD_ADD_PAIRING:    return "add pairing";
        case HK_PAIR_METHOD_LIST_PAIRINGS:  return "list pairings";
        case HK_PAIR_METHOD_REMOVE_PAIRING: return "removing pairing";
        default:                            return "unknown";
    }
}

void _add_pairing_request(hk_session_context_t *ctx, struct tlv8 **tlvs, size_t tlv_count,
                          void **response, size_t *resp_len, int *http_code)
{
    if (!ctx->pair->is_admin) {
        LOG_ERROR("add pairing request not from an admin pair, will deny request");
        _pair_setup_set_error_response(HK_TLV_PAIR_STATE_START_RESPONSE, HK_PAIR_ERR_AUTHENTICATION, response, resp_len);
        _pair_setup_set_http_code(403, http_code);
        return;
    }

    void *ctrl_id = NULL;
    size_t ctrl_id_len = 0;
    if (tlv8_lookup_binary_all(tlvs, tlv_count, HK_PAIR_TLV_IDENTIFIER, &ctrl_id, &ctrl_id_len) != TLV8_ERR_OK) {
        LOG_ERROR("add pairing request did not contain controller ID");
        _pair_setup_set_error_response(HK_TLV_PAIR_STATE_START_RESPONSE, HK_PAIR_ERR_UNKNOWN, response, resp_len);
        _pair_setup_set_http_code(400, http_code);
        return;
    }

    void *pubkey = NULL;
    size_t pubkey_len = 0;
    if (tlv8_lookup_binary_all(tlvs, tlv_count, HK_PAIR_TLV_PUBLIC_KEY, &pubkey, &pubkey_len) != TLV8_ERR_OK) {
        LOG_ERROR("add pairing request did not contain controller public key");
        _pair_setup_set_error_response(HK_TLV_PAIR_STATE_START_RESPONSE, HK_PAIR_ERR_UNKNOWN, response, resp_len);
        _pair_setup_set_http_code(400, http_code);
        free(ctrl_id);
        return;
    }

    hk_permission_t perms = HK_PERMISSION_NONE;
    if (tlv8_lookup_uint8(tlvs, tlv_count, HK_PAIR_TLV_PERMISSIONS, (uint8_t *)&perms) != TLV8_ERR_OK) {
        LOG_ERROR("add pairing request did not contain controller permissions");
        _pair_setup_set_error_response(HK_TLV_PAIR_STATE_START_RESPONSE, HK_PAIR_ERR_UNKNOWN, response, resp_len);
        _pair_setup_set_http_code(400, http_code);
        free(ctrl_id);
        free(pubkey);
        return;
    }

    char ctrl_id_str[ctrl_id_len + 1];
    memset(ctrl_id_str, 0, ctrl_id_len + 1);
    memcpy(ctrl_id_str, ctrl_id, ctrl_id_len);

    hk_controller_pair_t *pair = _get_pairing(ctx->ctx, ctrl_id_str);
    if (pair) {
        LOG_DEBUG("existing pair found, will update pairing");

        if (memcmp(pair->pubkey, pubkey, pubkey_len) != 0) {
            LOG_ERROR("existing pair public key does not match pair to be updated, will deny request");
            _pair_setup_set_error_response(HK_TLV_PAIR_STATE_START_RESPONSE, HK_PAIR_ERR_UNKNOWN, response, resp_len);
            _pair_setup_set_http_code(200, http_code);
            free(ctrl_id);
            free(pubkey);
        }

        hk_err_t err = _update_pairing(ctx->ctx, ctrl_id_str, perms, 0);
        if (err != HK_ERR_OK) {
            LOG_ERROR("failed to update pairing (%d)", err);
            _pair_setup_set_error_response(HK_TLV_PAIR_STATE_START_RESPONSE, HK_PAIR_ERR_UNKNOWN, response, resp_len);
            _pair_setup_set_http_code(500, http_code);
            free(ctrl_id);
            free(pubkey);
        }

        free(ctrl_id);
        free(pubkey);

        struct tlv8_container *container = tlv8_container_new();
        tlv8_container_add_uint8(container, HK_PAIR_TLV_STATE, HK_TLV_PAIR_STATE_START_RESPONSE);

        void *payload = NULL;
        size_t payload_len = 0;
        tlv8_container_encode(container, &payload, &payload_len);
        tlv8_container_free(container);

        *response = payload;
        *resp_len = payload_len;

        if (http_code)
            *http_code = 200;

        return;
    }

    LOG_DEBUG_HEX(pubkey, pubkey_len, "will add pairing controller_id=%s pubkey=", ctrl_id_str);

    hk_err_t err = _add_pairing(ctx->ctx, ctrl_id_str, pubkey, perms, 0);
    if (err != HK_ERR_OK) {
        LOG_ERROR("failed to add controller pairing (%d)", err);
        _pair_setup_set_error_response(HK_TLV_PAIR_STATE_START_RESPONSE, HK_PAIR_ERR_UNKNOWN, response, resp_len);
        _pair_setup_set_http_code(500, http_code);
        free(ctrl_id);
        free(pubkey);
    }

    free(ctrl_id);
    free(pubkey);

    struct tlv8_container *container = tlv8_container_new();
    tlv8_container_add_uint8(container, HK_PAIR_TLV_STATE, HK_TLV_PAIR_STATE_START_RESPONSE);

    void *payload = NULL;
    size_t payload_len = 0;
    tlv8_container_encode(container, &payload, &payload_len);
    tlv8_container_free(container);

    *response = payload;
    *resp_len = payload_len;

    if (http_code)
        *http_code = 200;
}

void _remove_pairing_request(hk_session_context_t *ctx, struct tlv8 **tlvs, size_t tlv_count,
                          void **response, size_t *resp_len, int *http_code)
{
    if (!ctx->pair->is_admin) {
        LOG_ERROR("remove pairing request is from non-admin controller, denying request");
        _pair_setup_set_error_response(HK_TLV_PAIR_STATE_START_RESPONSE, HK_PAIR_ERR_AUTHENTICATION, response, resp_len);
        _pair_setup_set_http_code(403, http_code);
        return;
    }

    void *ctrl_id = NULL;
    size_t ctrl_id_len = 0;
    if (tlv8_lookup_binary_all(tlvs, tlv_count, HK_PAIR_TLV_IDENTIFIER, &ctrl_id, &ctrl_id_len) != TLV8_ERR_OK) {
        LOG_ERROR("remove pairing request did not contain controller ID");
        _pair_setup_set_error_response(HK_TLV_PAIR_STATE_START_RESPONSE, HK_PAIR_ERR_UNKNOWN, response, resp_len);
        _pair_setup_set_http_code(400, http_code);
        return;
    }

    char ctrl_id_str[ctrl_id_len + 1];
    memset(ctrl_id_str, 0, ctrl_id_len + 1);
    memcpy(ctrl_id_str, ctrl_id, ctrl_id_len);

    LOG_DEBUG("will remove pairing controller_id=%s", ctrl_id_str);

    hk_err_t err = _remove_pairing(ctx->ctx, ctrl_id_str);
    free(ctrl_id);
    if (err != HK_ERR_OK) {
        LOG_ERROR("failed to remove pairing with controller ID %s", ctrl_id_str);
        _pair_setup_set_error_response(HK_TLV_PAIR_STATE_START_RESPONSE, HK_PAIR_ERR_UNKNOWN, response, resp_len);
        _pair_setup_set_http_code(400, http_code);
        return;
    }

    struct tlv8_container *container = tlv8_container_new();
    tlv8_container_add_uint8(container, HK_PAIR_TLV_STATE, HK_TLV_PAIR_STATE_START_RESPONSE);

    void *payload = NULL;
    size_t payload_len = 0;
    tlv8_container_encode(container, &payload, &payload_len);
    tlv8_container_free(container);

    *response = payload;
    *resp_len = payload_len;

    if (http_code)
        *http_code = 200;
}

void hk_handle_pairings_request(hk_session_context_t *ctx, void *request, size_t len,
                                void **response, size_t *resp_len, int *http_code)
{
    ASSERT(ctx == NULL);
    ASSERT(request == NULL);
    ASSERT(len == 0);
    ASSERT(response == NULL);
    ASSERT(resp_len == NULL);

    if (!ctx->verified) {
        LOG_DEBUG("denying pairings request for session context %p", ctx);
        *response = NULL;
        *resp_len = 0;

        if (http_code)
            *http_code = 403;

        return;
    }

    struct tlv8 **tlvs = NULL;
    size_t tlv_count = 0;
    if(tlv8_decode(request, len, &tlvs, &tlv_count) != TLV8_ERR_OK) {
        LOG_ERROR("failed to decode pairings request TLV data");
        _pair_setup_set_error_response(HK_TLV_PAIR_STATE_START_RESPONSE,
                                       HK_PAIR_ERR_UNKNOWN, response, resp_len);
        _pair_setup_set_http_code(400, http_code);
        return;
    }

    hk_pair_method_t method = 0;
    if (tlv8_lookup_uint8(tlvs, tlv_count, HK_PAIR_TLV_METHOD, (uint8_t *)&method) != TLV8_ERR_OK) {
        LOG_ERROR("pairings request did not contain method");
        _pair_setup_set_error_response(HK_TLV_PAIR_STATE_START_RESPONSE,
                                       HK_PAIR_ERR_UNKNOWN, response, resp_len);
        _pair_setup_set_http_code(400, http_code);
        return;
    }

    LOG_DEBUG("pairings request method is %s", hk_pairings_request_method_to_string(method));

    switch (method) {
        case HK_PAIR_METHOD_ADD_PAIRING:
            _add_pairing_request(ctx, tlvs, tlv_count, response, resp_len, http_code);
            break;

        case HK_PAIR_METHOD_REMOVE_PAIRING:
            _remove_pairing_request(ctx, tlvs, tlv_count, response, resp_len, http_code);
            break;

        case HK_PAIR_METHOD_LIST_PAIRINGS:
            _list_pairings_request(ctx, tlvs, tlv_count, response, resp_len, http_code);
            break;

        default:
            LOG_ERROR("invalid pair method %d in pairings request", method);
            _pair_setup_set_error_response(HK_TLV_PAIR_STATE_START_RESPONSE,
                                        HK_PAIR_ERR_UNKNOWN, response, resp_len);
            _pair_setup_set_http_code(400, http_code);
            break;
    }

    tlv8_free_all(tlvs, tlv_count);
}

static void _pair_verify_start_request(hk_session_context_t *ctx, struct tlv8 **tlvs,
    size_t tlv_count, void **response, size_t *resp_len, int *http_code)
{
    void *ios_curve_pubkey = NULL;
    size_t ios_curve_pubkey_len = 0;

    if (tlv8_lookup_binary_all(tlvs, tlv_count, HK_PAIR_TLV_PUBLIC_KEY,
        &ios_curve_pubkey, &ios_curve_pubkey_len) != TLV8_ERR_OK) {
        LOG_ERROR("pair verify start request did not contain public key TLV");
        _pair_setup_set_error_response(HK_TLV_PAIR_VERIFY_STATE_START_RESPONSE,
            HK_PAIR_ERR_UNKNOWN, response, resp_len);
        _pair_setup_set_http_code(400, http_code);
        return;
    }

    memcpy(ctx->controller_pubkey, ios_curve_pubkey, CURVE25519_KEYSIZE);
    free(ios_curve_pubkey);

    WC_RNG rng;
    int result = wc_InitRng(&rng);
    if (result != 0) {
        LOG_ERROR("failed to initialize RNG (%d)", result);
        _pair_setup_set_error_response(HK_TLV_PAIR_VERIFY_STATE_START_RESPONSE,
            HK_PAIR_ERR_UNKNOWN, response, resp_len);
        _pair_setup_set_http_code(500, http_code);
        return;
    }

    curve25519_key gen_curve_keypair;

    result = wc_curve25519_init(&ctx->keypair);
    if (result != 0) {
        LOG_ERROR("failed to make curve25519 key pair (%d)", result);
        _pair_setup_set_error_response(HK_TLV_PAIR_VERIFY_STATE_START_RESPONSE,
            HK_PAIR_ERR_UNKNOWN, response, resp_len);
        _pair_setup_set_http_code(500, http_code);
        return;
    }

    result = wc_curve25519_init(&gen_curve_keypair);
    if (result != 0) {
        LOG_ERROR("failed to make curve25519 key pair (%d)", result);
        _pair_setup_set_error_response(HK_TLV_PAIR_VERIFY_STATE_START_RESPONSE,
            HK_PAIR_ERR_UNKNOWN, response, resp_len);
        _pair_setup_set_http_code(500, http_code);
        wc_curve25519_free(&ctx->keypair);
        return;
    }

    result = wc_curve25519_make_key(&rng, CURVE25519_KEYSIZE, &ctx->keypair);
    if (result != 0) {
        LOG_ERROR("failed to make curve25519 key pair (%d)", result);
        _pair_setup_set_error_response(HK_TLV_PAIR_VERIFY_STATE_START_RESPONSE,
            HK_PAIR_ERR_UNKNOWN, response, resp_len);
        _pair_setup_set_http_code(500, http_code);
        wc_curve25519_free(&ctx->keypair);
        wc_curve25519_free(&gen_curve_keypair);
        return;
    }

    unsigned char accessory_curve_pubkey[CURVE25519_KEYSIZE];
    size_t accessory_curve_pubkey_len = CURVE25519_KEYSIZE;

    result = wc_curve25519_export_public_ex(&ctx->keypair, accessory_curve_pubkey,
        &accessory_curve_pubkey_len, EC25519_LITTLE_ENDIAN);
    if (result != 0) {
        LOG_ERROR("failed to export accessory curve public key (%d)", result);
        _pair_setup_set_error_response(HK_TLV_PAIR_VERIFY_STATE_START_RESPONSE,
            HK_PAIR_ERR_UNKNOWN, response, resp_len);
        _pair_setup_set_http_code(500, http_code);
        wc_curve25519_free(&ctx->keypair);
        wc_curve25519_free(&gen_curve_keypair);
        return;
    }

    memcpy(ctx->accessory_pubkey, accessory_curve_pubkey, CURVE25519_KEYSIZE);

    result = wc_curve25519_import_public_ex(ctx->controller_pubkey, CURVE25519_KEYSIZE,
        &gen_curve_keypair, EC25519_LITTLE_ENDIAN);
    if (result != 0) {
        LOG_ERROR("failed to export accessory curve public key (%d)", result);
        _pair_setup_set_error_response(HK_TLV_PAIR_VERIFY_STATE_START_RESPONSE,
            HK_PAIR_ERR_UNKNOWN, response, resp_len);
        _pair_setup_set_http_code(500, http_code);
        wc_curve25519_free(&ctx->keypair);
        wc_curve25519_free(&gen_curve_keypair);
        return;
    }

    ctx->shared_secret_len = 64;
    result = wc_curve25519_shared_secret_ex(&ctx->keypair, &gen_curve_keypair, ctx->shared_secret,
        &ctx->shared_secret_len, EC25519_LITTLE_ENDIAN);

    wc_curve25519_free(&ctx->keypair);
    wc_curve25519_free(&gen_curve_keypair);

    if (result != 0) {
        LOG_ERROR("failed to generate shared secret (%d)", result);
        _pair_setup_set_error_response(HK_TLV_PAIR_VERIFY_STATE_START_RESPONSE,
            HK_PAIR_ERR_UNKNOWN, response, resp_len);
        _pair_setup_set_http_code(500, http_code);
        return;
    }

    size_t acc_info_len = (CURVE25519_KEYSIZE * 2) + strlen(ctx->ctx->device_id);
    unsigned char *acc_info = malloc(acc_info_len);
    if (!acc_info) {
        LOG_ERROR("could not allocate accessory info");
        _pair_setup_set_error_response(HK_TLV_PAIR_VERIFY_STATE_START_RESPONSE,
            HK_PAIR_ERR_UNKNOWN, response, resp_len);
        _pair_setup_set_http_code(500, http_code);
        return;
    }

    memcpy(acc_info, accessory_curve_pubkey, CURVE25519_KEYSIZE);
    memcpy(acc_info + CURVE25519_KEYSIZE, ctx->ctx->device_id, strlen(ctx->ctx->device_id));
    memcpy(acc_info + CURVE25519_KEYSIZE + strlen(ctx->ctx->device_id), ctx->controller_pubkey, ED25519_PUB_KEY_SIZE);

    ed25519_key ltk;
    result = wc_ed25519_init(&ltk);
    if (result != 0) {
        LOG_ERROR("failed to init long term key");
        _pair_setup_set_error_response(HK_TLV_PAIR_VERIFY_STATE_START_RESPONSE,
            HK_PAIR_ERR_UNKNOWN, response, resp_len);
        _pair_setup_set_http_code(500, http_code);
        free(acc_info);
        return;
    }

    result = wc_ed25519_import_private_key(ctx->ctx->pair.accessory_ltsk, ED25519_PRV_KEY_SIZE,
        ctx->ctx->pair.accessory_ltpk, ED25519_PUB_KEY_SIZE, &ltk);

    if (result != 0) {
        LOG_ERROR("failed to import long term key");
        _pair_setup_set_error_response(HK_TLV_PAIR_VERIFY_STATE_START_RESPONSE,
            HK_PAIR_ERR_UNKNOWN, response, resp_len);
        _pair_setup_set_http_code(500, http_code);
        free(acc_info);
        wc_ed25519_free(&ltk);
        return;
    }

    unsigned char acc_sig[64];
    size_t acc_sig_len = 64;
    result = wc_ed25519_sign_msg(acc_info, acc_info_len, acc_sig, &acc_sig_len, &ltk);

    wc_ed25519_free(&ltk);

    if (result != 0) {
        LOG_ERROR("failed to sign accessory info (%d)", result);
        _pair_setup_set_error_response(HK_TLV_PAIR_VERIFY_STATE_START_RESPONSE,
            HK_PAIR_ERR_UNKNOWN, response, resp_len);
        _pair_setup_set_http_code(500, http_code);
        free(acc_info);
        return;
    }

    free(acc_info);

    LOG_DEBUG_HEX(acc_sig, acc_sig_len, "generated M2 response accessory info signature");

    LOG_DEBUG("device_id=%s device_id_len=%d", ctx->ctx->device_id, strlen(ctx->ctx->device_id));

    struct tlv8_container *container = tlv8_container_new();
    tlv8_container_add_binary(container, HK_PAIR_TLV_IDENTIFIER, ctx->ctx->device_id, strlen(ctx->ctx->device_id));
    tlv8_container_add_binary(container, HK_PAIR_TLV_SIGNATURE, acc_sig, acc_sig_len);

    void *sub_tlv_bytes = NULL;
    size_t sub_tlv_bytes_len = 0;
    if (tlv8_container_encode(container, &sub_tlv_bytes, &sub_tlv_bytes_len) != TLV8_ERR_OK) {
        LOG_ERROR("failed to encode sub TLV");
        _pair_setup_set_error_response(HK_TLV_PAIR_VERIFY_STATE_START_RESPONSE,
            HK_PAIR_ERR_UNKNOWN, response, resp_len);
        _pair_setup_set_http_code(500, http_code);
        tlv8_container_free(container);
        return;
    }

    tlv8_container_free(container);

    result = wc_HKDF(SHA512, ctx->shared_secret, ctx->shared_secret_len, (unsigned char *)HK_PAIR_VERIFY_ENC_SALT,
        strlen(HK_PAIR_VERIFY_ENC_SALT), (unsigned char *)HK_PAIR_VERIFY_ENC_INFO,
        strlen(HK_PAIR_VERIFY_ENC_INFO), ctx->session_key, 32);

    if (result != 0) {
        LOG_ERROR("failed to derive session key (%d)", result);
        _pair_setup_set_error_response(HK_TLV_PAIR_VERIFY_STATE_START_RESPONSE,
            HK_PAIR_ERR_UNKNOWN, response, resp_len);
        _pair_setup_set_http_code(500, http_code);
        free(sub_tlv_bytes);
        return;
    }

    unsigned char *encrypted_subtlv = malloc(sub_tlv_bytes_len + CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE);
    if (!encrypted_subtlv) {
        _pair_setup_set_error_response(HK_TLV_PAIR_VERIFY_STATE_START_RESPONSE,
            HK_PAIR_ERR_UNKNOWN, response, resp_len);
        _pair_setup_set_http_code(500, http_code);
        free(sub_tlv_bytes);
        return;
    }

    result = wc_ChaCha20Poly1305_Encrypt(ctx->session_key, (unsigned char *)HK_PAIR_VERIFY_START_RESP_NONCE,
        NULL, 0, sub_tlv_bytes, sub_tlv_bytes_len, encrypted_subtlv, encrypted_subtlv + sub_tlv_bytes_len);

    if (result != 0) {
        LOG_ERROR("failed to encrypt verify start response sub-TLV (%d)", result);
        _pair_setup_set_error_response(HK_TLV_PAIR_VERIFY_STATE_START_RESPONSE,
            HK_PAIR_ERR_UNKNOWN, response, resp_len);
        _pair_setup_set_http_code(500, http_code);
        free(sub_tlv_bytes);
        free(encrypted_subtlv);
    }

    free(sub_tlv_bytes);

    container = tlv8_container_new();
    tlv8_container_add_uint8(container, HK_PAIR_TLV_STATE, HK_TLV_PAIR_VERIFY_STATE_START_RESPONSE);
    tlv8_container_add_binary(container, HK_PAIR_TLV_PUBLIC_KEY, accessory_curve_pubkey, accessory_curve_pubkey_len);
    tlv8_container_add_binary(container, HK_PAIR_TLV_ENCRYPTED_DATA,
        encrypted_subtlv, sub_tlv_bytes_len + CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE);

    void *tlv_bytes = NULL;
    size_t tlv_bytes_len = 0;
    if (tlv8_container_encode(container, &tlv_bytes, &tlv_bytes_len) != TLV8_ERR_OK) {
        LOG_ERROR("failed to encode verify start response");
        _pair_setup_set_error_response(HK_TLV_PAIR_VERIFY_STATE_START_RESPONSE,
            HK_PAIR_ERR_UNKNOWN, response, resp_len);
        _pair_setup_set_http_code(500, http_code);
        free(encrypted_subtlv);
        return;
    }

    tlv8_container_free(container);

    // marking the session as verified so we know that future communications are encrypted
    ctx->verified = 1;

    *response = tlv_bytes;
    *resp_len = tlv_bytes_len;
    _pair_setup_set_http_code(200, http_code);
    free(encrypted_subtlv);
}

static void _pair_verify_finish_request(hk_session_context_t *ctx, struct tlv8 **tlvs,
    size_t tlv_count, void **response, size_t *resp_len, int *encrypt_future, int *http_code)
{
    void *encrypted_data = NULL;
    size_t encrypted_data_len = 0;
    if (tlv8_lookup_binary_all(tlvs, tlv_count, HK_PAIR_TLV_ENCRYPTED_DATA,
        &encrypted_data, &encrypted_data_len) != TLV8_ERR_OK) {
        LOG_ERROR("pair verify finish request did not contain encrypted data");
        _pair_setup_set_error_response(HK_TLV_PAIR_VERIFY_STATE_FINISH_RESPONSE,
            HK_PAIR_ERR_UNKNOWN, response, resp_len);
        _pair_setup_set_http_code(400, http_code);
        return;
    }

    unsigned char *authtag = encrypted_data + (encrypted_data_len - CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE);

    size_t decrypted_len = encrypted_data_len - CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE;
    unsigned char *decrypted = malloc(decrypted_len);
    int result = wc_ChaCha20Poly1305_Decrypt(ctx->session_key, (unsigned char *)HK_PAIR_VERIFY_FINISH_REQ_NONCE,
        NULL, 0, encrypted_data, encrypted_data_len - CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE, authtag, decrypted);

    if (result != 0) {
        LOG_ERROR("failed to decrypt verify start request encrypted data");
        _pair_setup_set_error_response(HK_TLV_PAIR_VERIFY_STATE_FINISH_RESPONSE,
            HK_PAIR_ERR_AUTHENTICATION, response, resp_len);
        _pair_setup_set_http_code(200, http_code);
        free(encrypted_data);
        free(decrypted);
        return;
    }

    free(encrypted_data);

    LOG_DEBUG_HEX(decrypted, decrypted_len, "decrypted pair verify finish request sub TLV");

    struct tlv8 **sub_tlvs = NULL;
    size_t subtlvs_len = 0;
    if (tlv8_decode(decrypted, decrypted_len, &sub_tlvs, &subtlvs_len) != TLV8_ERR_OK) {
        LOG_ERROR("failed to decode sub TLV");
        _pair_setup_set_error_response(HK_TLV_PAIR_VERIFY_STATE_FINISH_RESPONSE,
            HK_PAIR_ERR_UNKNOWN, response, resp_len);
        _pair_setup_set_http_code(200, http_code);
        free(decrypted);
        return;
    }

    void *sub_pairing_id = NULL;
    size_t sub_pairing_id_len = 0;
    if (tlv8_lookup_binary_all(sub_tlvs, subtlvs_len, HK_PAIR_TLV_IDENTIFIER,
        &sub_pairing_id, &sub_pairing_id_len) != TLV8_ERR_OK) {
        LOG_ERROR("sub TLV did not contain pairing identifier");
        _pair_setup_set_error_response(HK_TLV_PAIR_VERIFY_STATE_FINISH_RESPONSE,
            HK_PAIR_ERR_UNKNOWN, response, resp_len);
        _pair_setup_set_http_code(200, http_code);
        free(decrypted);
        tlv8_free_all(sub_tlvs, subtlvs_len);
        return;
    }

    memcpy(ctx->controller_id, sub_pairing_id, sub_pairing_id_len);
    free(sub_pairing_id);

    hk_controller_pair_t *pair = _get_pairing(ctx->ctx, ctx->controller_id);
    if (!pair) {
        LOG_ERROR("iOS device not found in pairings database");
        _pair_setup_set_error_response(HK_TLV_PAIR_VERIFY_STATE_FINISH_RESPONSE,
            HK_PAIR_ERR_AUTHENTICATION, response, resp_len);
        _pair_setup_set_http_code(200, http_code);
        free(decrypted);
        return;
    }

    ctx->pair = pair;

    void *sub_sig = NULL;
    size_t sub_sig_len = 0;
    if (tlv8_lookup_binary_all(sub_tlvs, subtlvs_len, HK_PAIR_TLV_SIGNATURE,
        &sub_sig, &sub_sig_len) != TLV8_ERR_OK) {
        LOG_ERROR("sub TLV did not contain signature");
        free(decrypted);
        tlv8_free_all(sub_tlvs, subtlvs_len);
    }

    size_t ios_info_len = CURVE25519_KEYSIZE + strlen(ctx->controller_id) + CURVE25519_KEYSIZE;
    unsigned char *ios_info = malloc(ios_info_len);
    memcpy(ios_info, ctx->controller_pubkey, CURVE25519_KEYSIZE);
    memcpy(ios_info + CURVE25519_KEYSIZE, ctx->controller_id, sub_pairing_id_len);
    memcpy(ios_info + CURVE25519_KEYSIZE + sub_pairing_id_len, ctx->accessory_pubkey, CURVE25519_KEYSIZE);

    int verified = 0;
    ed25519_key ios_pubkey;
    result = wc_ed25519_init(&ios_pubkey);
    if (result != 0) {
        LOG_ERROR("failed to initialize ed25519 key for signature verification (%d)", result);
        _pair_setup_set_error_response(HK_TLV_PAIR_VERIFY_STATE_FINISH_RESPONSE,
            HK_PAIR_ERR_UNKNOWN, response, resp_len);
        _pair_setup_set_http_code(200, http_code);
        free(sub_sig);
        tlv8_free_all(sub_tlvs, subtlvs_len);
        free(decrypted);
        return;
    }

    LOG_DEBUG_HEX(pair->pubkey, ED25519_PUB_KEY_SIZE, "will compare signatures using controller public key");
    LOG_DEBUG_HEX(sub_sig, sub_sig_len, "signature is");

    result = wc_ed25519_import_public(pair->pubkey, ED25519_PUB_KEY_SIZE, &ios_pubkey);
    if (result != 0) {
        LOG_ERROR("failed to import iOS LTPK for signature verification (%d)", result);
        _pair_setup_set_error_response(HK_TLV_PAIR_VERIFY_STATE_FINISH_RESPONSE,
            HK_PAIR_ERR_UNKNOWN, response, resp_len);
        _pair_setup_set_http_code(200, http_code);
        wc_ed25519_free(&ios_pubkey);
        free(sub_sig);
        tlv8_free_all(sub_tlvs, subtlvs_len);
        free(decrypted);
        return;
    }

    result = wc_ed25519_verify_msg(sub_sig, sub_sig_len, ios_info, ios_info_len, &verified, &ios_pubkey);
    if (result < 0) {
        LOG_ERROR("error attempting signature verification (%d)", result);
        _pair_setup_set_error_response(HK_TLV_PAIR_VERIFY_STATE_FINISH_RESPONSE,
            HK_PAIR_ERR_UNKNOWN, response, resp_len);
        _pair_setup_set_http_code(200, http_code);
        wc_ed25519_free(&ios_pubkey);
        free(sub_sig);
        tlv8_free_all(sub_tlvs, subtlvs_len);
        free(decrypted);
        return;
    }

    wc_ed25519_free(&ios_pubkey);
    free(sub_sig);
    tlv8_free_all(sub_tlvs, subtlvs_len);
    free(decrypted);

    if (!verified) {
        LOG_ERROR("signature verification failed");
        _pair_setup_set_error_response(HK_TLV_PAIR_VERIFY_STATE_FINISH_RESPONSE,
            HK_PAIR_ERR_AUTHENTICATION, response, resp_len);
        _pair_setup_set_http_code(200, http_code);
        return;
    }

    if (!_generate_session_encryption_keys(ctx)) {
        LOG_ERROR("failed to generate session encryption keys");
        _pair_setup_set_error_response(HK_TLV_PAIR_VERIFY_STATE_FINISH_RESPONSE,
            HK_PAIR_ERR_AUTHENTICATION, response, resp_len);
        _pair_setup_set_http_code(200, http_code);
        return;
    }

    struct tlv8_container *container = tlv8_container_new();
    tlv8_container_add_uint8(container, HK_PAIR_TLV_STATE, HK_TLV_PAIR_VERIFY_STATE_FINISH_RESPONSE);

    void *tlv_bytes = NULL;
    size_t tlv_bytes_len = 0;
    if (tlv8_container_encode(container, &tlv_bytes, &tlv_bytes_len) != TLV8_ERR_OK) {
        _pair_setup_set_error_response(HK_TLV_PAIR_VERIFY_STATE_FINISH_RESPONSE,
            HK_PAIR_ERR_UNKNOWN, response, resp_len);
        _pair_setup_set_http_code(200, http_code);
        tlv8_container_free(container);
        return;
    }

    tlv8_container_free(container);

    *response = tlv_bytes;
    *resp_len = tlv_bytes_len;
    _pair_setup_set_http_code(200, http_code);

    memcpy(pair->current_session_key, ctx->session_key, 32);
    *encrypt_future = 1;
}

void hk_handle_pair_verify_request(hk_session_context_t *ctx, void *request,
    size_t len, void **response, size_t *resp_len, int *encrypt_future, int *http_code)
{
    ASSERT(ctx == NULL);
    ASSERT(request == NULL);
    ASSERT(len == 0);
    ASSERT(response == NULL);
    ASSERT(resp_len == NULL);
    ASSERT(encrypt_future == NULL);

    struct tlv8 **tlvs = NULL;
    size_t decoded = 0;

    if (tlv8_decode(request, len, &tlvs, &decoded) != TLV8_ERR_OK) {
        LOG_ERROR("failed to decode pair verify request");
        _pair_setup_set_error_response(HK_TLV_PAIR_VERIFY_STATE_START_RESPONSE,
            HK_PAIR_ERR_UNKNOWN, response, resp_len);
        _pair_setup_set_http_code(400, http_code);
        return;
    }

    if (decoded == 0) {
        LOG_ERROR("pair verify request did not contain TLV data");
        tlv8_free_all(tlvs, decoded);
        _pair_setup_set_error_response(HK_TLV_PAIR_VERIFY_STATE_START_RESPONSE,
            HK_PAIR_ERR_UNKNOWN, response, resp_len);
        _pair_setup_set_http_code(400, http_code);
        return;
    }

    hk_tlv_pair_verify_state_t state = HK_TLV_PAIR_VERIFY_STATE_NONE;
    if (tlv8_lookup_uint8(tlvs, decoded, HK_PAIR_TLV_STATE, (uint8_t *)&state) != TLV8_ERR_OK) {
        LOG_ERROR("pair verify request missing state TLV");
        tlv8_free_all(tlvs, decoded);
        _pair_setup_set_error_response(HK_TLV_PAIR_VERIFY_STATE_START_RESPONSE,
            HK_PAIR_ERR_UNKNOWN, response, resp_len);
        _pair_setup_set_http_code(400, http_code);
        return;
    }

    LOG_DEBUG("pair verify request state is %s", hk_pair_verify_state_to_string(state));

    switch (state) {
        case HK_TLV_PAIR_VERIFY_STATE_START_REQUEST:
            _pair_verify_start_request(ctx, tlvs, decoded, response, resp_len, http_code);
            break;

        case HK_TLV_PAIR_VERIFY_STATE_FINISH_REQUEST:
            _pair_verify_finish_request(ctx, tlvs, decoded, response, resp_len, encrypt_future, http_code);
            break;

        default:
            LOG_ERROR("invalid or unrecognized pair verify state");
            break;
    }

    tlv8_free_all(tlvs, decoded);
}

int _wc_srp_set_key(Srp *srp, byte *secret, word32 size)
{
    SrpHash hash;
    int r = BAD_FUNC_ARG;

    srp->key = (byte *)malloc(SHA512_DIGEST_SIZE);
    if (!srp->key)
        return MEMORY_E;

    memset(srp->key, 0, SHA512_DIGEST_SIZE);

    srp->keySz = SHA512_DIGEST_SIZE;

    r = wc_InitSha512(&hash.data.sha512);
    if (!r) r = wc_Sha512Update(&hash.data.sha512, secret, size);
    if (!r) r = wc_Sha512Final(&hash.data.sha512, srp->key);

    return r;
}

static void _pair_setup_start_request(hk_accessory_t *ctx, struct tlv8 **tlvs,
    size_t tlv_count, void **response, size_t *resp_len, int *http_code)
{
    LOG_FUNCTION_ENTRY();

    // once the number of pair attempts is reached the user is required to reset the device.
    if (ctx->pair.attempts >= 100) {
        LOG_ERROR("cannot accept pair request, max pair attempts reached (%d)", 100);
        _pair_setup_set_error_response(HK_TLV_PAIR_STATE_START_RESPONSE,
            HK_PAIR_ERR_MAX_TRIES, response, resp_len);
        _pair_setup_set_http_code(200, http_code);
        return;
    }

    if (ctx->pair.pairing) {
        if (_pair_setup_has_timed_out(ctx)) {
            LOG_DEBUG("last pair attempt timed out, allowing pair setup request");
        } else {
            LOG_ERROR("already pairing, denying pair request");
            _pair_setup_set_error_response(HK_TLV_PAIR_STATE_START_RESPONSE,
                HK_PAIR_ERR_BUSY, response, resp_len);
            _pair_setup_set_http_code(429, http_code);
            return;
        }
    }

    LOG_DEBUG("pair setup start request accepted");
    gettimeofday(&ctx->pair.last_pair_attempt, NULL);

    if(wc_SrpInit(&ctx->pair.srp, SRP_TYPE_SHA512, SRP_CLIENT_SIDE) != 0) {
        LOG_ERROR("failed to initialize SRP");
        _pair_setup_set_error_response(HK_TLV_PAIR_STATE_START_RESPONSE,
            HK_PAIR_ERR_UNKNOWN, response, resp_len);
        _pair_setup_set_http_code(500, http_code);
        return;
    }

    ctx->pair.srp.keyGenFunc_cb = _wc_srp_set_key;

    ctx->pair.accessory_pubkey = malloc(384);
    ctx->pair.accessory_pubkey_len = 384;

    ctx->pair.accessory_privatekey = malloc(32);
    ctx->pair.accessory_privatekey_len = 32;

    ctx->pair.verification_key = malloc(384);
    ctx->pair.verification_key_len = 384;

    ctx->pair.salt = malloc(16);
    ctx->pair.salt_len = 16;


    gen_random(ctx->pair.accessory_privatekey, ctx->pair.accessory_privatekey_len);
    gen_random(ctx->pair.salt, ctx->pair.salt_len);

    LOG_DEBUG_HEX(ctx->pair.accessory_privatekey, ctx->pair.accessory_privatekey_len, "generated private key");
    LOG_DEBUG_HEX(ctx->pair.salt, ctx->pair.salt_len, "generated salt");

    wc_SrpSetUsername(&ctx->pair.srp, (byte *)"Pair-Setup", 10);
    wc_SrpSetParams(&ctx->pair.srp, HK_SRP_N, HK_SRP_N_LEN, HK_SRP_G, HK_SRP_G_LEN, ctx->pair.salt, ctx->pair.salt_len);
    wc_SrpSetPassword(&ctx->pair.srp, (byte *)ctx->setup_code, strlen(ctx->setup_code));
    wc_SrpGetVerifier(&ctx->pair.srp, ctx->pair.verification_key, &ctx->pair.verification_key_len);

    // wolfcrypt SRP assumes that verification keys are generated client side, so we started off
    // as client side and switch to server side once we have the verifier.
    ctx->pair.srp.side = SRP_SERVER_SIDE;
    wc_SrpSetVerifier(&ctx->pair.srp, ctx->pair.verification_key, ctx->pair.verification_key_len);
    wc_SrpSetPrivate(&ctx->pair.srp, ctx->pair.accessory_privatekey, ctx->pair.accessory_privatekey_len);
    wc_SrpGetPublic(&ctx->pair.srp, ctx->pair.accessory_pubkey, &ctx->pair.accessory_pubkey_len);

    LOG_DEBUG_HEX(ctx->pair.verification_key, ctx->pair.verification_key_len,
        "generated verification key (%d)", ctx->pair.verification_key_len);
    LOG_DEBUG_HEX(ctx->pair.accessory_pubkey, ctx->pair.accessory_pubkey_len,
        "generated device public key (%d)", ctx->pair.accessory_pubkey_len);

    size_t tlv_salt_encoded = 0, tlv_pubkey_encoded = 0;
    struct tlv8 **tlv_salt = tlv8_from_big_bin(HK_PAIR_TLV_SALT, ctx->pair.salt,
        ctx->pair.salt_len, &tlv_salt_encoded);

    struct tlv8 **tlv_pubkey = tlv8_from_big_bin(HK_PAIR_TLV_PUBLIC_KEY, ctx->pair.accessory_pubkey,
        ctx->pair.accessory_pubkey_len, &tlv_pubkey_encoded);

    struct tlv8 *tlv_state = tlv8_from_uint8(HK_PAIR_TLV_STATE, HK_TLV_PAIR_STATE_START_RESPONSE);

    struct tlv8_container *container = tlv8_container_new();
    tlv8_container_add(container, tlv_state);
    tlv8_container_add_all(container, tlv_pubkey, tlv_pubkey_encoded);
    tlv8_container_add_all(container, tlv_salt, tlv_salt_encoded);

    tlv8_container_encode(container, response, resp_len);

    tlv8_container_free(container);

    _pair_setup_set_http_code(200, http_code);
}

static void _pair_setup_verify_request(hk_accessory_t *ctx, struct tlv8 **tlvs,
    size_t tlv_count, void **response, size_t *resp_len, int *http_code)
{
    LOG_FUNCTION_ENTRY();

    void *ios_pubkey = NULL;
    size_t ios_pubkey_len = 0;
    if (tlv8_lookup_binary_all(tlvs, tlv_count, HK_PAIR_TLV_PUBLIC_KEY, &ios_pubkey, &ios_pubkey_len) != TLV8_ERR_OK) {
        LOG_ERROR("request TLV did not contain public key");
        _pair_setup_set_error_response(HK_TLV_PAIR_STATE_VERIFY_RESPONSE,
            HK_PAIR_ERR_UNKNOWN, response, resp_len);
        _pair_setup_set_http_code(400, http_code);
        return;
    }

    LOG_DEBUG_HEX(ios_pubkey, ios_pubkey_len, "received iOS public key (%d)", ios_pubkey_len);

    ctx->pair.ios_pubkey = ios_pubkey;
    ctx->pair.ios_pubkey_len = ios_pubkey_len;

    void *ios_proof = NULL;
    size_t ios_proof_len = 0;
    if (tlv8_lookup_binary(tlvs, tlv_count, HK_PAIR_TLV_PROOF, &ios_proof, &ios_proof_len) != TLV8_ERR_OK) {
        LOG_ERROR("request TLV did not contain SRP proof");
        _pair_setup_set_error_response(HK_TLV_PAIR_STATE_VERIFY_RESPONSE,
            HK_PAIR_ERR_UNKNOWN, response, resp_len);
        _pair_setup_set_http_code(400, http_code);
        free(ios_pubkey);
        return;
    }

    LOG_DEBUG_HEX(ios_proof, ios_proof_len, "received iOS proof");

    int result = wc_SrpComputeKey(&ctx->pair.srp, ios_pubkey, ios_pubkey_len, ctx->pair.accessory_pubkey,
        ctx->pair.accessory_pubkey_len);
    if (result != 0) {
            LOG_ERROR("failed to compute SRP key (%d)", result);
    }

    result = wc_SrpVerifyPeersProof(&ctx->pair.srp, ios_proof, ios_proof_len);
    LOG_DEBUG("verification check result=%d", result);
    if(result != 0) {
        LOG_ERROR("SRP authentication failed, returning invalid setup code (%d)", result);
        _pair_setup_set_error_response(HK_TLV_PAIR_STATE_VERIFY_RESPONSE,
            HK_PAIR_ERR_AUTHENTICATION, response, resp_len);
        _pair_setup_set_http_code(200, http_code);
        return;
    }

    LOG_INFO("iOS proof verification successful");

    // generate symmetric session key SessionKey
    result = wc_HKDF(SHA512, ctx->pair.srp.key, ctx->pair.srp.keySz, (unsigned char *)HK_PAIR_SETUP_ENC_SALT,
        strlen(HK_PAIR_SETUP_ENC_SALT), (unsigned char *)HOMKEIT_PAIR_SETUP_ENC_INFO,
        strlen(HOMKEIT_PAIR_SETUP_ENC_INFO), ctx->pair.session_key, CHACHA20_POLY1305_AEAD_KEYSIZE);

    if (result != 0) {
        LOG_ERROR("failed to generate symmetric session key (%d)", result);
        _pair_setup_set_error_response(HK_TLV_PAIR_STATE_EXCHANGE_RESPONSE,
            HK_PAIR_ERR_UNKNOWN, response, resp_len);
        _pair_setup_set_http_code(500, http_code);
        return;
    }

    unsigned char device_proof[64];
    size_t device_proof_len = 64;
    wc_SrpGetProof(&ctx->pair.srp, device_proof, &device_proof_len);

    struct tlv8_container *container = tlv8_container_new();
    tlv8_container_add_uint8(container, HK_PAIR_TLV_STATE, HK_TLV_PAIR_STATE_VERIFY_RESPONSE);
    tlv8_container_add_binary(container, HK_PAIR_TLV_PROOF, device_proof, device_proof_len);

    tlv8_container_encode(container, response, resp_len);
    tlv8_container_free(container);

    _pair_setup_set_http_code(200, http_code);

    free(ios_proof);
}

// M5 Verification
static uint8_t _verify_exchange_request(hk_accessory_t *ctx, unsigned char *pair_id,
    size_t pair_id_len, unsigned char *pubkey, size_t pubkey_len, unsigned char *signature, size_t signature_len)
{
    LOG_FUNCTION_ENTRY();

    unsigned char ios_device_x[CHACHA20_POLY1305_AEAD_KEYSIZE];

    int result = wc_HKDF(SHA512, ctx->pair.srp.key, ctx->pair.srp.keySz,
        (unsigned char *)HK_PAIR_SETUP_CTRL_SALT, strlen(HK_PAIR_SETUP_CTRL_SALT),
        (unsigned char *)HK_PAIR_SETUP_CTRL_INFO, strlen(HK_PAIR_SETUP_CTRL_INFO),
        ios_device_x, CHACHA20_POLY1305_AEAD_KEYSIZE);
    if (result != 0) {
        LOG_DEBUG("failed to generate HKDF key err=%d", result);
        return 0;
    }

    LOG_DEBUG_HEX(ios_device_x, CHACHA20_POLY1305_AEAD_KEYSIZE, "derrived iOSDeviceX HDFK key");

    size_t device_info_len = CHACHA20_POLY1305_AEAD_KEYSIZE + pair_id_len + pubkey_len;
    unsigned char *ios_device_info = malloc(device_info_len);

    memcpy(ios_device_info, ios_device_x, CHACHA20_POLY1305_AEAD_KEYSIZE);
    memcpy(ios_device_info + CHACHA20_POLY1305_AEAD_KEYSIZE, pair_id, pair_id_len);
    memcpy(ios_device_info + CHACHA20_POLY1305_AEAD_KEYSIZE + pair_id_len, pubkey, pubkey_len);

    ed25519_key ios_ed_key;
    wc_ed25519_init(&ios_ed_key);

    result = wc_ed25519_import_public(pubkey, pubkey_len, &ios_ed_key);
    if (result != 0) {
        LOG_DEBUG("failed to import iOS public key err=%d", result);
        free(ios_device_info);
        return 0;
    }

    int verification_status = 0;
    result = wc_ed25519_verify_msg(signature, signature_len, ios_device_info,
        device_info_len, &verification_status, &ios_ed_key);
    if (result < 0) {
        LOG_DEBUG("error verifying signature err=%d", result);
        free(ios_device_info);
        return 0;
    } else if (verification_status == 0) {
        LOG_DEBUG("signature failed verificaction");
        free(ios_device_info);
        return 0;
    }

    free(ios_device_info);
    return 1;
}

// M5 request and response generation
static void _pair_setup_exchange_request(hk_accessory_t *ctx, struct tlv8 **tlvs,
    size_t tlv_count, void **response, size_t *resp_len, int *http_code)
{
    LOG_FUNCTION_ENTRY();


    void *encrypted_data = NULL;
    size_t encrypted_data_len = 0;
    if (tlv8_lookup_binary_all(tlvs, tlv_count, HK_PAIR_TLV_ENCRYPTED_DATA, &encrypted_data,
        &encrypted_data_len) != TLV8_ERR_OK) {
        LOG_ERROR("exchange request did not contain encrypted data");
        _pair_setup_set_error_response(HK_TLV_PAIR_STATE_EXCHANGE_RESPONSE,
            HK_PAIR_ERR_UNKNOWN, response, resp_len);
        _pair_setup_set_http_code(400, http_code);
        return;
    }

    unsigned char *auth_tag = encrypted_data + encrypted_data_len - CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE;
    unsigned char *decrypted_data = malloc(encrypted_data_len);
    size_t decrypted_len = encrypted_data_len - CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE;

    int result = wc_ChaCha20Poly1305_Decrypt(ctx->pair.session_key, (unsigned char *)HK_PAIR_SETUP_EXCHANGE_NONCE, NULL, 0,
        encrypted_data, encrypted_data_len - CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE, auth_tag, decrypted_data);
    if (result != 0) {
        LOG_ERROR("failed to decrypt exchange request encrypted data (%d)", result);
        _pair_setup_set_error_response(HK_TLV_PAIR_STATE_EXCHANGE_RESPONSE,
            HK_PAIR_ERR_AUTHENTICATION, response, resp_len);
        _pair_setup_set_http_code(200, http_code);
        free(encrypted_data);
        free(decrypted_data);
        return;
    }

    free(encrypted_data);

    LOG_DEBUG_HEX(decrypted_data, decrypted_len, "decrypted iOS encrypted data");

    struct tlv8 **sub_tlvs = NULL;
    size_t sub_tlvs_decoded = 0;
    if (tlv8_decode(decrypted_data, decrypted_len, &sub_tlvs, &sub_tlvs_decoded) != TLV8_ERR_OK) {
        LOG_ERROR("could not decode decrypted TLV data");
        _pair_setup_set_error_response(HK_TLV_PAIR_STATE_EXCHANGE_RESPONSE,
            HK_PAIR_ERR_UNKNOWN, response, resp_len);
        _pair_setup_set_http_code(400, http_code);
        free(decrypted_data);
        return;
    }

    free(decrypted_data);

    void *ios_pairing_id = NULL, *ios_pubkey = NULL, *ios_signature = NULL;
    size_t ios_pairing_id_len = 0, ios_pubkey_len = 0, ios_signature_len = 0;

    if (tlv8_lookup_binary(sub_tlvs, sub_tlvs_decoded, HK_PAIR_TLV_IDENTIFIER,
        &ios_pairing_id, &ios_pairing_id_len) != TLV8_ERR_OK || ios_pairing_id_len >= HK_MAX_PAIRING_ID_LEN) {
            LOG_ERROR("request did not contain iOS pairing identifier or pairing ID length exceeded");
        _pair_setup_set_error_response(HK_TLV_PAIR_STATE_EXCHANGE_RESPONSE,
            HK_PAIR_ERR_UNKNOWN, response, resp_len);
        _pair_setup_set_http_code(400, http_code);
        tlv8_free_all(sub_tlvs, sub_tlvs_decoded);
        return;
    }

    if (tlv8_lookup_binary(sub_tlvs, sub_tlvs_decoded, HK_PAIR_TLV_PUBLIC_KEY,
        &ios_pubkey, &ios_pubkey_len) != TLV8_ERR_OK) {
            LOG_ERROR("request did not contain iOS public key");
        _pair_setup_set_error_response(HK_TLV_PAIR_STATE_EXCHANGE_RESPONSE,
            HK_PAIR_ERR_UNKNOWN, response, resp_len);
        _pair_setup_set_http_code(400, http_code);
        free(ios_pairing_id);
        tlv8_free_all(sub_tlvs, sub_tlvs_decoded);
        return;
    }

    if (tlv8_lookup_binary(sub_tlvs, sub_tlvs_decoded, HK_PAIR_TLV_SIGNATURE,
        &ios_signature, &ios_signature_len) != TLV8_ERR_OK) {
            LOG_ERROR("request did not contain signature");
        _pair_setup_set_error_response(HK_TLV_PAIR_STATE_EXCHANGE_RESPONSE,
            HK_PAIR_ERR_UNKNOWN, response, resp_len);
        _pair_setup_set_http_code(400, http_code);
        free(ios_pairing_id);
        free(ios_pubkey);
        tlv8_free_all(sub_tlvs, sub_tlvs_decoded);
        return;
    }

    tlv8_free_all(sub_tlvs, sub_tlvs_decoded);

    LOG_DEBUG_HEX(ios_pairing_id, ios_pairing_id_len, "decoded iOS pairing identifier");
    LOG_DEBUG_HEX(ios_pubkey, ios_pubkey_len, "decoded iOS pairing public key");
    LOG_DEBUG_HEX(ios_signature, ios_signature_len, "decoded iOS signatuure");

    if(!_verify_exchange_request(ctx, ios_pairing_id, ios_pairing_id_len, ios_pubkey, ios_pubkey_len,
        ios_signature, ios_signature_len)) {
        LOG_ERROR("failed to verify exchange request");
        _pair_setup_set_error_response(HK_TLV_PAIR_STATE_EXCHANGE_RESPONSE,
            HK_PAIR_ERR_AUTHENTICATION, response, resp_len);
        _pair_setup_set_http_code(200, http_code);
        free(ios_pairing_id);
        free(ios_pubkey);
        free(ios_signature);
        return;
    }

    LOG_INFO("exchange request verified");

    char ios_pairing_id_str[HK_MAX_PAIRING_ID_LEN];
    memset(ios_pairing_id_str, 0, HK_MAX_PAIRING_ID_LEN);
    memcpy(ios_pairing_id_str, ios_pairing_id, ios_pairing_id_len);
    free(ios_pairing_id);

    // controllers that are paired via pair setup are automatically admins
    if (_add_pairing(ctx, ios_pairing_id_str, ios_pubkey,
        HK_PERMISSION_READ | HK_PERMISSION_WRITE | HK_PERMISSION_NOTIFY, 1) != HK_ERR_OK) {
            LOG_ERROR("failed to add new pairing");
        _pair_setup_set_error_response(HK_TLV_PAIR_STATE_EXCHANGE_RESPONSE,
            HK_PAIR_ERR_UNKNOWN, response, resp_len);
        _pair_setup_set_http_code(500, http_code);
        free(ios_pairing_id);
        free(ios_pubkey);
        free(ios_signature);
    }

    LOG_DEBUG("added pairing with pairing ID %s", ios_pairing_id_str);

    free(ios_pubkey);
    free(ios_signature);

    if (!_generate_long_term_keys(ctx)) {
        LOG_ERROR("failed to generate long term public and private keys");
        _pair_setup_set_error_response(HK_TLV_PAIR_STATE_EXCHANGE_RESPONSE,
            HK_PAIR_ERR_UNKNOWN, response, resp_len);
        _pair_setup_set_http_code(500, http_code);
        return;
    }

    unsigned char accessory_x[32];

    result = wc_HKDF(SHA512, ctx->pair.srp.key, ctx->pair.srp.keySz,
        (unsigned char *)HK_PAIR_SETUP_ACC_SALT, strlen(HK_PAIR_SETUP_ACC_SALT),
        (unsigned char *)HK_PAIR_SETUP_ACC_INFO, strlen(HK_PAIR_SETUP_ACC_INFO),
        accessory_x, 32);

    if (result != 0) {
        LOG_ERROR("failed to generate accessory x (%d)", result);
        _pair_setup_set_error_response(HK_TLV_PAIR_STATE_EXCHANGE_RESPONSE,
            HK_PAIR_ERR_UNKNOWN, response, resp_len);
        _pair_setup_set_http_code(500, http_code);
        return;
    }

    LOG_DEBUG_HEX(accessory_x, 32, "generated accessory X");

    size_t accessory_info_len = CHACHA20_POLY1305_AEAD_KEYSIZE + strlen(ctx->device_id) + ED25519_PUB_KEY_SIZE;
    unsigned char *accessory_info = malloc(accessory_info_len);

    memcpy(accessory_info, accessory_x, CHACHA20_POLY1305_AEAD_KEYSIZE);
    memcpy(accessory_info + CHACHA20_POLY1305_AEAD_KEYSIZE, ctx->device_id, strlen(ctx->device_id));
    memcpy(accessory_info + CHACHA20_POLY1305_AEAD_KEYSIZE + strlen(ctx->device_id), ctx->pair.accessory_ltpk, ED25519_PUB_KEY_SIZE);

    unsigned char accessory_signature[64];
    size_t accessory_signature_len = 64;
    ed25519_key sig_key;

    result = wc_ed25519_init(&sig_key);
    if (result != 0) {
        LOG_ERROR("failed to initialize ed25519 key for accessory info signing (%d)", result);
        _pair_setup_set_error_response(HK_TLV_PAIR_STATE_EXCHANGE_RESPONSE,
            HK_PAIR_ERR_UNKNOWN, response, resp_len);
        _pair_setup_set_http_code(500, http_code);
        free(accessory_info);
        return;
    }

    result = wc_ed25519_import_private_key(ctx->pair.accessory_ltsk, ED25519_PRV_KEY_SIZE,
        ctx->pair.accessory_ltpk, ED25519_PUB_KEY_SIZE, &sig_key);

    if (result != 0) {
        LOG_ERROR("failed to import key for accessory info signing (%d)", result);
        _pair_setup_set_error_response(HK_TLV_PAIR_STATE_EXCHANGE_RESPONSE,
            HK_PAIR_ERR_UNKNOWN, response, resp_len);
        _pair_setup_set_http_code(500, http_code);
        free(accessory_info);
        return;
    }

    result = wc_ed25519_sign_msg(accessory_info, accessory_info_len,
        accessory_signature, &accessory_signature_len, &sig_key);

    if (result != 0) {
        LOG_ERROR("failed to sign accessory signature (%d)", result);
        _pair_setup_set_error_response(HK_TLV_PAIR_STATE_EXCHANGE_RESPONSE,
            HK_PAIR_ERR_UNKNOWN, response, resp_len);
        _pair_setup_set_http_code(500, http_code);
        free(accessory_info);
        return;
    }

    free(accessory_info);

    LOG_DEBUG_HEX(accessory_signature, accessory_signature_len, "generated accessory info signature");

    struct tlv8_container *container = tlv8_container_new();
    tlv8_container_add_binary(container, HK_PAIR_TLV_IDENTIFIER, ctx->device_id, strlen(ctx->device_id));
    tlv8_container_add_binary(container, HK_PAIR_TLV_PUBLIC_KEY, ctx->pair.accessory_ltpk, ED25519_PUB_KEY_SIZE);
    tlv8_container_add_binary(container, HK_PAIR_TLV_SIGNATURE, accessory_signature, accessory_signature_len);

    void *sub_tlv_data = NULL;
    size_t sub_tlv_data_len = 0;
    if (tlv8_container_encode(container, &sub_tlv_data, &sub_tlv_data_len) != TLV8_ERR_OK) {
        _pair_setup_set_error_response(HK_TLV_PAIR_STATE_EXCHANGE_RESPONSE,
            HK_PAIR_ERR_UNKNOWN, response, resp_len);
        _pair_setup_set_http_code(500, http_code);
        tlv8_container_free(container);
        return;
    }

    LOG_DEBUG_HEX(sub_tlv_data, sub_tlv_data_len, "raw sub TLV data encoded (%d)", sub_tlv_data_len);

    tlv8_container_free(container);

    unsigned char *encrypted = malloc(sub_tlv_data_len + CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE);
    size_t encrypted_len = sub_tlv_data_len;
    result = wc_ChaCha20Poly1305_Encrypt(ctx->pair.session_key, (unsigned char *)HK_PAIR_SETUP_EXCHANGE_RESP_NONCE,
        NULL, 0, sub_tlv_data, sub_tlv_data_len, encrypted, encrypted + encrypted_len);
    free(sub_tlv_data);

    if (result != 0) {
        LOG_ERROR("failed to encrypt sub-tlv encrypted data (%d)", result);
        _pair_setup_set_error_response(HK_TLV_PAIR_STATE_EXCHANGE_RESPONSE,
            HK_PAIR_ERR_UNKNOWN, response, resp_len);
        _pair_setup_set_http_code(500, http_code);
    }

    LOG_DEBUG_HEX(encrypted, encrypted_len + CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE, "encrypted sub TLV with authtag (%d)",
        encrypted_len + CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE);

    container = tlv8_container_new();
    tlv8_container_add_uint8(container, HK_PAIR_TLV_STATE, HK_TLV_PAIR_STATE_EXCHANGE_RESPONSE);
    tlv8_container_add_binary(container, HK_PAIR_TLV_ENCRYPTED_DATA, encrypted, encrypted_len + CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE);

    void *tlv_resp = NULL;
    size_t tlv_resp_len = 0;
    if(tlv8_container_encode(container, &tlv_resp, &tlv_resp_len) != TLV8_ERR_OK) {
        LOG_ERROR("failed to serialized encrypted data TLV");
        _pair_setup_set_error_response(HK_TLV_PAIR_STATE_EXCHANGE_RESPONSE,
            HK_PAIR_ERR_UNKNOWN, response, resp_len);
        _pair_setup_set_http_code(500, http_code);
    } else {
        *response = tlv_resp;
        *resp_len = tlv_resp_len;
        _pair_setup_set_http_code(200, http_code);
    }

    tlv8_container_free(container);
    ctx->pair.pairing = 0;
}

void hk_handle_pair_setup_request(hk_accessory_t *ctx, void *request,
    size_t len, void **response, size_t *resp_len, int *http_code)
{
    ASSERT(ctx == NULL);
    ASSERT(request == NULL);
    ASSERT(len == 0);
    ASSERT(response == NULL);
    ASSERT(resp_len == NULL);

    if (ctx->pair.paired) {
        LOG_DEBUG("already paired, denying pair pair setup request");
        _pair_setup_set_error_response(HK_TLV_PAIR_STATE_START_RESPONSE,
            HK_PAIR_ERR_UNAVAILABLE, response, resp_len);
        _pair_setup_set_http_code(200, http_code);
        return;
    }

    struct tlv8 **tlvs = NULL;
    size_t decoded = 0;
    if (tlv8_decode(request, len, &tlvs, &decoded) != TLV8_ERR_OK) {
        LOG_ERROR("failed to decode request TLV8");
        _pair_setup_set_error_response(HK_TLV_PAIR_STATE_START_RESPONSE,
            HK_PAIR_ERR_UNKNOWN, response, resp_len);
        _pair_setup_set_http_code(400, http_code);
        return;
    }

    if (decoded == 0) {
        tlv8_free_all(tlvs, decoded);
        LOG_ERROR("request contained no TLV data");
        _pair_setup_set_error_response(HK_TLV_PAIR_STATE_START_RESPONSE,
            HK_PAIR_ERR_UNKNOWN, response, resp_len);
        _pair_setup_set_http_code(400, http_code);
        return;
    }

    hk_tlv_pair_state_t pair_state = HK_TLV_PAIR_STATE_NONE;
    if (tlv8_lookup_uint8(tlvs, decoded, HK_PAIR_TLV_STATE, (uint8_t *)&pair_state) != TLV8_ERR_OK) {
        LOG_ERROR("request did not contain pair state value");
        _pair_setup_set_error_response(HK_TLV_PAIR_STATE_START_RESPONSE,
            HK_PAIR_ERR_UNKNOWN, response, resp_len);
        _pair_setup_set_http_code(400, http_code);
        tlv8_free_all(tlvs, decoded);
        return;
    }

    LOG_DEBUG("request pair state is %s", hk_pair_state_to_string(pair_state));

    switch (pair_state) {
    case HK_TLV_PAIR_STATE_START_REQUEST:
        _pair_setup_start_request(ctx, tlvs, decoded, response, resp_len, http_code);
        break;

    case HK_TLV_PAIR_STATE_VERIFY_REQUEST:
        _pair_setup_verify_request(ctx, tlvs, decoded, response, resp_len, http_code);
        break;

    case HK_TLV_PAIR_STATE_EXCHANGE_REQUEST:
        _pair_setup_exchange_request(ctx, tlvs, decoded, response, resp_len, http_code);
        break;

    case HK_TLV_PAIR_STATE_NONE:
    default:
        LOG_ERROR("invalid or unrecognized pair state %d", pair_state);
        break;
    }

    tlv8_free_all(tlvs, decoded);
}



