#pragma once

#include <sys/time.h>
#include "homekit.h"

#define HK_PAIR_SETUP_USERNAME   "Pair-Setup"
#define HK_CONTENT_TYPE_PAIR_TLV "application/pairing+tlv8"

#define HK_PAIR_TIMEOUT_SEC    30

#define HK_PAIR_SETUP_ENC_SALT  "Pair-Setup-Encrypt-Salt"
#define HOMKEIT_PAIR_SETUP_ENC_INFO  "Pair-Setup-Encrypt-Info"

#define HK_PAIR_SETUP_CTRL_SALT "Pair-Setup-Controller-Sign-Salt"
#define HK_PAIR_SETUP_CTRL_INFO "Pair-Setup-Controller-Sign-Info"

#define HK_PAIR_SETUP_ACC_SALT  "Pair-Setup-Accessory-Sign-Salt"
#define HK_PAIR_SETUP_ACC_INFO  "Pair-Setup-Accessory-Sign-Info"

#define HK_PAIR_VERIFY_ENC_SALT "Pair-Verify-Encrypt-Salt"
#define HK_PAIR_VERIFY_ENC_INFO "Pair-Verify-Encrypt-Info"

#define HK_PAIR_SETUP_EXCHANGE_NONCE      "\0\0\0\0PS-Msg05"
#define HK_PAIR_SETUP_EXCHANGE_RESP_NONCE "\0\0\0\0PS-Msg06"

#define HK_PAIR_VERIFY_START_RESP_NONCE   "\0\0\0\0PV-Msg02"
#define HK_PAIR_VERIFY_FINISH_REQ_NONCE   "\0\0\0\0PV-Msg03"

#define HK_SESSION_CTRL_SALT       "Control-Salt"
#define HK_SESSION_ENCRYPT_CTRL_READ_INFO  "Control-Read-Encryption-Key"
#define HK_SESSION_DECRYPT_CTRL_WRITE_INFO "Control-Write-Encryption-Key"

#define HK_SESSION_REQUEST_LEN_SIZE    2

typedef enum {
    HK_TLV_PAIR_STATE_NONE,
    HK_TLV_PAIR_STATE_START_REQUEST,
    HK_TLV_PAIR_STATE_START_RESPONSE,
    HK_TLV_PAIR_STATE_VERIFY_REQUEST,
    HK_TLV_PAIR_STATE_VERIFY_RESPONSE,
    HK_TLV_PAIR_STATE_EXCHANGE_REQUEST,
    HK_TLV_PAIR_STATE_EXCHANGE_RESPONSE
} hk_tlv_pair_state_t;

typedef enum {
    HK_TLV_PAIR_VERIFY_STATE_NONE,
    HK_TLV_PAIR_VERIFY_STATE_START_REQUEST,
    HK_TLV_PAIR_VERIFY_STATE_START_RESPONSE,
    HK_TLV_PAIR_VERIFY_STATE_FINISH_REQUEST,
    HK_TLV_PAIR_VERIFY_STATE_FINISH_RESPONSE
} hk_tlv_pair_verify_state_t;

typedef enum {
    HK_PAIR_METHOD_RESERVED,
    HK_PAIR_METHOD_SETUP,
    HK_PAIR_METHOD_VERIFY,
    HK_PAIR_METHOD_ADD_PAIRING,
    HK_PAIR_METHOD_REMOVE_PAIRING,
    HK_PAIR_METHOD_LIST_PAIRINGS,
    HK_PAIR_METHOD_RESERVED_ABOVE
    /* anything greater than or equal to RESERVED_ABOVE is also reserved */
} hk_pair_method_t;

typedef enum {
    HK_PAIR_ERR_RESERVED,
    HK_PAIR_ERR_UNKNOWN,
    HK_PAIR_ERR_AUTHENTICATION,
    HK_PAIR_ERR_BACKOFF,
    HK_PAIR_ERR_MAX_PEERS,
    HK_PAIR_ERR_MAX_TRIES,
    HK_PAIR_ERR_UNAVAILABLE,
    HK_PAIR_ERR_BUSY,
    HK_PAIR_ERR_RESERVED_ABOVE
    /* anything greater than or equal to RESERVED_ABOVE is also reserved */
} hk_pair_err_t;

typedef enum {
    HK_PAIR_TLV_METHOD,
    HK_PAIR_TLV_IDENTIFIER,
    HK_PAIR_TLV_SALT,
    HK_PAIR_TLV_PUBLIC_KEY,
    HK_PAIR_TLV_PROOF,
    HK_PAIR_TLV_ENCRYPTED_DATA,
    HK_PAIR_TLV_STATE,
    HK_PAIR_TLV_ERROR,
    HK_PAIR_TLV_RETRY_DELAY,
    HK_PAIR_TLV_CERT,
    HK_PAIR_TLV_SIGNATURE,
    HK_PAIR_TLV_PERMISSIONS,
    HK_PAIR_TLV_FRAGMENT_DATA,
    HK_PAIR_TLV_FRAGMENT_LAST,
    HK_PAIR_TLV_SEPARATOR
} hk_pair_tlv_value_t;

// hk_session_encrypt_response should be used to encrypt a response to an encrypted request from
// a controller. After a pair is verified, the verified member of the hk_session_context_t structure
// is set to 1. If it is set to one, hk_sesssion_decrypt_request and hk_session_encrypt_response
// should be used to encrypt and decrypt HTTP requests and responses respectively.
// ctx should be the hk_session_context_t for the session.
// response should be a pointer to a pointer that contains the response to encrypt. The original pointer
// will be changed, because the size will need to be increased.
// len should be a pointer to a size_t that indicates the size of response in bytes. After encryption
// is completed len will be set to the new size.
uint8_t hk_session_encrypt_response(hk_session_context_t *ctx, void **response, size_t *len);

// hk_session_decrypt_request should be used to decrypt a request from a controller.
// After a pair is verified, the verified member of the hk_session_context_t structure
// is set to 1. If it is set to one, hk_sesssion_decrypt_request and hk_session_encrypt_response
// should be used to encrypt and decrypt HTTP requests and responses respectively.
// ctx should be the hk_session_context_t for the session.
// request should be the encrypted request data received.
// len should be a pointer to a size_t that indicates the size of request in bytes. After decryption
// is completed len will be set to the new (smaller) size of the decrypted data in bytes.
uint8_t hk_session_decrypt_request(hk_session_context_t *ctx, void *request, size_t *len);

// hk_handle_pair_setup_request should be used to forward Pair Setup requests on to
// esp-homekit. For IP accessories, this would be requests to /pair-setup.
//
// request should contain the raw TLV8 encoded request data.
// len should be the size in bytes of request.
// response should be a pointer to a pointer, which will be set to the raw data that should
// be passed to the iOS accessory in response to the request. The caller is responsible for
// freeing response.
// resp_len should be a pointer to an int, which will be set to the size of the response data in bytes.
// http_code can optionally point to an integer, which will be set to the HTTP response code that
// should be used. For IP accessories only.
void hk_handle_pair_setup_request(hk_accessory_t *ctx, void *request,
    size_t len, void **response, size_t *resp_len, int *http_code);

// hk_handle_pair_verify_request should be used to forward Pair Verify requests on to
// esp-homekit. For IP accessories, this would be requests to /pair-verify.
//
// request should contain the raw TLV8 encoded request data.
// len should be the size in bytes of request.
// response should be a pointer to a pointer, which will be set to the raw data that should
// be passed to the iOS accessory in response to the request. The caller is responsible for
// freeing response.
// resp_len should be a pointer to an int, which will be set to the size of the response data in bytes.
// encrypt_future should be a pointer to an int which will be set to 1 if future HTTP requests will
// be entirely encrypted (headers and all). Encrypted requests should use hk_decrypt_request_data function
// to decrypt payloads.
// http_code can optionally point to an integer, which will be set to the HTTP response code that
// should be used. For IP accessories only.
void hk_handle_pair_verify_request(hk_session_context_t *ctx, void *request,
    size_t len, void **response, size_t *resp_len, int *encrypt_future, int *http_code);

// hk_handle_pairings_request should be used to forward pairings requests on to esp-homekit.
// For IP accessories, this would be requests to /pairings. This function will respond by either:
//   1. returning a list of pairings for the accessory
//   2. adding a requested pairing
//   3. removing a requested pairing
//
// ctx should be the hk_session_context_t for the session in which the request was made
// request should be the body of the request from the controller
// len should be the size of request in bytes
// response should be a pointer to a pointer, which will be set to the response. The caller is
//          responsible for freeing this
// resp_len should be a pointer to a size_t, which will be set to the size of response in bytes
// http_code is an optional pointer to an int, which will be set to the HTTP status code
//           for the response
void hk_handle_pairings_request(hk_session_context_t *ctx, void *request, size_t len,
                                void **response, size_t *resp_len, int *http_code);

