#include <homekit/types.h>
#include <homekit/pair.h>
#include <homekit/session.h>

#include "homekit/handlers.h"

static const char *TAG = "esp-homekit-handlers";

uint8_t hk_decrypt_request_data(void *arg, void *buff, size_t *len)
{
    hk_session_context_t *ctx = (hk_session_context_t *)arg;
    return hk_session_decrypt_request(ctx, buff, len);
}

uint8_t hk_encrypt_response_data(void *arg, void **buff, size_t *len)
{
    hk_session_context_t *ctx = (hk_session_context_t *)arg;
    return hk_session_encrypt_response(ctx, buff, len);
}

httpd_handler_err_t hk_accessories_req_handler(struct http_connection_state *ctx, struct http_request *request)
{
    hk_session_context_t *session_ctx = (hk_session_context_t *)ctx->arg;

    void *hk_response = NULL;
    size_t hk_resp_len = 0;
    int http_code = 0;
    hk_handle_attribute_db_request(session_ctx, &hk_response, &hk_resp_len, &http_code);

    struct http_response *r = http_new_response(http_code, http_status_for_code(http_code));
    if (!r) {
        free(hk_response);
        return HTTPD_REQUEST_HANDLER_ERR;
    }

    http_add_header(&r->headers, &r->header_count, HTTP_HEADER_KEY_CONTENT_TYPE, HK_CONTENT_TYPE_JSON);
    r->body = hk_response;
    r->body_len = hk_resp_len;

    err_t tcp_err = httpd_send(ctx, r);
    if (tcp_err != ERR_OK) {
        LOG_ERROR("tcp send error %d for accessories request response for session %p, cleaning up session", tcp_err, session_ctx);
        hk_free_session_context(session_ctx);
    }

    http_free_response(r);

    return HTTPD_REQUEST_HANDLER_SUCCESS;
}

httpd_handler_err_t hk_characteristics_req_handler(struct http_connection_state *ctx, struct http_request *request)
{
    hk_session_context_t *session_ctx = ctx->arg;

    void *hk_response = NULL;
    size_t hk_response_len = 0;
    int http_code = 0;

    if (!strcmp(request->method, "PUT")) {
        hk_handle_characteristics_write_request(session_ctx, request->body, request->body_len,
                                                &hk_response, &hk_response_len, &http_code);

        struct http_response *r = http_new_response(http_code, http_status_for_code(http_code));
        if (!r) {
            free(hk_response);
            return HTTPD_REQUEST_HANDLER_ERR;
        }

        if (hk_response) {
            LOG_DEBUG_HEX(hk_response, hk_response_len, "characteristics write request homekit response http_code=%d", http_code);
            r->body = hk_response;
            r->body_len = hk_response_len;
        }

        err_t tcp_err = httpd_send(ctx, r);
        if (tcp_err != ERR_OK) {
            LOG_ERROR("tcp send error %d for characteristics read request response for session %p, cleaning up session", tcp_err, session_ctx);
            hk_free_session_context(session_ctx);
        }

        http_free_response(r);
        return HTTPD_REQUEST_HANDLER_SUCCESS;
    } else if(!strcmp(request->method, "GET")) {
        hk_handle_characteristics_read_request(session_ctx, request->query_params,
                                               request->query_param_count, &hk_response,
                                               &hk_response_len, &http_code);

        struct http_response *r = http_new_response(http_code, http_status_for_code(http_code));
        if (!r) {
            free(hk_response);
            return HTTPD_REQUEST_HANDLER_ERR;
        }

        if (hk_response) {
            LOG_DEBUG_HEX(hk_response, hk_response_len, "characteristics read request homekit response http_code=%d", http_code);
            http_add_header(&r->headers, &r->header_count, HTTP_HEADER_KEY_CONTENT_TYPE, HK_CONTENT_TYPE_JSON);
            r->body = hk_response;
            r->body_len = hk_response_len;
        }

        err_t tcp_err = httpd_send(ctx, r);
        if (tcp_err != ERR_OK) {
            LOG_ERROR("tcp send error %d for characteristics write request response for session %p, cleaning up session", tcp_err, session_ctx);
            hk_free_session_context(session_ctx);
        }

        http_free_response(r);
        return HTTPD_REQUEST_HANDLER_SUCCESS;
    } else {
        return HTTPD_REQUEST_HANDLER_BAD_REQUEST;
    }

    return HTTPD_REQUEST_HANDLER_ERR;
}

httpd_handler_err_t hk_identify_req_handler(struct http_connection_state *ctx, struct http_request *request)
{
    return HTTPD_REQUEST_HANDLER_SUCCESS;
}

httpd_handler_err_t hk_pair_setup_req_handler(struct http_connection_state *ctx, struct http_request *request)
{
    void *hk_response = NULL;
    size_t hk_response_len = 0;
    int status_code = 0;
    hk_handle_pair_setup_request(ctx->server->accessory, request->body, request->body_len, &hk_response,
        &hk_response_len, &status_code);

    LOG_DEBUG_HEX(hk_response, hk_response_len, "homekit pair setup response http_code=%d body=", status_code);

    struct http_response *r = http_new_response(status_code, http_status_for_code(status_code));
    if (!r)
        return HTTPD_REQUEST_HANDLER_ERR;

    http_add_header(&r->headers, &r->header_count, HTTP_HEADER_KEY_CONTENT_TYPE, HK_CONTENT_TYPE_PAIR_TLV);
    r->body = hk_response;
    r->body_len = hk_response_len;

    httpd_send(ctx, r);
    http_free_response(r);

    return HTTPD_REQUEST_HANDLER_SUCCESS;
}

httpd_handler_err_t hk_pair_verify_req_handler(struct http_connection_state *ctx, struct http_request *request)
{
    hk_session_context_t *pair_ctx = ctx->arg;
    if (!pair_ctx) {
        pair_ctx = hk_new_session_context(ctx->server->accessory, ctx);
        if (!pair_ctx)
            return HTTPD_REQUEST_HANDLER_ERR;

        ctx->arg = (void *)pair_ctx;
    }

    void *hk_response = NULL;
    size_t hk_response_len = 0;
    int status_code = 0;
    int encrypt_future = 0;

    hk_handle_pair_verify_request(pair_ctx, request->body, request->body_len,
        &hk_response, &hk_response_len, &encrypt_future, &status_code);

    LOG_DEBUG_HEX(hk_response, hk_response_len, "homekit pair verify response http_code=%d body=", status_code);

    struct http_response *r = http_new_response(status_code, http_status_for_code(status_code));
    if (!r)
        return HTTPD_REQUEST_HANDLER_ERR;

    http_add_header(&r->headers, &r->header_count, HTTP_HEADER_KEY_CONTENT_TYPE, HK_CONTENT_TYPE_PAIR_TLV);
    r->body = hk_response;
    r->body_len = hk_response_len;

    err_t tcp_err = httpd_send(ctx, r);
    if (tcp_err != ERR_OK) {
        LOG_ERROR("tcp send error %d for pair verify request response for session %p, cleaning up session", tcp_err, pair_ctx);
        hk_free_session_context(pair_ctx);
    }

    http_free_response(r);

    if (encrypt_future) {
        LOG_DEBUG("future request data for session %p should be decrypted", pair_ctx);
        ctx->encrypt_func = hk_encrypt_response_data;
        ctx->decrypt_func = hk_decrypt_request_data;
    }

    return HTTPD_REQUEST_HANDLER_SUCCESS;
}

httpd_handler_err_t hk_pairings_req_handler(struct http_connection_state *ctx, struct http_request *request)
{
    hk_session_context_t *session_ctx = (hk_session_context_t *)ctx->arg;

    void *hk_response = NULL;
    size_t hk_response_len = 0;
    int http_code = 0;

    hk_handle_pairings_request(session_ctx, request->body, request->body_len, &hk_response,
                               &hk_response_len, &http_code);

    LOG_DEBUG_HEX(hk_response, hk_response_len, "pairings request response from homekit status_code=%d", http_code);

    struct http_response *r = http_new_response(http_code, http_status_for_code(http_code));
    if (!r) {
        free(hk_response);
        return HTTPD_REQUEST_HANDLER_ERR;
    }

    http_add_header(&r->headers, &r->header_count, HTTP_HEADER_KEY_CONTENT_TYPE, HK_CONTENT_TYPE_PAIR_TLV);
    r->body = hk_response;
    r->body_len = hk_response_len;

    err_t tcp_err = httpd_send(ctx, r);
    if (tcp_err != ERR_OK) {
        LOG_ERROR("tcp send error %d for pairings request response for session %p, cleaning up session", tcp_err, session_ctx);
        hk_free_session_context(session_ctx);
    }

    http_free_response(r);

    return HTTPD_REQUEST_HANDLER_SUCCESS;
}

void hk_http_connection_cleanup_handler(struct http_connection_state *ctx)
{
    LOG_DEBUG("HTTP connection cleanup callback invoked for state %p", ctx);

    if (ctx->arg)
        hk_free_session_context(ctx->arg);
}