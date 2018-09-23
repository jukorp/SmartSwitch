#pragma once

#include <esphttpd.h>
#include <homekit/types.h>

httpd_handler_err_t hk_accessories_req_handler(struct http_connection_state *ctx,
                                               struct http_request *request);

httpd_handler_err_t hk_characteristics_req_handler(struct http_connection_state *ctx,
                                                   struct http_request *request);

httpd_handler_err_t hk_identify_req_handler(struct http_connection_state *ctx,
                                            struct http_request *request);

httpd_handler_err_t hk_pair_setup_req_handler(struct http_connection_state *ctx,
                                              struct http_request *request);

httpd_handler_err_t hk_pair_verify_req_handler(struct http_connection_state *ctx,
                                               struct http_request *request);

httpd_handler_err_t hk_pairings_req_handler(struct http_connection_state *ctx,
                                            struct http_request *request);


uint8_t hk_decrypt_request_data(void *arg, void *buff, size_t *len);
uint8_t hk_encrypt_response_data(void *arg, void **buff, size_t *len);

void hk_http_connection_cleanup_handler(struct http_connection_state *ctx);

