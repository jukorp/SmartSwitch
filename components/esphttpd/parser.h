#pragma once

#include <stdio.h>
#include <freertos/FreeRTOS.h>
#include <utils.h>

struct http_request {
    char *method;
    char *uri;
    char *version;

    uint8_t keep_alive;

    char ***query_params;
    int query_param_count;

    char ***headers;
    int header_count;

    void *body;
    size_t body_len;
};

struct http_response {
    char *http_version;
    int code;
    char *status;

    char ***headers;
    int header_count;

    void *body;
    size_t body_len;
};

#define HTTP_HEADER_KEY_CONTENT_TYPE   "Content-Type"
#define HTTP_HEADER_KEY_CONTENT_LENGTH "Content-Length"
#define HTTP_HEADER_KEY_CONNECTION     "Connection"

#define HTTP_STATUS_CODE_OK                200
#define HTTP_STATUS_OK                     "OK"
#define HTTP_STATUS_CODE_NO_CONTENT        204
#define HTTP_STATUS_NO_CONTENT             "No Content"
#define HTTP_STATUS_CODE_MULTI_STATUS      207
#define HTTP_STATUS_MULTI_STATUS           "Multi-Status"
#define HTTP_STATUS_CODE_NOT_FOUND         404
#define HTTP_STATUS_NOT_FOUND              "Not Found"
#define HTTP_STATUS_CODE_BAD_REQUEST       400
#define HTTP_STATUS_BAD_REQUEST            "Bad Request"
#define HTTP_STATUS_CODE_UNAUTHORIZED      401
#define HTTP_STATUS_UNAUTHORIZED           "Unauthorized"
#define HTTP_STATUS_CODE_PAYLOAD_TOO_LARGE 413
#define HTTP_STATUS_PAYLOAD_TOO_LARGE      "Payload Too Large"
#define HTTP_STATUS_CODE_INTERNAL_ERR      500
#define HTTP_STATUS_INTERNAL_ERR           "Internal Server Error"

void  http_free_headers(char ***headers, int len);

char *http_response_to_bytes(struct http_response *response, size_t *sz);

struct http_response *http_new_response(int code, char *status);

struct http_request *http_new_request(void);

void http_free_request(struct http_request *req);

void http_free_response(struct http_response *resp);

void http_debug_print_requests(struct http_request **requests, size_t len);

void http_add_header(char ****headers, int *count, char *key, char *value);

char *http_get_header(char ***headers, int count, char *key);

/* http_parse_requests takes a blob and parses any number of contained HTTP requests.
 * Returns 0 if the entirety of data was used. Returns -1 on error, which indicates that the
 * entirety of data should be discarded. Returns >= 0 indicating the offset of the first byte
 * of unused data (presumably, the start of an incomplete request).
 *
 * Note: we assume that unused data is an incomplete request, unlike the lwip httpd
 *       because we are supporting persistent connections.
 */
int8_t http_parse_requests(char *data, size_t len, struct http_request ***requests, size_t *count);

void http_free_requests(struct http_request **requests, size_t len);

char *http_status_for_code(int code);
