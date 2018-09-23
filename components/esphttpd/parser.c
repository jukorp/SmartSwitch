#include <freertos/FreeRTOS.h>
#include <utils.h>

#include "parser.h"

static const char *TAG = "http-parser";

char *http_response_to_bytes(struct http_response *response, size_t *sz)
{
    ASSERT(response == NULL);
    ASSERT(sz == 0);
    ASSERT(response->code > 999);

    size_t estimated_size = response->body_len;
    estimated_size += 13 + strlen(response->status); /* HTTP version, code, status text */
    estimated_size += 18 + 32;                       /* Content-Length line with buffer for size digits */
    estimated_size += 8;                             /* double CRLF header delimiter */

    if (response->headers) {
        for(int index = 0; index < response->header_count; index++) {
            estimated_size += strlen(response->headers[index][0]) + 2;
            estimated_size += strlen(response->headers[index][1]) + 2;
        }
    }

    char *buff = (char *)malloc(estimated_size);
    if (!buff) {
        return NULL;
    }

    memset(buff, 0, estimated_size);

    char *http_ver = response->http_version;
    if (!http_ver)
        http_ver = "HTTP/1.1";

    sprintf(buff, "%s %d %s\r\n", http_ver, response->code, response->status);
    sprintf(buff + strlen(buff), "Content-Length: %d\r\n", response->body_len);

    if (response->headers && response->header_count) {
        for (int index = 0; index < response->header_count; index++) {
            sprintf(buff + strlen(buff), "%s: %s\r\n", response->headers[index][0], response->headers[index][1]);
        }
    }

    sprintf(buff + strlen(buff), "\r\n");
    size_t header_len = strlen(buff);

    if (response->body_len) {
        memcpy(buff + strlen(buff), response->body, response->body_len);
    }

    *sz = (header_len + response->body_len);
    return buff;
}

struct http_response *http_new_response(int code, char *status)
{
    struct http_response *resp = (struct http_response *)malloc(sizeof(struct http_response));
    if (resp) {
        memset(resp, 0, sizeof(struct http_response));
        resp->status = (char *)strdup(status);
        resp->code = code;
    }

    return resp;
}

struct http_request *http_new_request(void)
{
    struct http_request *req = (struct http_request *)malloc(sizeof(struct http_request));
    if (req) {
        memset(req, 0, sizeof(struct http_request));
    }

    return req;
}

void http_free_request(struct http_request *req)
{
    if (req) {
        LOG_DEBUG("will free request %p", req);
        http_free_headers(req->headers, req->header_count);
        http_free_headers(req->query_params, req->query_param_count);
        if (req->method)  free(req->method);
        if (req->uri)     free(req->uri);
        if (req->version) free(req->version);
        if (req->body)    free(req->body);

        free(req);

        LOG_DEBUG("did free request %p", req);
    }
}

void http_free_response(struct http_response *resp)
{
    if (resp) {
        http_free_headers(resp->headers, resp->header_count);
        if (resp->http_version) free(resp->http_version);
        if (resp->status)       free(resp->status);
        if (resp->body)         free(resp->body);

        free(resp);
    }
}

void http_debug_print_requests(struct http_request **requests, size_t len)
{
    LOG_FUNCTION_ENTRY();
    LOG_DEBUG("printing %d HTTP requests:", len);

    for (size_t i = 0; i < len; i++) {
        LOG_DEBUG("---- request %d ----", i);
        LOG_DEBUG("Method: %s", requests[i]->method);
        LOG_DEBUG("Version: %s", requests[i]->version);
        LOG_DEBUG("URI: %s", requests[i]->uri);

        LOG_DEBUG("Query Parameters (%d):", requests[i]->query_param_count);
        for (size_t param_i = 0; param_i < requests[i]->query_param_count; param_i++) {
            char **param = requests[i]->query_params[param_i];
            LOG_DEBUG("%d: %s = %s", param_i, param[0],
                                     param[1] ? param[1] : "(null)");
        }

        LOG_DEBUG("Headers (%d):", requests[i]->header_count);

        for (size_t header_i = 0; header_i < requests[i]->header_count; header_i++) {
            LOG_DEBUG("%d: %s = %s", header_i, requests[i]->headers[header_i][0], requests[i]->headers[header_i][1]);
        }

        char *body_hex = bin2hex(requests[i]->body, requests[i]->body_len);
        if (body_hex) {
            LOG_DEBUG("Body: %s", body_hex);
            free(body_hex);
        }
    }
}

void http_add_header(char ****headers, int *count, char *key, char *value)
{
    ASSERT(headers == NULL);
    ASSERT(key == NULL);

    *count = *count + 1;
    *headers = (char ***)realloc(*headers, sizeof(char **) * *count);
    (*headers)[*count - 1] = (char **)malloc(sizeof(char *) * 2);
    (*headers)[*count - 1][0] = (char *)strdup(key);
    (*headers)[*count - 1][1] = (char *)strdup(value);
}

char *http_get_header(char ***headers, int count, char *key)
{
    ASSERT(headers == NULL);
    ASSERT(key == NULL);

    char *value = NULL;
    for (int n = 0; n < count; n++) {
        if (!strcmp(key, headers[n][0])) {
            value = headers[n][1];
            break;
        }
    }

    return value;
}

void  http_free_headers(char ***headers, int len)
{
    LOG_FUNCTION_ENTRY();

    if (headers) {
        LOG_DEBUG("will free headers at %p", headers);
        for (int index = 0; index < len; index++) {
            if (headers[index]) {
                if (headers[index][0]) free(headers[index][0]);
                if (headers[index][1]) free(headers[index][1]);

                free(headers[index]);
            }
        }

        free(headers);
        LOG_DEBUG("did free headers at %p", headers);
    }
}

void http_free_requests(struct http_request **requests, size_t len)
{
    if (requests) {
        for(size_t i = 0; i < len; i++) {
            if (requests[i])
                http_free_request(requests[i]);
        }

        free(requests);
    }
}

/* http_parse_requests takes a blob and parses any number of contained HTTP requests.
 * Returns 0 if the entirety of data was used. Returns -1 on error, which indicates that the
 * entirety of data should be discarded. Returns >= 0 indicating the offset of the first byte
 * of unused data (presumably, the start of an incomplete request). In such a case,
 * 0 indicates that zero data was remaining, and the entirety of data was parsed as valid
 * request(s).
 *
 * Note: we assume that unused data is an incomplete request, unlike the lwip httpd
 *       because we are supporting persistent connections.
 */
IRAM_ATTR int8_t http_parse_requests(char *data, size_t len, struct http_request ***requests, size_t *count)
{
    LOG_FUNCTION_ENTRY();

    ASSERT(data == NULL);
    ASSERT(requests == NULL);

    /* we expect that data may contain one or more complete or incomplete requests,
     * so we continue parsing until we have decided that:
     *   1) we have parsed all requests in full, or
     *   2) we have parsed all requests with some unprocessed remainder
     */
    *count = 0;
    size_t current_req_offset = 0;
    size_t parsed_requests = 0;
    char *current_req_start;

    for (;;) {
        current_req_start = data + current_req_offset;

        if (current_req_offset >= len) {
            // TODO: this might need attention.
            current_req_offset = 0;
            break;
        }

        char *header_break = strstr(current_req_start, /*len,*/ "\r\n\r\n");
        if (!header_break) {
            LOG_DEBUG("no header CRLF found, returning %d", current_req_offset);
            return current_req_offset;
        }

        LOG_DEBUG("header end CRLF found at %p", header_break);

        *header_break = 0;
        char *body_start = header_break + 4;

        struct tokens *line_tokens = tokenize(current_req_start, "\r\n", 0);
        if (!line_tokens || line_tokens->count < 2) {
            free_tokens(line_tokens);
            return -1;
        }

        struct http_request *req = http_new_request();
        ASSERT(req == NULL);

        for (int line_offset = 0; line_offset < line_tokens->count; line_offset++) {
            char *line = line_tokens->tokens[line_offset];

            /* should be METHOD RESOURCE HTTP_VERSION */
            if (line_offset == 0) {
                struct tokens *words = tokenize(line, " ", 3);
                if (!words || words->count != 3) {
                    free_tokens(line_tokens);
                    free_tokens(words);
                    return -1;
                }

                char *uri_token = words->tokens[1];
                char *query_start = strstr(uri_token, "?");
                if (query_start) {
                    req->uri = strndup(words->tokens[1], query_start - words->tokens[1]);

                    struct tokens *param_tokens = tokenize(query_start + 1, "&", 0);
                    if (param_tokens) {
                        for (int i = 0; i < param_tokens->count; i++) {
                            char *token = param_tokens->tokens[i];

                            if (!strlen(token))
                                continue;

                            char ***params = realloc(req->query_params,
                                                        sizeof(char **) * ++req->query_param_count);
                            if(!params)
                                continue;

                            char **new_param = malloc(sizeof(char *) * 2);

                            char *equals = strstr(token, "=");
                            if (equals) {
                                new_param[0] = strndup(token, equals - token);
                                new_param[1] = strndup(equals + 1, strlen(equals + 1));
                            } else {
                                new_param[0] = strdup(token);
                                new_param[1] = NULL;
                            }

                            params[req->query_param_count - 1] = new_param;
                            req->query_params = params;
                        }

                        free_tokens(param_tokens);
                    }
                } else {
                    req->uri = strdup(words->tokens[1]);
                }

                req->method = strdup(words->tokens[0]);
                req->version = strdup(words->tokens[2]);

                // TODO: parse and store GET parameters. req->uri should then contain the resource
                // indicator with any query string removed.

                // TODO: once we store query params and rewq->uri contains just resource indicator,
                // change the logic when doing URL route matching, because right now it removes
                // the query, which won't be necessary

                free_tokens(words);
            }
            else /* it's a header */ {
                struct tokens *header_key_value = tokenize(line, ":", 2);
                if (!header_key_value || header_key_value->count < 2) {
                    free_tokens(header_key_value);
                    free_tokens(line_tokens);
                    return -1;
                }

                char *key = header_key_value->tokens[0];
                char *value = header_key_value->tokens[1];
                http_add_header(&req->headers, &req->header_count, ltrim(rtrim(key)), ltrim(rtrim(value)));

                free_tokens(header_key_value);
            }
        }

        free_tokens(line_tokens);

        char *keep_alive = http_get_header(req->headers, req->header_count, HTTP_HEADER_KEY_CONNECTION);
        if (keep_alive && !strcmp(keep_alive, "keep-alive")) {
            req->keep_alive = 1;
        }

        size_t content_length = 0;
        char *content_length_str = http_get_header(req->headers, req->header_count, HTTP_HEADER_KEY_CONTENT_LENGTH);
        if (content_length_str) {
            content_length = atol(content_length_str);
        }

        if (content_length) {
            req->body_len = content_length;
            req->body = malloc(content_length);
            ASSERT(req->body == NULL);
            memcpy(req->body, body_start, content_length);
        }

        LOG_DEBUG("current_req_offset was %d", current_req_offset);
        current_req_offset = (body_start + content_length) - data;
        LOG_DEBUG("current_req_offset is now %d", current_req_offset);

        LOG_DEBUG("will realloc requests buffer current_size=%d new_size=%d",
            parsed_requests * sizeof(struct http_request), (parsed_requests + 1) * sizeof(struct http_request));
        *requests = realloc(*requests, ++parsed_requests * sizeof(struct http_request));
        (*requests)[parsed_requests - 1] = req;
        *count = parsed_requests;
    }

    LOG_DEBUG("finished with request offset %d", current_req_offset);
    return current_req_offset;
}

char *http_status_for_code(int code)
{
    switch (code) {
        case 200: return HTTP_STATUS_OK;
        case 204: return HTTP_STATUS_NO_CONTENT;
        case 207: return HTTP_STATUS_MULTI_STATUS;
        case 404: return HTTP_STATUS_NOT_FOUND;
        case 400: return HTTP_STATUS_BAD_REQUEST;
        case 413: return HTTP_STATUS_PAYLOAD_TOO_LARGE;
        case 500: return HTTP_STATUS_INTERNAL_ERR;
        default: return "";
    }
}
