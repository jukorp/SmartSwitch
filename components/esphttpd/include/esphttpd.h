#pragma once

#include <homekit/types.h>
#include <lwip/tcp.h>
#include "../parser.h"

//
// configurable definitions
//

// default port for esphttpd.
#define HTTPD_DEFAULT_PORT 80

// maximum HTTP request size.
// This can be changed depending the available memory.

// store esphttpd networking callbacks in RAM
#define HTTPD_LWIP_METHODS_RAM 1

// maximum request size for incoming requests (kB)
#define HTTPD_MAX_REQ_SIZE 2 * 1024

// recieve buffer for an httpd connection
#define HTTPD_RECV_BUFF_SIZE HTTPD_MAX_REQ_SIZE * 2

// poll interval in 500ms chunks
#define HTTPD_POLL_INTERVAL 2

// logging of receive buffers (hex)
#define HTTPD_LOG_RECV_BUFFERS 1

//
// non-configurable
//

#define HTTPD_MIN_REQUEST_LEN       7

// essentially number of seconds we allow an idle connection. copied from apache
#define HTTPD_MAX_RETRIES 30

#if HTTPD_LWIP_METHODS_RAM > 0
#define HTTPD_IRAM_ATTR IRAM_ATTR
#else
#define HTTPD_IRAM_ATTR
#endif

// send_buffer_encrypt_func is a callback function that can be set for an HTTP connection that can be
// used to encrypt an outbound request. arg is the user-supplied argument set in the http_connection_state.
// buff is a pointer to the buffer containing the response data, which may be reallocated if the the data
// must grow in size during encryption. len is a pointer to a size_t that indicates the length of buff
// in bytes. It should be set to the length of the new contents after encryption.
// Return 1 for success and 0 for failure.
typedef uint8_t (*send_buffer_encrypt_func)(void *arg, void **buff, size_t *len);

// recv_buffer_decrypt_func is a callback function that can be set for an HTTP connection that can be
// used to decrypt received data. arg is the user-supplied argument set in the http_connection_state.
// buff is the buffer containing the received data from the client, which should be replaced with the
// decrypted data. len is a pointer to a size_t that is the length of buff in bytes. Once the data has
// been replaced with the decrypted data, *len should be replaced with the new size.
// Return 1 for success and 0 for failure.
typedef uint8_t (*recv_buffer_decrypt_func)(void *arg, void *buff, size_t *len);

// http_connection_state keeps track of the context for a connection to esphttpd.
// when data is received, it is written to &recv_buff[recv_buff_len].
// poll_retries keeps track of how many times we have polled the connection without
// receiving any data.
struct http_connection_state {
    struct hkhttpd *server;
    struct tcp_pcb *pcb;
    char recv_buff[HTTPD_RECV_BUFF_SIZE];
    size_t recv_buff_len;
    uint8_t poll_retries;
    void *arg;
    send_buffer_encrypt_func encrypt_func;
    recv_buffer_decrypt_func decrypt_func;
};

typedef enum {
    HTTPD_REQUEST_HANDLER_SUCCESS,     /* returns the http_response set in the request handler callback */
    HTTPD_REQUEST_HANDLER_BAD_REQUEST, /* returns 400 Bad Request */
    HTTPD_REQUEST_HANDLER_ERR          /* returns 500 Internal Server Error */
} httpd_handler_err_t;

// request_handler_func is a callback function that is invoked by esphttpd when a request matching
// a given handler URI is received. The received request is passed as the first argument, and a pointer
// to a pointer for an http_response is provided as the second. The implementor should dereference it
// and set it to a pointer to a new http_response. esphttpd will call http_free_response on it after
// the response has been sent to the client. If the return value of the handler was not
// HTTPD_REQUEST_HANDLER_SUCCESS esphttpd assumes that the response was not set and will not free it.
typedef httpd_handler_err_t (*request_handler_func)(struct http_connection_state *ctx, struct http_request *);

// connection_cleanup_func is a callback function that is invoked by esphttpd when a connection
// has been closed. Can be used to do any necessary cleanup, such as freeing memory pointed to
// by http_connection_state.arg.
typedef void (*connection_cleanup_func)(struct http_connection_state *ctx);

// http_request_handler is a structure that identifies a request handler. uri is the URI used to
// match the request with a given handler. Matching is done as a prefix comparison.
// requsest_handler should point to a callback function used to handle the request.
// If full_match is positive then the requested resource will be fully compared to the handler uri.
// If full_match is not 1, the comparision is essentially a prefix comparison.
struct httpd_request_handler {
    uint8_t full_match;
    char uri[255];
    request_handler_func request_handler;
    uint8_t allow_encryption;
};

struct hkhttpd {
    hk_accessory_t *accessory;
    uint16_t port;
    struct tcp_pcb *pcb;
    struct httpd_request_handler **request_handlers;
    size_t request_handler_count;
    connection_cleanup_func cleanup_func;
};

// httpd_init initializes esphttpd. port should be set to the port in which esphttpd
// should listen on, or HTTPD_DEFAULT_PORT.
err_t httpd_init(struct hkhttpd *server, hk_accessory_t *accessory, uint16_t port);

// httpd_set_connection_cleanup_handler sets the callback function that should be invoked when
// an HTTP connection is closed. See connection_cleanup_func for more information.
void httpd_set_connection_cleanup_handler(struct hkhttpd *server, connection_cleanup_func func);

// httpd_add_request_handler adds an HTTP request handler to be used for request processing.
void httpd_add_request_handler(struct hkhttpd *server, struct httpd_request_handler *handler);

// httpd_send sends response for a request from connection state. Should be called in the request
// handler routine.
err_t httpd_send(struct http_connection_state *state, struct http_response *response);

// httpd_send_simple creates an HTTP response using code as the HTTP status code and status
// as the HTTP status.
// close indicates whether or not the connection should be closed after sending.
err_t httpd_send_simple(struct http_connection_state *state, int code, char *status, uint8_t close);

