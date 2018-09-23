#include <string.h>
#include <freertos/FreeRTOS.h>
#include <esp_system.h>
#include <tcpip_adapter.h>
#include <lwip/init.h>
#include <lwip/tcpip.h>
#include <esphttpd.h>
#include "utils.h"
#include "parser.h"

static const char *TAG = "esphttpd";

static struct http_connection_state *httpd_new_state(struct hkhttpd *server, struct tcp_pcb *pcb)
{
    LOG_FUNCTION_ENTRY();

    struct http_connection_state *state = malloc(sizeof(struct http_connection_state));
    if (!state)
        return NULL;

    memset(state, 0, sizeof(struct http_connection_state));
    state->pcb = pcb;
    state->server = server;

    LOG_DEBUG("allocated new http connection state %p for connection %p", state, state->pcb);
    return state;
}

void httpd_free_state(struct http_connection_state *state)
{
    if (state) {
        LOG_DEBUG("will free state %p", state);
        free(state);
        LOG_DEBUG("did free state %p", state);
    }
}

err_t HTTPD_IRAM_ATTR httpd_send(struct http_connection_state *state, struct http_response *response)
{
    ASSERT(state == NULL);
    ASSERT(response == NULL);

    size_t payload_len;
    char *payload = http_response_to_bytes(response, &payload_len);
    if (!payload) {
        LOG_ERROR("failed to allocate serialize HTTP response %p for connection state %p", response, state);
        return ERR_MEM;
    }

#if HTTPD_LOG_RECV_BUFFERS
    LOG_DEBUG_HEX(payload, payload_len, "will send HTTP response %p for connection state %p", response, state);
#endif

    if (state->encrypt_func) {
        LOG_DEBUG("calling state send buffer encryption function %p", state->encrypt_func);
        if (!state->encrypt_func(state->arg, (void *)&payload, &payload_len)) {
            LOG_DEBUG("state send buffer encryption call failed, will not send request");
            free(payload);
            return ERR_VAL;
        }

#if HTTPD_LOG_RECV_BUFFERS
        LOG_DEBUG_HEX(payload, payload_len, "will send encrypted HTTP response %p for connection state %p", response, state);
#endif
    }

    u16_t max_payload_size = tcp_sndbuf(state->pcb);
    if (max_payload_size < payload_len) {
        LOG_ERROR("max send size (%d) is lower than serialized HTTP response size (%d) for state %p",
            max_payload_size, payload_len, state);
        free(payload);
        return ERR_BUF;
    }

    LOG_DEBUG("HTTP response status_code=%d content_length=%d", response->code, payload_len);

    err_t result = tcp_write(state->pcb, payload, payload_len, TCP_WRITE_FLAG_COPY);
    if (result != ERR_OK) {
        LOG_ERROR("error writing HTTP response to state %p err=%d", state, result);
    }

    free(payload);
    tcp_output(state->pcb);

    return result;
}

err_t HTTPD_IRAM_ATTR httpd_send_simple(struct http_connection_state *state, int code, char *status, uint8_t close)
{
    struct http_response *response = http_new_response(code, status);

    if (close) {
        http_add_header(&response->headers, &response->header_count, "Connection", "close");
    }

    err_t result = httpd_send(state, response);
    http_free_response(response);

    return result;
}

struct httpd_request_handler * HTTPD_IRAM_ATTR http_matching_handler_for_request(struct hkhttpd *server, struct http_request *request)
{
    struct httpd_request_handler *match = NULL;

    if (request) {
        char *request_uri = strdup(request->uri);
        char *query_start = strstr(request_uri, "?");
        if (query_start) *query_start = 0;

        for (size_t i = 0; i < server->request_handler_count; i++) {
            if (server->request_handlers[i]->full_match) {
                if(strcmp(request_uri, server->request_handlers[i]->uri) == 0) {
                    LOG_DEBUG("request %p full match for handler %s", request, server->request_handlers[i]->uri);
                    match = server->request_handlers[i];
                    break;
                }
            } else {
                if (strncmp(request_uri, server->request_handlers[i]->uri, strlen(server->request_handlers[i]->uri)) == 0) {
                    LOG_DEBUG("request %p partial match for handler %s", request, server->request_handlers[i]->uri);
                    match = server->request_handlers[i];
                    break;
                }
            }
        }

        free(request_uri);
    }

    return match;
}

void HTTPD_IRAM_ATTR httpd_process_requests(struct http_connection_state *state, struct http_request **requests, size_t len)
{
    if (state->server->request_handler_count && state->server->request_handlers) {
        for (size_t i = 0; i < len; i++) {
            if (requests[i]) {
                struct httpd_request_handler *handler = http_matching_handler_for_request(state->server, requests[i]);
                if (handler) {
                    httpd_handler_err_t result = handler->request_handler(state, requests[i]);
                    if (result == HTTPD_REQUEST_HANDLER_SUCCESS) {
                        // do nothing
                    } else if(result == HTTPD_REQUEST_HANDLER_BAD_REQUEST) {
                        httpd_send_simple(state, HTTP_STATUS_CODE_BAD_REQUEST, HTTP_STATUS_BAD_REQUEST, 0);
                    } else {
                        httpd_send_simple(state, HTTP_STATUS_CODE_INTERNAL_ERR, HTTP_STATUS_INTERNAL_ERR, 0);
                    }
                } else {
                    httpd_send_simple(state, HTTP_STATUS_CODE_NOT_FOUND, HTTP_STATUS_NOT_FOUND, 0);
                }
            } else {
                LOG_ERROR("attempted to process a NULL request at index %d", i);
            }
        }
    } else {
        LOG_ERROR("no request handlers registered to handle requests");
        httpd_send_simple(state, 404, "Not Found", 1);
    }
}

static err_t HTTPD_IRAM_ATTR httpd_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
    LOG_FUNCTION_ENTRY();

    LOG_DEBUG("recieving %d bytes from connection %p", (p) ? p->tot_len : -1, pcb);

    struct http_connection_state *state = (struct http_connection_state *)arg;
    ASSERT(state == NULL);

    if (err != ERR_OK || p == NULL || state == NULL) {
        LOG_DEBUG("connection should be closed from recv pcb=%p err=%d p=%p state=%p", pcb, err, p, state);

        if (p != NULL) {
            tcp_recved(pcb, p->tot_len);
            pbuf_free(p);
        }

        tcp_close(pcb);

        // we receive a NULL pbuf any time the connection is closed, whether it was closed by the
        // remote host or we closed it. so we will handle all cleanup here
        if (state->server->cleanup_func) {
            state->server->cleanup_func(state);
        }

        httpd_free_state(state);
        return ERR_OK;
    }

    tcp_recved(pcb, p->tot_len);
    LOG_DEBUG("httpd_recv pcb=%p len=%d tot_len=%d", pcb, p->len, p->tot_len);

    if (p->len != p->tot_len) {
        LOG_ERROR("chained pbuf detected");
    }

    // recv_buff_data_len change if there is a decryption function for state
    size_t recv_buff_data_len = p->tot_len;
    void *recv_buff = memdup(p->payload, p->tot_len);
    pbuf_free(p);

    if (!recv_buff) {
        LOG_ERROR("failed to allocate duplicated receive buffer, will close connection state %p", state);
        tcp_close(pcb);
        return ERR_MEM;
    }

    size_t buff_remaining = HTTPD_RECV_BUFF_SIZE - state->recv_buff_len;
    if (buff_remaining < recv_buff_data_len) {
        LOG_ERROR("receive buffer overflow, closing connection %p", pcb);

        struct http_response *response = http_new_response(413, "Payload Too Large");
        if (response) {
            http_add_header(&response->headers, &response->header_count, "Connection", "close");
            httpd_send(state, response);
            http_free_response(response);
        }

        free(recv_buff);
        tcp_close(pcb);
        return ERR_MEM;
    }

#if HTTPD_LOG_RECV_BUFFERS
    LOG_DEBUG_HEX(recv_buff, recv_buff_data_len, "receive buffer connection_state=%p", state);
#endif

    if (state->decrypt_func) {
        LOG_DEBUG("calling state recieve buffer decryption function %p", state->decrypt_func);

        if (!state->decrypt_func(state->arg, recv_buff, &recv_buff_data_len)) {
            LOG_DEBUG("decryption function returned error, discarding");
            free(recv_buff);
            tcp_close(pcb);
            return ERR_OK;
        }

        LOG_DEBUG("recieve buffer data size after decryption is %d", recv_buff_data_len);

#if HTTPD_LOG_RECV_BUFFERS
        LOG_DEBUG_HEX(recv_buff, recv_buff_data_len, "decrypted receive buffer connection_state=%p", state);
#endif
    }


    LOG_DEBUG("receive buffer remaining before request is %d", buff_remaining);

    memcpy(state->recv_buff + state->recv_buff_len, recv_buff, recv_buff_data_len);
    state->recv_buff_len += recv_buff_data_len;

    free(recv_buff);

    struct http_request **requests = NULL;
    size_t request_count = 0;

    int8_t parse_state = http_parse_requests(state->recv_buff, state->recv_buff_len, &requests, &request_count);

    LOG_DEBUG("finished parse requests state=%d request_count=%d", parse_state, request_count);

    if (request_count && requests) {
        // reset poll retries so we wait an appropriate amount of time for another request
        state->poll_retries = 0;
        httpd_process_requests(state, requests, request_count);
        http_debug_print_requests(requests, request_count);
        http_free_requests(requests, request_count);
    }

    if (parse_state == -1) {
        httpd_send_simple(state, HTTP_STATUS_CODE_BAD_REQUEST, HTTP_STATUS_BAD_REQUEST, 1);
        tcp_close(state->pcb);

        if (state->server->cleanup_func) {
            state->server->cleanup_func(state);
        }

        httpd_free_state(state);

    } else if (parse_state == 0) {
        state->recv_buff_len = 0;
    } else {
        // a result greater than zero indicates that there's unsused data that should be
        // saved. i.e. the parser assumes there is an incomplete request in the buffer in which
        // the rest has yet to be received.
        size_t new_buff_size = state->recv_buff_len - parse_state;
        memmove(state->recv_buff + parse_state, state->recv_buff, new_buff_size);
        memset(state->recv_buff + state->recv_buff_len, 0, HTTPD_RECV_BUFF_SIZE - new_buff_size);

        state->recv_buff_len = new_buff_size;
    }

    return ERR_OK;
}

static err_t HTTPD_IRAM_ATTR httpd_poll(void *arg, struct tcp_pcb *pcb)
{
    struct http_connection_state *state = (struct http_connection_state *)arg;
    if (state == NULL) {
        LOG_DEBUG("bad state will close connection %p", pcb);
        tcp_close(pcb);
        return ERR_OK;
    }

    LOG_DEBUG("poll for connection state %p", state);

    // state->poll_retries++;

    // if (state->poll_retries == HTTPD_MAX_RETRIES) {
    //     // if there is data in the receive buffer we assume that it's an incomplete request
    //     if (state->recv_buff_len) {
    //         httpd_send_simple(state, 400, "Bad Request", 0);
    //     }

    //     LOG_DEBUG("max poll retries, closing connection %p", pcb);
    //     tcp_close(pcb);

    //     return ERR_OK;
    // }

    return ERR_OK;
}

static err_t HTTPD_IRAM_ATTR httpd_sent(void *arg, struct tcp_pcb *tpcb, u16_t len)
{
    LOG_FUNCTION_ENTRY();
    return ERR_OK;
}

static void HTTPD_IRAM_ATTR httpd_err(void *arg, err_t err)
{
    LOG_FUNCTION_ENTRY();
    struct http_connection_state *state = (struct http_connection_state *)arg;

    LOG_DEBUG("received error state=%p err=%d (%s)", state, err, lwip_strerr(err));

    // don't do anything else. if we need to do any connection cleanup it will be done in the
    // receive callback when we get the indication that the connection should be closed.
    // context: https://github.com/nikharris0/esp-homekit/issues/47
}

static err_t HTTPD_IRAM_ATTR httpd_accept(void *arg, struct tcp_pcb *pcb, err_t err)
{
    LOG_FUNCTION_ENTRY();

    struct hkhttpd *server = (struct hkhttpd *)arg;

    struct tcp_pcb_listen *lpcb = (struct tcp_pcb_listen *)server->pcb;

    tcp_accepted(lpcb);
    tcp_setprio(pcb, TCP_PRIO_NORMAL);

    pcb->so_options |= SOF_KEEPALIVE;
    pcb->keep_intvl = 30000;
    pcb->keep_idle = 30000;
    pcb->keep_cnt = 2;


    struct http_connection_state *state = httpd_new_state(server, pcb);
    if (state == NULL) {
        LOG_ERROR("failed to allocate http_connection_state");
        return ERR_MEM;
    }

    tcp_arg(pcb, state);

    tcp_recv(pcb, httpd_recv);
    tcp_err(pcb, httpd_err);
    tcp_poll(pcb, httpd_poll, HTTPD_POLL_INTERVAL);
    tcp_sent(pcb, httpd_sent);

    LOG_DEBUG("accepting connection from %s", ipaddr_ntoa(&pcb->remote_ip));
    return ERR_OK;
}

err_t httpd_init(struct hkhttpd *server, hk_accessory_t *accessory, uint16_t port)
{
    LOG_FUNCTION_ENTRY();

    ASSERT(server == NULL);
    ASSERT(accessory == NULL);
    ASSERT(port <= 0);

    if (port <= 0) {
        port = HTTPD_DEFAULT_PORT;
    }

    struct tcp_pcb *pcb;
    err_t err;

    pcb = tcp_new();
    if (!pcb)
        return ERR_MEM;

    tcp_setprio(pcb, TCP_PRIO_NORMAL);
    err = tcp_bind(pcb, IP_ADDR_ANY, port);
    if (err != ERR_OK)
        return err;

    pcb = tcp_listen(pcb);
    if (!pcb)
        return ERR_MEM;

    tcp_arg(pcb, server);
    tcp_accept(pcb, httpd_accept);

    LOG_DEBUG("listening for connections on port %d for server %p", port, server);

    server->port = port;
    server->accessory = accessory;
    server->pcb = pcb;

    return ERR_OK;
}

void httpd_add_request_handler(struct hkhttpd *server, struct httpd_request_handler *handler)
{
    ASSERT(handler == NULL);

    server->request_handlers = realloc(server->request_handlers, sizeof(struct httpd_request_handler *) * ++server->request_handler_count);
    ASSERT(server->request_handlers == NULL);

    server->request_handlers[server->request_handler_count - 1] = malloc(sizeof(struct httpd_request_handler));
    ASSERT(server->request_handlers[server->request_handler_count - 1] == NULL);

    memcpy(server->request_handlers[server->request_handler_count - 1], handler, sizeof(struct httpd_request_handler));
}

void httpd_set_connection_cleanup_handler(struct hkhttpd *server, connection_cleanup_func func)
{
    server->cleanup_func = func;
}
