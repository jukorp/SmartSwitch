#include <esphttpd.h>
#include <lwip/tcpip.h>
#include "homekit/session.h"

static const char *TAG = "esp-homekit-session";

hk_session_context_t *hk_new_session_context(hk_accessory_t *ctx, struct http_connection_state *state)
{
    ASSERT(ctx == NULL);
    ASSERT(state == NULL);

    hk_session_context_t *pair_ctx = (hk_session_context_t *)malloc(sizeof(struct hk_session_context_t));
    if (pair_ctx) {
        memset(pair_ctx, 0, sizeof(struct hk_session_context_t));
        pair_ctx->ctx = ctx;
        pair_ctx->httpd_state = state;

        hk_add_active_session(ctx, pair_ctx);
    }

    return pair_ctx;
}

void hk_free_session_context(hk_session_context_t *ctx)
{
    if (ctx) {
        hk_remove_active_session(ctx->ctx, ctx);
        free(ctx);
    }
}

void hk_add_active_session(hk_accessory_t *ctx, hk_session_context_t *session)
{
    ASSERT(ctx == NULL);
    ASSERT(session == NULL);

    LOG_DEBUG("will add active session session_count=%d", ctx->active_session_count + 1);

    hk_session_context_t **sessions = realloc(ctx->active_sessions,
                                        ++ctx->active_session_count * sizeof(hk_session_context_t));
    if (sessions) {
        sessions[ctx->active_session_count - 1] = session;
        ctx->active_sessions = sessions;
    }
}

void hk_remove_active_session(hk_accessory_t *ctx, hk_session_context_t *session)
{
    ASSERT(ctx == NULL);
    ASSERT(session == NULL);

    ssize_t index = -1;
    for (size_t i = 0; i < ctx->active_session_count; i++) {
        if (ctx->active_sessions[i] == session) {
            index = i;
            break;
        }
    }

    if (index < 0)
        return;

    LOG_DEBUG("will remove session index=%d", index);

    hk_session_unregister_all_notifications(ctx, session);

    // if it's the last one in the list we have nothing to move
    if (index != ctx->active_session_count - 1) {
        size_t mv_size = sizeof(hk_session_context_t *) * (ctx->active_session_count - index - 1);
        LOG_DEBUG("session is not last in the list, will move session after it down by 1 mv_size=%d", mv_size);
        memmove(&ctx->active_sessions[index], &ctx->active_sessions[index + 1], mv_size);
    }

    if (ctx->active_session_count - 1 == 0) {
        LOG_DEBUG("active sessions now zero, will free all active session memory");
        free(ctx->active_sessions);
        ctx->active_sessions = NULL;
        ctx->active_session_count--;
    } else {
        LOG_DEBUG("will reallocate active sessions list new_count=%d", ctx->active_session_count - 1);
        hk_session_context_t **sessions = realloc(ctx->active_sessions,
            sizeof(hk_session_context_t *) * --ctx->active_session_count);
        if (sessions)
            ctx->active_sessions = sessions;
    }
}

hk_err_t hk_session_register_notifications(hk_session_context_t *ctx, hk_characteristic_t *ch)
{
    ASSERT(ctx == NULL);
    ASSERT(ch == NULL);

    for(int i = 0; i < ctx->notify_chrs_count; i++) {
        if (ch == ctx->notify_chrs[i])
            return HK_ERR_OK;
    }

    hk_characteristic_t **notifys = realloc(ctx->notify_chrs,
                                        ++ctx->notify_chrs_count * sizeof(hk_characteristic_t *));
    if(!notifys) {
        return HK_ERR_MEM;
    }

    notifys[ctx->notify_chrs_count - 1] = ch;
    ctx->notify_chrs = notifys;

    return HK_ERR_OK;
}

void hk_session_unregister_notification(hk_session_context_t *ctx, hk_characteristic_t *ch)
{
    ASSERT(ctx == NULL);
    ASSERT(ch == NULL);

    LOG_FUNCTION_ENTRY();

    int index = -1;
    for (int i = 0; i < ctx->notify_chrs_count; i++) {
        if (ch == ctx->notify_chrs[i]) {
            index = i;
            break;
        }
    }

    if (index < 0)
        return;

    // if it's the last one in the list we have nothing to move
    if (index != ctx->notify_chrs_count - 1) {
        size_t mv_size = sizeof(hk_characteristic_t *) * (ctx->notify_chrs_count - index - 1);
        memmove(&ctx->notify_chrs[index], &ctx->notify_chrs[index + 1], mv_size);
    }

    if (ctx->notify_chrs_count - 1 == 0) {
        free(ctx->notify_chrs);
        ctx->notify_chrs = NULL;
        ctx->notify_chrs_count--;
    } else {
        hk_characteristic_t **new_notifys = realloc(ctx->notify_chrs,
                                                sizeof(hk_characteristic_t *) * --ctx->notify_chrs_count);
        if (new_notifys)
            ctx->notify_chrs = new_notifys;
    }
}

void hk_session_unregister_all_notifications(hk_accessory_t *ctx, hk_session_context_t *session)
{
    ASSERT(ctx == NULL);
    ASSERT(session == NULL);

    LOG_FUNCTION_ENTRY();

    for (size_t service_i = 0; service_i < ctx->services_count; service_i++) {
        hk_service_t *service = ctx->services[service_i];

        for (size_t chr_i = 0; chr_i < service->characteristic_count; chr_i++) {
            hk_characteristic_t *chr = service->characteristics[chr_i];
            hk_session_unregister_notification(session, chr);
        }
    }
}

bool hk_session_is_registered_notifications(hk_session_context_t *ctx, hk_characteristic_t *ch)
{
    ASSERT(ctx == NULL);
    ASSERT(ch == NULL);

    for (int i = 0; i < ctx->notify_chrs_count; i++)
        if (ch == ctx->notify_chrs[i])
            return true;

    return false;
}

hk_err_t hk_sessions_send_notification(hk_accessory_t *ctx, hk_session_context_t *requestor,
                                       hk_characteristic_t *ch, void *payload, size_t len)
{
    ASSERT(ctx == NULL);
    ASSERT(ch == NULL);

    if (!ctx->active_session_count)
        return HK_ERR_OK;

    struct http_response *r = NULL;
    hk_err_t err = HK_ERR_OK;

    for (size_t i = 0; i < ctx->active_session_count; i++) {
        hk_session_context_t *session = ctx->active_sessions[i];

        if (requestor && session == requestor)
            continue;

        if (!hk_session_is_registered_notifications(session, ch))
            continue;

        LOG_DEBUG("session %p is registetered for notifications for characteristic iid %d",
                  session, ch->instance_id);

        if (!r) {
            r = http_new_response(HTTP_STATUS_CODE_OK, HTTP_STATUS_OK);
            if (!r) {
                err = HK_ERR_MEM;
                break;
            }

            http_add_header(&r->headers, &r->header_count, HTTP_HEADER_KEY_CONTENT_TYPE, HK_CONTENT_TYPE_JSON);

            r->http_version = strdup("EVENT/1.0");
            r->body = memdup(payload, len);
            r->body_len = len;
        }

        LOG_DEBUG("sending notification response %p to session %p", r, session);
        err_t tcp_err = httpd_send(session->httpd_state, r);
        if (tcp_err != ERR_OK) {
            LOG_ERROR("TCP send error %d for session %p, cleaning up session", tcp_err, session);
            hk_free_session_context(session);
        }
    }

    http_free_response(r);

    return err;
}
