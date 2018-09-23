#pragma once

#include "types.h"
#include <stdbool.h>
#include <cJSON.h>

// hk_new_pairing_context allocates a new hk_session_context_t.
// When a pair setup or pair verify request is received, the application should call this function
// and pass it to the handle functions. A reference to the context should be associated with the
// iOS device/controller. For example, with IP accessories, the context should be associated with the
// HTTP connection, and deallocated once the connection is closed.
hk_session_context_t *hk_new_session_context(hk_accessory_t *ctx, struct http_connection_state *state);

// hk_free_pairing_context deallocated an hk_session_context_t. For IP accessories, this should be invoked
// when the HTTP connection for a pair setup or pair verify request has been closed.
void hk_free_session_context(hk_session_context_t *ctx);

// hk_add_active_session adds session as an active session for accessory ctx. HomeKit uses the active
// sessions when determining which sessions require notifications.
void hk_add_active_session(hk_accessory_t *ctx, hk_session_context_t *session);

// hk_remove_active_session removes session from the active sessions list for accessory ctx.
void hk_remove_active_session(hk_accessory_t *ctx, hk_session_context_t *session);

// hk_session_register_notifications registers session ctx for change notifications for
// characteristic ch.
//
// ctx  an active session
// ch   a characteristic in which the session should receive notifications for
//
// Returns HK_ERR_OK on success.
hk_err_t hk_session_register_notifications(hk_session_context_t *ctx, hk_characteristic_t *ch);

// hk_session_unregister_notifications unregisters session ctx for change notifications for
// characteristic ch.
//
// ctx  an active session
// ch   a characteristic in which the session should no longer receive notifications for
void hk_session_unregister_notification(hk_session_context_t *ctx, hk_characteristic_t *ch);

// hk_session_unregister_all_notifications unregisters session for notifications for all
// characteristics for accessory ctx.
//
// ctx      the accessory
// session  the session in which should be unregistered for all notifications
void hk_session_unregister_all_notifications(hk_accessory_t *ctx, hk_session_context_t *session);

// hk_session_is_registered_notifications determines whether or not session ctx is registered for
// change notifications of characteristic ch.
//
// ctx  an active session
// ch   a characteristic in which the notification state should be determined
//
// Returns true when the session is registered, and false otherwise.
bool hk_session_is_registered_notifications(hk_session_context_t *ctx, hk_characteristic_t *ch);


// hk_session_send_notification sends a change notification to the active session ctx.
//
// ctx        the accessory
// requestor  the requesting session that caused the change, or NULL if none
// ch         a characteristic which value has recently changed
// payload    the body of the unsolicited event to be sent
// len        the length of payload in bytes
//
// Returns HK_ERR_OK on success.
hk_err_t hk_sessions_send_notification(hk_accessory_t *ctx, hk_session_context_t *requestor,
                                       hk_characteristic_t *ch, void *payload, size_t len);

