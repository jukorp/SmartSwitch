#include <stdio.h>
#include <string.h>
#include <freertos/FreeRTOS.h>
#include <esp_system.h>
#include <esp_log.h>
#include <utils.h>
#include <cJSON.h>

#include <esphttpd.h>
#include <homekit/homekit.h>
#include "homekit/types.h"
#include "homekit/session.h"
#include "homekit/service.h"
#include "homekit/handlers.h"
#include "persistence.h"

static const char *TAG = "esp-homekit";

static char * const kHKJSONAccessoriesKey    = "accessories";
static char * const kHKJSONAccessoryIdKey    = "aid";
static char * const kHKJSONServicesKey       = "services";
static char * const kHKJSONPrimaryKey        = "primary";
static char * const kHKJSONChrKey            = "characteristics";
static char * const kHKJSONStatusKey         = "status";
static char * const kHKJSONServiceChrTypeKey = "type";
static char * const kHKJSONInstanceIdKey     = "iid";
static char * const kHKJSONNotificationsKey  = "ev";
static char * const kHKJSONValueKey          = "value";
static char * const kHKJSONPermissionsKey    = "perms";
static char * const kHKJSONFormatKey         = "format";
static char * const kHKJSONMaxValueKey       = "maxValue";
static char * const kHKJSONMinValueKey       = "minValue";
static char * const kHKJSONMinStepKey        = "minStep";
static char * const kHKJSONUnitKey           = "unit";

static char *invalid_setup_keys[12] = {
    "000-00-000", "111-11-111", "222-22-222", "333-33-333",
    "444-44-444", "555-55-555", "666-66-666", "777-77-777",
    "888-88-888", "999-99-999", "123-45-678", "876-54-321"
};

void hk_short_guid_from_guid(char *guid, char short_guid[10])
{
    ASSERT(guid == NULL);
    ASSERT(short_guid == NULL);

    char *ptr = guid;
    while(*ptr == '0')
        ptr++;

    char *end = strchr(ptr, '-');
    if (end) {
        memset(short_guid, 0, 10);
        memcpy(short_guid, ptr, end - ptr);
    }
}

hk_accessory_t *hk_init(hk_accessory_category_t cat, char *device_id, char *model)
{
    ASSERT(device_id == NULL);
    ASSERT(model == NULL);

    hk_accessory_t *ctx = malloc(sizeof(hk_accessory_t));
    if (ctx) {
        memset(ctx, 0, sizeof(hk_accessory_t));

        ctx->category = cat;
        ctx->instance_id      = 1;
        ctx->next_instance_id = ctx->instance_id + 1;
        ctx->config           = 1;
        ctx->status_flags    |= HK_STATUS_FLAG_NOT_PAIRED;

        strncpy(ctx->device_id, device_id, min_int(strlen(device_id), 64));
        strncpy(ctx->device_model_name, model, 64);
    }

    return ctx;
}

hk_err_t hk_ip_start(hk_accessory_t *ctx, uint16_t port)
{
    ASSERT(ctx == NULL);
    ASSERT(port <= 0);

    struct hkhttpd *server = malloc(sizeof(struct hkhttpd));
    if (!server)
        return HK_ERR_MEM;

    memset(server, 0, sizeof(struct hkhttpd));

    err_t err = httpd_init(server, ctx, port);
    if (err != ERR_OK) {
        free(server);
        return err;
    }

    ctx->server = server;

    struct httpd_request_handler accessories_handler = {
        .full_match = 1,
        .uri = HK_HTTP_ACCESSORIES_URI,
        .request_handler = hk_accessories_req_handler
    };

    httpd_add_request_handler(server, &accessories_handler);

    struct httpd_request_handler characteristics_handler = {
        .full_match = 1,
        .uri = HK_HTTP_CHARACTERISTICS_URI,
        .request_handler = hk_characteristics_req_handler
    };

    httpd_add_request_handler(server, &characteristics_handler);

    struct httpd_request_handler identify_handler = {
        .full_match = 1,
        .uri = HK_HTTP_IDENTIFY_URI,
        .request_handler = hk_identify_req_handler
    };

    httpd_add_request_handler(server, &identify_handler);

    struct httpd_request_handler pair_setup_handler = {
        .full_match = 1,
        .uri = HK_HTTP_PAIR_SETUP_URI,
        .request_handler = hk_pair_setup_req_handler
    };

    httpd_add_request_handler(server, &pair_setup_handler);

    struct httpd_request_handler pair_verify_handler = {
        .full_match = 1,
        .uri = HK_HTTP_PAIR_VERIFY_URI,
        .request_handler = hk_pair_verify_req_handler
    };

    httpd_add_request_handler(server, &pair_verify_handler);

    struct httpd_request_handler pairings_handler = {
        .full_match = 1,
        .uri = HK_HTTP_PAIRINGS_URI,
        .request_handler = hk_pairings_req_handler
    };

    httpd_add_request_handler(server, &pairings_handler);

    httpd_set_connection_cleanup_handler(server, hk_http_connection_cleanup_handler);

    return HK_ERR_OK;
}

void hk_update_mdns_txts(hk_accessory_t *ctx)
{
    ASSERT(ctx == NULL);
    ASSERT(ctx->mdns_update_func == NULL);

    char txts[8][3][32] = {0};

    sprintf(txts[0][0], "c#");
    sprintf(txts[0][1], "%d", ctx->config);
    sprintf(txts[1][0], "ff");

    // HAP spec says this value should be 1 and is required for all accessories, but I think this
    // should only be used for mFI accessories, because the "uncertified" warning goes away and
    // pairing fails/times out when it's 1.
    sprintf(txts[1][1], /*"1"*/ "0");

    sprintf(txts[2][0], "id");
    sprintf(txts[2][1], "%s", ctx->device_id);
    sprintf(txts[3][0], "md");
    sprintf(txts[3][1], "%s", ctx->device_model_name);
    sprintf(txts[4][0], "pv");
    sprintf(txts[4][1], "%.01f", HK_PROTO_VERSION);
    sprintf(txts[5][0], "s#");
    sprintf(txts[5][1], "1");
    sprintf(txts[6][0], "sf");
    sprintf(txts[6][1], "%d", ctx->status_flags);
    sprintf(txts[7][0], "ci");
    sprintf(txts[7][1], "%d", ctx->category);

    ctx->mdns_update_func(txts, 8);
}

hk_err_t hk_increment_config(hk_accessory_t *ctx)
{
    ASSERT(ctx == NULL);

    if (ctx->config == 0xFFFFFFFF)
        ctx->config = 1;
    else
        ctx->config++;


    hk_update_mdns_txts(ctx);
    return hk_write_accessory_config(ctx);
}

hk_err_t hk_add_service(hk_accessory_t *ctx, hk_service_t *service)
{
    ASSERT(ctx == NULL);
    ASSERT(service == NULL);

    LOG_DEBUG("adding service %p to accessory %p instance_id=%d", service, ctx, ctx->next_instance_id);

    service->instance_id = ctx->next_instance_id++;
    for (int i = 0; i < service->characteristic_count; i++) {
        LOG_DEBUG("assigning characteristic instance id service=%p characteristic=%p instance_id=%d",
                  service, service->characteristics[i], ctx->next_instance_id);
        service->characteristics[i]->instance_id = ctx->next_instance_id++;
    }

    hk_service_t **svcs = realloc(ctx->services, ++ctx->services_count * sizeof(hk_service_t *));
    if (!svcs) {
        return HK_ERR_MEM;
    }

    ctx->services = svcs;
    ctx->services[ctx->services_count - 1] = service;

    hk_err_t err = hk_increment_config(ctx);
    if (err != HK_ERR_OK) {
        LOG_ERROR("failed to increment accessory config (%d)", err);
        return err;
    }

    return HK_ERR_OK;
}

hk_service_t *hk_get_service(hk_accessory_t *ctx, const char *serviceId)
{
    ASSERT(ctx == NULL);
    ASSERT(serviceId == NULL);

    for (int i = 0; i < ctx->services_count; i++) {
        hk_service_t *service = ctx->services[i];
        if (!strcmp(service->id, serviceId)) {
            return service;
        }
    }

    return NULL;
}

void hk_set_accessory_error_state(hk_accessory_t *ctx, bool state)
{
    ASSERT(ctx == NULL);

    if (state)
        ctx->status_flags |= HK_STATUS_FLAG_PROBLEM;
    else
        ctx->status_flags &= ~HK_STATUS_FLAG_PROBLEM;

    hk_update_mdns_txts(ctx);

    hk_err_t err = hk_write_accessory_config(ctx);
    if (err != HK_ERR_OK) {
        LOG_ERROR("failed to persist accessory state after pair state change (%d)", err);
    }
}

void hk_set_paired_status(hk_accessory_t *ctx, bool paired)
{
    ASSERT(ctx == NULL);

    ctx->pair.paired = paired;

    if (paired)
        ctx->status_flags &= ~HK_STATUS_FLAG_NOT_PAIRED;
    else
        ctx->status_flags |= HK_STATUS_FLAG_NOT_PAIRED;

    hk_update_mdns_txts(ctx);
}

void hk_set_update_mdns_func(hk_accessory_t *ctx, hk_update_mdns_txts_func func)
{
    ASSERT(ctx == NULL);
    ASSERT(func == NULL);

    ctx->mdns_update_func = func;
    LOG_DEBUG("mDNS update func set to %p for accessory %p", func, ctx);

    hk_update_mdns_txts(ctx);
}

static uint8_t setup_code_is_valid(char code[11])
{
    for (int n = 0; n < array_len(invalid_setup_keys); n++) {
        if (!strcmp(code, invalid_setup_keys[n])) {
            return 0;
        }
    }

    return 1;
}

hk_err_t hk_set_storage_path(hk_accessory_t *ctx, const char *path)
{
    ASSERT(ctx == NULL);
    ASSERT(path == NULL);

    strncpy(ctx->storage_path, path, HK_MAX_PATH);

    return hk_load_accessory_config(ctx);
}

static hk_characteristic_t *hk_get_characteristic_by_iid(hk_accessory_t *ctx, int instance_id)
{
    ASSERT(ctx == NULL);
    ASSERT(instance_id < 1);

    for(int service_i = 0; service_i < ctx->services_count; service_i++)
        for (int chr_i = 0; chr_i < ctx->services[service_i]->characteristic_count; chr_i++) {
            if (ctx->services[service_i]->characteristics[chr_i]->instance_id == instance_id)
                return ctx->services[service_i]->characteristics[chr_i];
        }

    return NULL;
}

static cJSON *create_characheristic_json(hk_accessory_t *ctx, hk_characteristic_t *ch,
                                         bool min_max_step, bool unit, bool perms, bool type)
{
    ASSERT(ch == NULL);

    cJSON *ch_json = cJSON_CreateObject();

    cJSON_AddNumberToObject(ch_json, kHKJSONAccessoryIdKey, (double)ctx->instance_id);
    cJSON_AddNumberToObject(ch_json, kHKJSONInstanceIdKey, (double)ch->instance_id);

    if (perms) {
        cJSON *perms_arr_json = cJSON_CreateArray();

        if (ch->perms & HK_PERMISSION_READ)
            cJSON_AddItemToArray(perms_arr_json, cJSON_CreateString("pr"));

        if (ch->perms & HK_PERMISSION_WRITE)
            cJSON_AddItemToArray(perms_arr_json, cJSON_CreateString("pw"));

        if (ch->perms & HK_PERMISSION_NOTIFY)
            cJSON_AddItemToArray(perms_arr_json, cJSON_CreateString("ev"));

        cJSON_AddItemToObject(ch_json, kHKJSONPermissionsKey, perms_arr_json);
    }

    if (type) {
        char id_str[64];
        hk_short_guid_from_guid(ch->id, id_str);
        cJSON_AddStringToObject(ch_json, kHKJSONServiceChrTypeKey, id_str);
    }

    if (ch->perms & HK_PERMISSION_READ) {
        switch (ch->format) {
            case HK_VALUE_FORMAT_BOOL: {
                int value = atoi(ch->value);
                cJSON_AddBoolToObject(ch_json, kHKJSONValueKey, value);
                break;
            }

            case HK_VALUE_FORMAT_BYTES: {
                // TODO: implement bytes characteristic value type
                LOG_WARN("unimplemented characteristic value type bytes");
                break;
            }

            case HK_VALUE_FORMAT_FLOAT: {
                double value = atof(ch->value);
                cJSON_AddNumberToObject(ch_json, kHKJSONValueKey, value);

                if (min_max_step) {
                    cJSON_AddNumberToObject(ch_json, kHKJSONMaxValueKey, ch->max_value);
                    cJSON_AddNumberToObject(ch_json, kHKJSONMinValueKey, ch->min_value);
                    cJSON_AddNumberToObject(ch_json, kHKJSONMinStepKey, ch->step_value);
                }

                if (unit) {
                    cJSON_AddStringToObject(ch_json, kHKJSONUnitKey, hk_characteristic_unit_to_string(ch->unit));
                }

                break;
            }

            case HK_VALUE_FORMAT_INT: {
                int value = atoi(ch->value);
                cJSON_AddNumberToObject(ch_json, kHKJSONValueKey, value);

                if (min_max_step) {
                    cJSON_AddNumberToObject(ch_json, kHKJSONMaxValueKey, ch->max_value);
                    cJSON_AddNumberToObject(ch_json, kHKJSONMinValueKey, ch->min_value);
                    cJSON_AddNumberToObject(ch_json, kHKJSONMinStepKey, ch->step_value);
                }

                if (unit) {
                    cJSON_AddStringToObject(ch_json, kHKJSONUnitKey, hk_characteristic_unit_to_string(ch->unit));
                }

                break;
            }

            case HK_VALUE_FORMAT_STRING: {
                cJSON_AddStringToObject(ch_json, kHKJSONValueKey, ch->value);
                break;
            }

            case HK_VALUE_FORMAT_TLV8: {
                // TODO: implement tlv8 characteristic value type
                LOG_WARN("unimplemented characteristic value type tlv8");
                break;
            }

            default:
                LOG_WARN("characteristic has an unrecognized format, will serialize as NULL");
                cJSON_AddNullToObject(ch_json, "value");
        }
    }

    return ch_json;
}

static hk_err_t send_notification(hk_accessory_t *ctx, hk_characteristic_t *ch,
                                  hk_session_context_t *requestor)
{
    ASSERT(ctx == NULL);
    ASSERT(ch == NULL);

    cJSON *ch_json = create_characheristic_json(ctx, ch, false, false, false, false);
    cJSON *ch_arr_json = cJSON_CreateArray();
    cJSON_AddItemToArray(ch_arr_json, ch_json);

    cJSON *json = cJSON_CreateObject();
    cJSON_AddItemToObject(json, kHKJSONChrKey, ch_arr_json);

    char *payload = cJSON_Print(json);
    cJSON_Delete(json);

    if (!payload) {
        LOG_ERROR("failed to seriallize notification payload");
        return HK_ERR_MEM;
    }

    hk_err_t err = hk_sessions_send_notification(ctx, requestor, ch, payload, strlen(payload));
    free(payload);

    return err;
}

void hk_handle_characteristics_read_request(hk_session_context_t *ctx, char ***opts,
                                            int opts_len, void **response,
                                            size_t *resp_len, int *http_code)
{
    ASSERT(ctx == NULL);
    ASSERT(response == NULL);
    ASSERT(resp_len == NULL);

    if (!ctx->verified) {
        LOG_DEBUG("denying characteristics read for session context %p", ctx);
        *response = NULL;
        *resp_len = 0;

        if (http_code)
            *http_code = 403;

        return;
    }

    struct tokens *ids = NULL;
    bool meta = false, perms = false, type = false, ev = false;

    for (int i = 0; i < opts_len; i++) {
        if (!opts[i][1])
            continue;

        if (!strcmp(opts[i][0], "id")) {
            ids = tokenize(opts[i][1], ",", 0);
        } else if (!strcmp(opts[i][0], "meta") && !strcmp(opts[i][1], "1"))
            meta = true;
        else if (!strcmp(opts[i][0], "perms") && !strcmp(opts[i][1], "1"))
            perms = true;
        else if (!strcmp(opts[i][0], "type") && !strcmp(opts[i][1], "1"))
            type = true;
        else if (!strcmp(opts[i][0], "ev") && !strcmp(opts[i][1], "1"))
            ev = true;
    }

    if (!ids) {
        *response = NULL;
        *resp_len = 0;

        if (http_code)
            *http_code = 400;

        return;
    }

    cJSON *resp_ch_arr_json = cJSON_CreateArray();

    for (size_t service_i = 0; service_i < ctx->ctx->services_count; service_i++) {
        hk_service_t *service = ctx->ctx->services[service_i];

        for (size_t chr_i = 0; chr_i < service->characteristic_count; chr_i++) {
            hk_characteristic_t *chr = service->characteristics[chr_i];

            char chr_full_id[32];
            sprintf(chr_full_id, "%d.%d", ctx->ctx->instance_id, chr->instance_id);

            if (strindex(chr_full_id, ids->tokens, ids->count) != -1) {
                LOG_DEBUG("characteristic full id %s was in ids requested, will process", chr_full_id);

                cJSON *ch_json = create_characheristic_json(ctx->ctx, chr, meta, meta, perms, type);

                if (ev) {
                    uint8_t notify_state = hk_session_is_registered_notifications(ctx, chr);
                    cJSON_AddBoolToObject(ch_json, kHKJSONNotificationsKey, notify_state);
                }

                cJSON_AddItemToArray(resp_ch_arr_json, ch_json);
            }
        }
    }

    free_tokens(ids);

    cJSON *json = cJSON_CreateObject();
    cJSON_AddItemToObject(json, kHKJSONChrKey, resp_ch_arr_json);

    char *payload = cJSON_Print(json);
    cJSON_Delete(json);

    if (!payload) {
        *response = NULL;
        *resp_len = 0;

        if (http_code)
            *http_code = 500;

        return;
    }

    *response = payload;
    *resp_len = strlen(payload);

    if (http_code)
        *http_code = 200;
}

void hk_handle_characteristics_write_request(hk_session_context_t *ctx, void *request, size_t len,
                                             void **response, size_t *resp_len, int *http_code)
{
    ASSERT(ctx == NULL);
    ASSERT(request == NULL);
    ASSERT(len == 0);
    ASSERT(response == NULL);
    ASSERT(resp_len == NULL);

    if (!ctx->verified) {
        LOG_DEBUG("denying characteristics write request for session context %p", ctx);
        *response = NULL;
        *resp_len = 0;

        if (http_code)
            *http_code = 403;

        return;
    }

    cJSON *json_req = cJSON_Parse(request);
    if (!json_req) {
        LOG_ERROR("error parsing characteristics write request JSON");
        if (http_code)
            *http_code = 400;

        return;
    }

    cJSON *json_write_chrs_arr = cJSON_GetObjectItem(json_req, kHKJSONChrKey);
    if (!json_write_chrs_arr || !cJSON_IsArray(json_write_chrs_arr)) {
        LOG_ERROR("request did not contain characteristics array");
        if (http_code)
            *http_code = 400;

        cJSON_Delete(json_req);
        return;
    }

    cJSON *json_chrs = cJSON_CreateArray();

    uint8_t error_occurred = 0;
    int json_write_chrs_arr_size = cJSON_GetArraySize(json_write_chrs_arr);
    for (int i = 0; i < json_write_chrs_arr_size; i++) {
        cJSON *ch_json = cJSON_GetArrayItem(json_write_chrs_arr, i);
        cJSON *ch_iid_json = cJSON_GetObjectItem(ch_json, kHKJSONInstanceIdKey);

        cJSON *resp_ch_json = cJSON_CreateObject();
        cJSON_AddNumberToObject(resp_ch_json, kHKJSONAccessoryIdKey, (double)ctx->ctx->instance_id);
        cJSON_AddNumberToObject(resp_ch_json, kHKJSONInstanceIdKey, (double)ch_iid_json->valueint);

        hk_characteristic_t *ch = hk_get_characteristic_by_iid(ctx->ctx, ch_iid_json->valueint);
        if (!ch) {
            LOG_ERROR("characteristic with instance id %d not found", ch_iid_json->valueint);
            error_occurred = 1;
            cJSON_AddNumberToObject(resp_ch_json, kHKJSONStatusKey, HK_STATUS_CODE_EXIST);
            cJSON_AddItemToArray(json_chrs, resp_ch_json);
            continue;
        }

        cJSON *notifications_json = cJSON_GetObjectItem(ch_json, kHKJSONNotificationsKey);
        cJSON *value_json = cJSON_GetObjectItem(ch_json, kHKJSONValueKey);
        if (!value_json && !notifications_json) {
            LOG_ERROR("value and notifications keys not present in characteristic write request object %d", i);
            error_occurred = 1;
            cJSON_AddNumberToObject(resp_ch_json, kHKJSONStatusKey, HK_STATUS_CODE_INVALID_VALUE);
            cJSON_AddItemToArray(json_chrs, resp_ch_json);
            continue;
        }

        if (notifications_json) {
            if (!(ch->perms & HK_PERMISSION_NOTIFY)) {
                LOG_ERROR("session %p notifications registration denied due to permissions", ctx);
                cJSON_AddNumberToObject(resp_ch_json, kHKJSONStatusKey, HK_STATUS_CODE_NOTIF_NOT_SUPPORTED);
                cJSON_AddItemToArray(json_chrs, resp_ch_json);
            } else {
                LOG_INFO("session %p requests notification state %d for characteristic iid %d",
                         ctx, notifications_json->valueint, ch->instance_id);

                if (notifications_json->valueint)
                    hk_session_register_notifications(ctx, ch);
                else
                    hk_session_unregister_notification(ctx, ch);

                cJSON_AddNumberToObject(resp_ch_json, kHKJSONStatusKey, 0);
                cJSON_AddItemToArray(json_chrs, resp_ch_json);
            }

            continue;
        }

        if (value_json) {
            switch(ch->format) {
                case HK_VALUE_FORMAT_BOOL:
                    LOG_INFO("characteristic %p value updated to %d (boolean)", ch, value_json->valueint);
                    hk_characteristic_set_value(ch, hk_characteristic_value_from_bool(value_json->valueint));
                    cJSON_AddNumberToObject(resp_ch_json, kHKJSONStatusKey, 0);
                    cJSON_AddItemToArray(json_chrs, resp_ch_json);
                    break;

                case HK_VALUE_FORMAT_FLOAT:
                    LOG_INFO("characteristic %p value updated to %f (double)", ch, value_json->valuedouble);
                    hk_characteristic_set_value(ch, hk_characteristic_value_from_double(value_json->valuedouble));
                    cJSON_AddNumberToObject(resp_ch_json, kHKJSONStatusKey, 0);
                    cJSON_AddItemToArray(json_chrs, resp_ch_json);
                    break;

                case HK_VALUE_FORMAT_INT:
                    LOG_INFO("characteristic %p value updated to %d (int)", ch, value_json->valueint);
                    hk_characteristic_set_value(ch, hk_characteristic_value_from_bool(value_json->valueint));
                    cJSON_AddNumberToObject(resp_ch_json, kHKJSONStatusKey, 0);
                    cJSON_AddItemToArray(json_chrs, resp_ch_json);
                    break;

                case HK_VALUE_FORMAT_STRING:
                    LOG_INFO("characteristic %p value updated to \"%s\"", ch, value_json->valuestring);
                    hk_characteristic_set_value(ch, hk_characteristic_value_from_string(value_json->valuestring));
                    cJSON_AddNumberToObject(resp_ch_json, kHKJSONStatusKey, 0);
                    cJSON_AddItemToArray(json_chrs, resp_ch_json);
                    break;

                case HK_VALUE_FORMAT_TLV8:
                    LOG_WARN("characteristic %p value to tlv8 not implemented!", ch);
                    cJSON_AddNumberToObject(resp_ch_json, kHKJSONStatusKey, HK_STATUS_CODE_INVALID_VALUE);
                    cJSON_AddItemToArray(json_chrs, resp_ch_json);
                    break;

                case HK_VALUE_FORMAT_BYTES:
                    LOG_WARN("characteristic %p value to bytes not implemented!", ch);
                    cJSON_AddNumberToObject(resp_ch_json, kHKJSONStatusKey, HK_STATUS_CODE_INVALID_VALUE);
                    cJSON_AddItemToArray(json_chrs, resp_ch_json);
                    break;

                default:
                    LOG_ERROR("characteristic %p write request with invalud value format %d", ch, ch->format);
                    cJSON_AddNumberToObject(resp_ch_json, kHKJSONStatusKey, HK_STATUS_CODE_INVALID_VALUE);
                    cJSON_AddItemToArray(json_chrs, resp_ch_json);
                    break;
            }

            hk_err_t err = send_notification(ctx->ctx, ch, ctx);
            if (err != HK_ERR_OK) {
                LOG_ERROR("failed to send notifications for characteristic %p and requestor session %p (%d)", ch, ctx, err);
            }

            if (ch->change_func) {
                LOG_DEBUG("will call change function callback %p for characteristic %p", ch->change_func, ch);
                ch->change_func(ctx->ctx, ch);
            }
        }
    }

    // if any errors occurred we need to return the array with individual status codes and for HTTP,
    // a status code of 207 Multi-Status
    if (error_occurred) {
        cJSON *json = cJSON_CreateObject();
        cJSON_AddItemToObject(json, kHKJSONChrKey, json_chrs);

        char *payload = cJSON_Print(json);
        cJSON_Delete(json);

        if (!payload) {
            *response = NULL;
            *resp_len = 0;

            if (http_code)
                *http_code = 500;
        } else {
            *response = payload;
            *resp_len = strlen(payload);

            if (http_code)
                *http_code = 207;
        }
    } else {
        *response = NULL;
        *resp_len = 0;

        if (http_code)
            *http_code = 204;
    }

    cJSON_Delete(json_req);
}

void hk_handle_attribute_db_request(hk_session_context_t *ctx, void **response,
                                        size_t *resp_len, int *resp_code)
{
    LOG_FUNCTION_ENTRY();

    ASSERT(ctx == NULL);
    ASSERT(response == NULL);
    ASSERT(resp_len == NULL);

    if (!ctx->verified) {
        LOG_DEBUG("denying attribute db request for session context %p", ctx);
        *response = NULL;
        *resp_len = 0;

        if (resp_code)
            *resp_code = 403;

        return;
    }

    cJSON *services_arr_json = cJSON_CreateArray();

    hk_service_t *service = NULL;
    for (size_t i = 0; i < ctx->ctx->services_count; i++, service = ctx->ctx->services[i] ) {
        service = ctx->ctx->services[i];

        cJSON *service_json = cJSON_CreateObject();
        char service_id_str[10];
        hk_short_guid_from_guid(service->id, service_id_str);

        cJSON_AddStringToObject(service_json, kHKJSONServiceChrTypeKey, service_id_str);
        cJSON_AddNumberToObject(service_json, kHKJSONInstanceIdKey, (double)ctx->ctx->services[i]->instance_id);
        cJSON_AddBoolToObject(service_json, kHKJSONPrimaryKey, service->is_primary);

        cJSON *chs_arr_json = cJSON_CreateArray();

        for (size_t j = 0; j < service->characteristic_count; j++) {
            hk_characteristic_t *ch = service->characteristics[j];

            LOG_DEBUG("building characteristic JSON data characteristic=%p type=%s", ch, ch->id);

            char chr_id_str[10];
            hk_short_guid_from_guid(ch->id, chr_id_str);

            cJSON *ch_json = create_characheristic_json(ctx->ctx, ch, true, true, true, true);
            cJSON_AddItemToArray(chs_arr_json, ch_json);
        }

        cJSON_AddItemToObject(service_json, kHKJSONChrKey, chs_arr_json);
        cJSON_AddItemToObject(services_arr_json, kHKJSONChrKey, service_json);
    }

    cJSON *json = cJSON_CreateObject();
    cJSON *accessories_arr_json = cJSON_CreateArray();
    cJSON *accessory_json = cJSON_CreateObject();

    cJSON_AddNumberToObject(accessory_json, kHKJSONAccessoryIdKey, (double)ctx->ctx->instance_id);
    cJSON_AddItemToObject(accessory_json, kHKJSONServicesKey, services_arr_json);
    cJSON_AddItemToArray(accessories_arr_json, accessory_json);
    cJSON_AddItemToObject(json, kHKJSONAccessoriesKey, accessories_arr_json);

    char *json_payload = cJSON_Print(json);
    if (!json_payload) {
        *response = NULL;
        *resp_len = 0;

        if (resp_code)
            *resp_code = 500;

        cJSON_Delete(json);
        return;
    }

    LOG_DEBUG("attribute db JSON response is:\n%s", json_payload);

    *response = json_payload;
    *resp_len = strlen(json_payload);

    if (resp_code)
        *resp_code = 200;

    cJSON_Delete(json);
}

void hk_update_value(hk_accessory_t *ctx, hk_characteristic_t *ch, char *value)
{
    ASSERT(ctx == NULL);
    ASSERT(ch == NULL);
    ASSERT(value == NULL);

    ch->value = value;

    hk_err_t err = send_notification(ctx, ch, NULL);
    if (err != HK_ERR_OK) {
        LOG_ERROR("failed to send notifications for API characteristic change (%d)", err);
    }
}

void hk_generate_setup_code(char code[11])
{
    do {
        uint32_t chip_id = esp_random();
        char device_id[32];
        sprintf(device_id, "%09u", chip_id);

        for (int code_offset = 0, chip_id_offset = 0; code_offset < 10; code_offset++) {
            if (code_offset == 3 || code_offset == 6) {
                code[code_offset] = '-';
                continue;
            }

            code[code_offset] = device_id[chip_id_offset];
            chip_id_offset++;
        }

        code[10] = 0;
    } while(!setup_code_is_valid(code));

    LOG_DEBUG("generated setup code %s", code);
}

hk_err_t hk_set_setup_code(hk_accessory_t *ctx, char *code)
{
    if (!setup_code_is_valid(code))
        return HK_ERR_BAD_ARG;

    ctx->setup_code = strdup(code);
    return HK_ERR_OK;
}
