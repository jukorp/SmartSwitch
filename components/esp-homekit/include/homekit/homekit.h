#ifndef _ESP_HK_H_
#define _ESP_HK_H_

#include "types.h"

void hk_set_accessory_error_state(hk_accessory_t *ctx, bool state);
void hk_set_paired_status(hk_accessory_t *ctx, bool paired);

/* hk_init initializes an esp-homekit accessory.
 *
 * cat should be the HomeKit accessory category
 * device_id should be in the format XX:XX:XX:XX:XX:XX
 * model should be the device model. E.g. Device1,1
 */
hk_accessory_t *hk_init(hk_accessory_category_t cat, char *device_id, char *model);

/* hk_start starts the HomeKit accessory HTTP server for IP accessories.
 *
 * ctx   a valid hk_accessory_t for a previously initialized accessory via homekit_init
 * port  the port number in which the server should listen on. Can use HK_DEFAULT_PORT
 *
 * Returns HK_ERR_OK on success.
 */
hk_err_t hk_ip_start(hk_accessory_t *ctx, uint16_t port);

/* hk_set_update_mdns_func sets the mDNS updater function that should be called when
 * homekit requires that mDNS TXT entries are updated.
 *
 * When core HomeKit configurations change, it's possible that the TXT entries that are
 * being broadcasted through mDNS need to be updated. When this occurs, homekit will call
 * the function provided here, passing the updated TXT records.
 */
void hk_set_update_mdns_func(hk_accessory_t *ctx, hk_update_mdns_txts_func func);

/* hk_set_storage_path sets the on-disk storage path which should be used for persisting accessory
 * state and any pairs. When called, esp-homekit will attempt to load the accessory state from the file.
 * If it doesn't exist, the current accessory config will be written for the first time.
 *
 * path should be the path that should be used for the file
 *
 * returns HK_ERR_OK on success.
 */
hk_err_t hk_set_storage_path(hk_accessory_t *ctx, const char *path);

// hk_add_service adds service to the accessory ctx.
hk_err_t hk_add_service(hk_accessory_t *ctx, hk_service_t *service);

/* hk_get_service returns the hk_service_t instance associated with accessory ctx that has
 * an ID that matches serviceId.
 *
 * ctx should be the hk_accessory_t which contains the desired service
 * serviceId is the ID of desired service
 *
 * returns NULL if the service does not exist.
 */
hk_service_t *hk_get_service(hk_accessory_t *ctx, const char *serviceId);

/* hk_handle_characteristics_write_request is used to handle an incoming read request.
 * For IP accessories, this is a GET request to /characteristics.
 *
 * ctx should be the hk_session_context_t associated with a verified session.
 * opts is an array of key value pairs which provide the filters to be used for the request.
 *         The key names are the same as provided in the GET request query parameters for IP
 *         accessories: id, meta, perms, type, ev. See HAP 5.7.3 for more information.
 * opts_len is the number of key/value pairs in opts.
 * response is a pointer to a pointer that will be set to the response to be sent to the controller.
 * resp_len should be a pointer toa size_t that will be set to the size of response in bytes.
 * http_code is an optional pointer to an int which will be set to the appropriate HTTP status code.
 */
void hk_handle_characteristics_read_request(hk_session_context_t *ctx, char ***opts,
                                            int opts_len, void **response,
                                            size_t *resp_len, int *http_code);

/* hk_handle_characteristics_write_request is used to handle an incoming write request.
 * For IP accessories, this is a PUT request to /characteristics.
 *
 * ctx should be the hk_session_context_t associated with a verified session.
 * request is a pointer to the request body for the write request
 * len is the size of request in bytes
 * response is a pointer to a pointer that will be set to the response to be sent to the controller.
 * resp_len should be a pointer to a size_t and will be set to the size of response in bytes.
 * http_code is an optional pointer to an int which will be set to the appropriate HTTP status code.
 */
void hk_handle_characteristics_write_request(hk_session_context_t *ctx, void *request, size_t len,
                                             void **response, size_t *resp_len, int *http_code);

/* hk_handle_attribute_db_request is used to handle an incoming accessory attribute database request.
 * For IP accessories, this is a request to /accessories.
 *
 * ctx should be the hk_session_context_t that represents a verified HTTP session.
 * response is a pointer to a pointer that will be set to the response to be sent to the controller.
 *          The caller is responsible for freeing the contents, if not NULL.
 * resp_len should be a pointer to a size_t and will be set to the size of response in bytes.
 * resp_code is an optional pointer to an int, which will be set to the appropriate HTTP status code.
 */
void hk_handle_attribute_db_request(hk_session_context_t *ctx, void **response,
                                        size_t *resp_len, int *resp_code);


/* hk_update_value updates a characteristic value. This function should be used to update a value
 * any time it has changed outside of HomeKit. value should be a result of the function
 * hk_characteristic_value_from_from_{bool,string,int,double}
 */
void hk_update_value(hk_accessory_t *ctx, hk_characteristic_t *ch, char *value);

/* hk_generate_setup_code generates a HomeKit-compliant 6-digit setup code used
 * for the initial pairing process. Accessories that can display a setup code should use this.
 * Accesssories that cannot display a setup code should have one generated at manufacture time
 * and printed on a label somewhere.
 */
void hk_generate_setup_code(char code[11]);

/* hk_set_setup_code sets the pairing setup code to be used. It should be in the format
 * of ##-##-##. If the code is not in the correct format or is one of the disallowed codes
 * outlined by the HomeKit specification, 0 will be returned. 1 is returned on success.
 *
 * Returns HK_ERR_BAD_ARG if the setup code is not valid, or HK_ERR_OK on success.
 */
hk_err_t hk_set_setup_code(hk_accessory_t *ctx, char *code);

#endif
