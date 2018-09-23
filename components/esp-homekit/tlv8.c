#include <string.h>
#include <utils.h>
#include "homekit/tlv8.h"

static const char *TAG = "tlv8";

struct tlv8_container *tlv8_container_new(void)
{
    struct tlv8_container *container = malloc(sizeof(struct tlv8_container));
    if (container) {
        memset(container, 0, sizeof(struct tlv8_container));
    }

    return container;
}

tlv8_err_t tlv8_container_add(struct tlv8_container *c, struct tlv8 *tlv)
{
    ASSERT(c == NULL);
    ASSERT(tlv == NULL);

    c->tlvs = realloc(c->tlvs, sizeof(struct tlv8 *) * ++c->count);
    if (!c->tlvs)
        return TLV8_ERR_MEM;

    c->tlvs[c->count - 1] = malloc(sizeof(struct tlv8));
    if (!c->tlvs[c->count - 1])
        return TLV8_ERR_MEM;

    c->tlvs[c->count - 1] = tlv;
    return TLV8_ERR_OK;
}

tlv8_err_t tlv8_container_add_all(struct tlv8_container *c, struct tlv8 **tlvs, size_t count)
{
    ASSERT(c == NULL);
    ASSERT(tlvs == NULL);

    tlv8_err_t err = TLV8_ERR_OK;
    for (size_t i = 0; i < count; i++) {
        err = tlv8_container_add(c, tlvs[i]);
        if (err != TLV8_ERR_OK)
            return err;
    }

    return err;
}

tlv8_err_t tlv8_container_encode(struct tlv8_container *c, void **data, size_t *len)
{
    LOG_FUNCTION_ENTRY();

    ASSERT(c == NULL);
    ASSERT(data == NULL);
    ASSERT(len == NULL);

    void *out = NULL;
    size_t out_len = 0;

    for (size_t i = 0; i < c->count; i++) {
        LOG_DEBUG("encoding container tlv %d of %d at %p", i + 1, c->count, c->tlvs[i]);
        LOG_DEBUG("will encode TLV8 type=%d length=%d first_byte=%02x",
             c->tlvs[i]->type, c->tlvs[i]->length, *((unsigned char *)c->tlvs[i]->value));

        out = realloc(out, out_len + c->tlvs[i]->length + 2);
        if (!out)
            return TLV8_ERR_MEM;

        memcpy(out + out_len, &c->tlvs[i]->type, sizeof(uint8_t));
        memcpy(out + out_len + 1, &c->tlvs[i]->length, sizeof(uint8_t));
        memcpy(out + out_len + 2, c->tlvs[i]->value, c->tlvs[i]->length);
        out_len += c->tlvs[i]->length + 2;
    }

    *data = out;
    *len = out_len;
    return TLV8_ERR_OK;
}

tlv8_err_t tlv8_uint8_from_value(struct tlv8 *tlv, uint8_t *value)
{
    ASSERT(tlv == NULL);

    if (tlv->length != sizeof(uint8_t))
        return TLV8_ERR_INVALID;

    memcpy(value, tlv->value, sizeof(uint8_t));

    return TLV8_ERR_OK;
}

tlv8_err_t tlv8_lookup_binary(struct tlv8 **tlvs, size_t len, uint8_t type, void **dst, size_t *dst_len)
{
    ASSERT(tlvs == NULL);
    ASSERT(dst == NULL);
    ASSERT(dst_len == NULL);

    for (size_t i = 0; i < len; i++) {
        if (tlvs[i]->type == type) {
            *dst = malloc(tlvs[i]->length);
            if (!*dst)
                return TLV8_ERR_MEM;

            memcpy(*dst, tlvs[i]->value, tlvs[i]->length);
            *dst_len = tlvs[i]->length;
            return TLV8_ERR_OK;
        }
    }

    return TLV8_ERR_NOT_FOUND;
}

tlv8_err_t tlv8_lookup_binary_all(struct tlv8 **tlvs, size_t len, uint8_t type, void **dst, size_t *dst_len)
{
    ASSERT(tlvs == NULL);
    ASSERT(dst == NULL);
    ASSERT(dst_len == NULL);

    size_t buff_size = 0;
    void *buff = NULL;

    for (size_t i = 0; i < len; i++) {
        if (tlvs[i]->type == type) {
            buff = realloc(buff, buff_size + tlvs[i]->length);
            memcpy(buff + buff_size, tlvs[i]->value, tlvs[i]->length);
            buff_size += tlvs[i]->length;
        }
    }

    if (buff_size == 0)
        return TLV8_ERR_NOT_FOUND;

    *dst_len = buff_size;
    *dst = buff;
    return TLV8_ERR_OK;
}

tlv8_err_t tlv8_lookup_uint8(struct tlv8 **tlvs, size_t len, uint8_t type, uint8_t *value)
{
    ASSERT(tlvs == NULL);
    ASSERT(value == NULL);

    for (size_t i = 0; i < len; i++) {
        if (tlvs[i]->type == type && tlvs[i]->length == sizeof(uint8_t)) {
            memcpy(value, tlvs[i]->value, sizeof(uint8_t));
            return TLV8_ERR_OK;
        }
    }

    return TLV8_ERR_NOT_FOUND;
}

tlv8_err_t tlv8_lookup_uint32(struct tlv8 **tlvs, size_t len, uint8_t type, uint32_t *value)
{
    ASSERT(tlvs == NULL);
    ASSERT(value == NULL);

    for (size_t i = 0; i < len; i++) {
        if (tlvs[i]->type == type && tlvs[i]->length == sizeof(uint32_t)) {
            memcpy(value, tlvs[i]->value, sizeof(uint32_t));
            return TLV8_ERR_OK;
        }
    }

    return TLV8_ERR_NOT_FOUND;
}

tlv8_err_t tlv8_container_add_uint8(struct tlv8_container *c, uint8_t type, uint8_t value)
{
    ASSERT(c == NULL);

    struct tlv8 *tlv = tlv8_from_uint8(type, value);
    if (!tlv)
        return TLV8_ERR_MEM;

    return tlv8_container_add(c, tlv);
}

tlv8_err_t tlv8_container_add_uint32(struct tlv8_container *c, uint8_t type, uint32_t value)
{
    ASSERT(c == NULL);

    struct tlv8 *tlv = tlv8_from_uint32(type, value);
    if (!tlv)
        return TLV8_ERR_MEM;

    return tlv8_container_add(c, tlv);
}

struct tlv8 *tlv8_from_uint8(uint8_t type, uint8_t value)
{
    struct tlv8 *tlv = malloc(sizeof(struct tlv8));
    if (tlv) {
        tlv->type   = type;
        tlv->length = sizeof(uint8_t);
        tlv->value  = malloc(tlv->length);
        memcpy(tlv->value, &value, tlv->length);
    }

    return tlv;
}

struct tlv8 *tlv8_from_uint32(uint8_t type, uint32_t value)
{
    struct tlv8 *tlv = malloc(sizeof(struct tlv8));
    if (tlv) {
        tlv->type   = type;
        tlv->length = sizeof(uint32_t);
        tlv->value  = malloc(tlv->length);
        memcpy(tlv->value, &value, tlv->length);
    }

    return tlv;
}

tlv8_err_t tlv8_container_add_binary(struct tlv8_container *c, uint8_t type, void *value, size_t len)
{
    ASSERT(c == NULL);
    ASSERT(value == NULL);
    ASSERT(len == 0);

    size_t encoded = 0;
    struct tlv8 **tlvs = tlv8_from_big_bin(type, value, len, &encoded);
    if (!tlvs)
        return TLV8_ERR_MEM;

    return tlv8_container_add_all(c, tlvs, encoded);
}

tlv8_err_t tlv8_container_add_zero_length(struct tlv8_container *c, uint8_t type)
{
    ASSERT(c == NULL);

    struct tlv8 **tlvs = realloc(c->tlvs, sizeof(struct tlv8 *) * ++c->count);
    if (!tlvs) {
        c->count--;
        return TLV8_ERR_MEM;
    }

    c->tlvs = tlvs;

    c->tlvs[c->count - 1] = malloc(sizeof(struct tlv8));
    c->tlvs[c->count - 1]->type = type;
    c->tlvs[c->count - 1]->length = 0;
    c->tlvs[c->count - 1]->value = NULL;

    return TLV8_ERR_OK;
}

struct tlv8 **tlv8_from_big_bin(uint8_t type, void *value, size_t len, size_t *encoded)
{
    ASSERT(value == NULL);
    ASSERT(encoded == NULL);

    struct tlv8 **tlvs = NULL, **tlvs_ptr = NULL;
    size_t tlv_count = 0;

    char *read_ptr = value;
    size_t written = 0;
    size_t to_write = 0;

    while (written < len) {
        to_write = (len - written <= 255) ? len - written : 255;
        tlvs_ptr = realloc(tlvs, sizeof(struct tlv8 *) * ++tlv_count);
        if (!tlvs_ptr) {
            LOG_DEBUG("failed to reallocate TLV value buffer");
            free(tlvs);
            return NULL;
        }

        tlvs = tlvs_ptr;

        tlvs[tlv_count - 1]         = malloc(sizeof(struct tlv8));
        tlvs[tlv_count - 1]->type   = type;
        tlvs[tlv_count - 1]->length = to_write;
        tlvs[tlv_count - 1]->value  = malloc(to_write);
        memcpy(tlvs[tlv_count - 1]->value, read_ptr, to_write);

        LOG_DEBUG("encoded %d bytes to TLV fragment %d type=%d length=%d first_byte=%02x ",
            to_write, tlv_count - 1, type, to_write, *((unsigned char *)read_ptr));

        written += to_write;
        read_ptr += to_write;
    }

    LOG_DEBUG("encoded total of %d bytes in %d fragments", len, tlv_count);

    *encoded = tlv_count;
    return tlvs;
}

tlv8_err_t tlv8_encode(struct tlv8 **tlvs, size_t count, void **data, size_t *len)
{
    ASSERT(tlvs == NULL);
    ASSERT(count == 0);
    ASSERT(data == NULL);
    ASSERT(len == NULL);

    size_t tot_size = 0;
    for (size_t i = 0; i < count; i++) {
        tot_size += 2 + tlvs[i]->length;
    }

    void *buff = malloc(tot_size);
    if (!buff)
        return TLV8_ERR_MEM;

    void *buff_ptr = buff;

    for (size_t i = 0; i < count; i++) {
        memcpy(buff_ptr++, &tlvs[i]->type, sizeof(uint8_t));
        memcpy(buff_ptr++, &tlvs[i]->length, sizeof(uint8_t));

        // we support zero length tlvs
        if (tlvs[i]->value) {
            memcpy(buff_ptr, tlvs[i]->value, tlvs[i]->length);
            buff_ptr += tlvs[i]->length;
        }
    }

    *len = tot_size;
    *data = buff;

    return TLV8_ERR_OK;
}

tlv8_err_t tlv8_decode(void *data, size_t len, struct tlv8 ***t, size_t *decoded)
{
    ASSERT(data == NULL);
    ASSERT(len == 0);
    ASSERT(t == NULL);
    ASSERT(decoded == NULL);

    void *data_ptr = data;
    void *data_end = data + len;
    struct tlv8 **tlvs = NULL;
    size_t count = 0;

    while (data_ptr + TLV8_MIN_BLOB_SIZE <= data_end) {
        tlvs = realloc(tlvs, ++count * sizeof(struct tlv8 *));
        if (!tlvs)
            return TLV8_ERR_MEM;

        *t = tlvs;

        tlvs[count - 1] = malloc(sizeof(struct tlv8));
        if (!tlvs[count - 1]) {
            return TLV8_ERR_MEM;
        }

        memset(tlvs[count - 1], 0, sizeof(struct tlv8));
        memcpy(&tlvs[count - 1]->type, data_ptr++, sizeof(uint8_t));
        memcpy(&tlvs[count - 1]->length, data_ptr++, sizeof(uint8_t));

        tlvs[count - 1]->value = malloc(tlvs[count - 1]->length);
        memcpy(tlvs[count - 1]->value, data_ptr, tlvs[count - 1]->length);

        LOG_DEBUG("decoded tlv8 blob type=%d length=%d first_byte=%02x", tlvs[count - 1]->type,
            tlvs[count - 1]->length, *((char *)tlvs[count -1]->value));

        data_ptr += tlvs[count - 1]->length;
    }

    *decoded = count;

    if (data_ptr != data_end) {
        LOG_WARN("decoded TLV data has an unused remainder of %d bytes", data_end - data_ptr);
        return TLV8_ERR_OK_REMAINDER;
    }

    return TLV8_ERR_OK;
}

void tlv8_container_free(struct tlv8_container *c)
{
    if (c) {
        if (c->tlvs)
            tlv8_free_all(c->tlvs, c->count);

        free(c);
    }
}

void tlv8_free(struct tlv8 *tlv)
{
    if (tlv) {
        if (tlv->value) free(tlv->value);
        free(tlv);
    }
}

void tlv8_free_all(struct tlv8 **tlvs, size_t len)
{
    if (tlvs) {
        for (size_t i = 0; i < len; i++) {
            if (tlvs[i]) {
                if (tlvs[i]->value)
                    free(tlvs[i]->value);

                free(tlvs[i]);
            }
        }

        free(tlvs);
    }
}