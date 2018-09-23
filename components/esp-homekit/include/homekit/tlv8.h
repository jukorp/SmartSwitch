#ifndef _TLV8_H_
#define _TLV8_H_

#include <freertos/FreeRTOS.h>

#define TLV8_MIN_BLOB_SIZE  3

struct tlv8 {
    uint8_t type;
    uint8_t length;
    void *value;
};

struct tlv8_container {
    size_t count;
    struct tlv8 **tlvs;
};

typedef enum {
    TLV8_ERR_OK,           // success
    TLV8_ERR_OK_REMAINDER, // success with unused data
    TLV8_ERR_INVALID,      // data was invalid
    TLV8_ERR_MEM,          // couldn't allocate memory
    TLV8_ERR_NOT_FOUND     // requested value not found
} tlv8_err_t;

// tlv8_container_new allocates a new tlv8_container and returns it.
// Returns NULL on an allocation error.
struct tlv8_container *tlv8_container_new(void);

tlv8_err_t tlv8_container_add_uint8(struct tlv8_container *c, uint8_t type, uint8_t value);

tlv8_err_t tlv8_container_add_uint32(struct tlv8_container *c, uint8_t type, uint32_t value);

tlv8_err_t tlv8_container_add_binary(struct tlv8_container *c, uint8_t type, void *value, size_t len);

// tlv8_container_add_zero_length adds a zero length TLV item with type to container c.
// Typically used for separator TLVs but can be used for anything.
tlv8_err_t tlv8_container_add_zero_length(struct tlv8_container *c, uint8_t type);

// tlv8_container_add adds a TLV item tlv to container c.
// The container will contain a pointer to the passed tlv8, therefore it must
// remain in memory for the duration in which the container is in use.
// Returns TLV8_ERR_OK on success.
tlv8_err_t tlv8_container_add(struct tlv8_container *c, struct tlv8 *tlv);

// tlv8_container_add_all adds all count TLVs in tlvs to container c. Generally used to add
// TLVs that were a product of tlv8_from_big_bin.
// The container will contain a pointer to the passed tlv8's, therefore they must
// remain in memory for the duration in which the container is in use.
// Returns TLV8_ERR_OK on success.
tlv8_err_t tlv8_container_add_all(struct tlv8_container *c, struct tlv8 **tlvs, size_t count);

// tlv8_container_encode encodes a tlv8_container into byte form.
// Returns TLV8_ERR_OK on success.
tlv8_err_t tlv8_container_encode(struct tlv8_container *c, void **data, size_t *len);

// tlv8_lookup_binary sets *dst to a blob of data found in tlvs that matches type.
// The pointer passed will be set to an allocaated chunk of memory with the size
// as specified by the tlv8. The caller is responsible for freeing dst.
// If a matching tlv8 was not found, TLV8_ERR_NOT_FOUND is returned.
// If a matching tlv8 was found, but memory could not be allocated, TLV8_ERR_MEM
// is returned. Otherwise, TLV8_ERR_OK is returned.
tlv8_err_t tlv8_lookup_binary(struct tlv8 **tlvs, size_t len, uint8_t type, void **dst, size_t *dst_len);

// tlv8_lookup_binary_all sets *dst to the concatenation of data for all TLV values that matched type.
tlv8_err_t tlv8_lookup_binary_all(struct tlv8 **tlvs, size_t len, uint8_t type, void **dst, size_t *dst_len);

// tlv8_uint8_from_value returns a uint8_t from the TLV8 value provided in
// tlv. If the length of the TLV8 value does not match the size of uint8
// TLV8_ERR_INVALID is returned. Otherwise, TLV8_ERR_OK is returned.
tlv8_err_t tlv8_uint8_from_value(struct tlv8 *tlv, uint8_t *value);

// tlv8_lookup_uint8 finds the first TLV value that matches type type. Returns
// TLV8_ERR_NOT_FOUND if one is not found, otherwise TLV8_ERR_OK.
tlv8_err_t tlv8_lookup_uint8(struct tlv8 **tlvs, size_t len, uint8_t type, uint8_t *value);

// tlv8_lookup_uint32 finds the first TLV value that matches type type. Returns
// TLV8_ERR_NOT_FOUND if one is not found, otherwise TLV8_ERR_OK.
tlv8_err_t tlv8_lookup_uint32(struct tlv8 **tlvs, size_t len, uint8_t type, uint32_t *value);

// tlv8_from_uint8 creates a tlv8 with the provided type and value.
// Returns NULL if the tlv8 could not be allocated.
struct tlv8 *tlv8_from_uint8(uint8_t type, uint8_t value);

// tlv8_from_uint32 creates a tlv8 with the provided type and value.
// Returns NULL if the tlv8 could not be alloacated.
struct tlv8 *tlv8_from_uint32(uint8_t type, uint32_t value);

// tlv8_from_big_bin create an array of tlv8s, both with type, containing the binary data
// in value fragmented across them. Should be used for any data with a length greather than 256.
// *encoded will be set to the number of tlv8s encoded.
struct tlv8 **tlv8_from_big_bin(uint8_t type, void *value, size_t len, size_t *encoded);

// tlv8_encode encodes len TLV8 data in tlvs, and sets the pointer pointed to
// by data to the final binary data.
tlv8_err_t tlv8_encode(struct tlv8 **tlvs, size_t count, void **data, size_t *len);

// tlv8_decode decodes the TLV8 data that is encoded in data that has length len.
// tlvs should be a pointer to an array of tlv8's which will hold the decoded data.
// The size_t pointed to by decoded will be set to the number of tlv8's decoded.
tlv8_err_t tlv8_decode(void *data, size_t len, struct tlv8 ***tlvs, size_t *decoded);

// tlv8_container_free deallocates a tlv8_container structure.
void tlv8_container_free(struct tlv8_container *c);

// tlv8_free deallocates a tlv8 structure.
void tlv8_free(struct tlv8 *tlv);

// tlv8_free deallocates an array of tlv8 structures.
void tlv8_free_all(struct tlv8 **tlvs, size_t len);

#endif
