#pragma once

#include <stdio.h>
#include <string.h>
#include <esp_log.h>
#include <esp_err.h>

#define array_len(x) (sizeof(x) / sizeof(x[0]))
#define min_int(a, b) ((a < b) ? a : b)

// tokens is the structure returned by a successful call to tokenize. count contains
// the number of tokens that were extracted. tokens is a char* array containing
// all extracted tokens.
struct tokens {
    size_t count;
    char **tokens;
};

// logging macros
// fmt and variable arguments are the same as *printf functions.
// These methods assume that variable TAG is in scope when called, and is
// the string identifier for the component writing the logs.
#define LOG_DEBUG(fmt, ...)  ESP_LOGD(TAG, "<%s> " fmt, __FUNCTION__, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...)   ESP_LOGI(TAG, fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...)  ESP_LOGE(TAG, fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)   ESP_LOGW(TAG, fmt, ##__VA_ARGS__)
#define LOG_FUNCTION_ENTRY() LOG_DEBUG("invoked")

// log binary data in hexadecimal representation
#define LOG_DEBUG_HEX(data, len, msg, ...) do {                \
    char *__data_hex = bin2hex(data, len);                     \
    if (__data_hex) {                                          \
        ESP_LOGD(TAG, msg ":\n%s", ##__VA_ARGS__, __data_hex); \
        free(__data_hex);                                      \
    }                                                          \
} while (0);

// TODO: all ASSERT calls need to be converted so that they fail when the assertion is false.
// Right now all of the calls work with ESP_ERROR_CHECK, which fails on true :(
#define ASSERT(expression)   ESP_ERROR_CHECK((expression))

// bin2hex converts a blob of data to a string with the data in hexidecimal representation for the
// purposes of displaying. Bytes are separated by a space for readability, and therefore it should
// not be used for anything other than displaying/logging binary data.
char *bin2hex(void *data, size_t len);

// alloc_sprintf allocates a string using the format and arguments provided.
// Caller is responsible for freeing the result.
char *alloc_sprintf(const char *fmt, ...);

// memdup allocates len bytes of memory and copies the contents of buff into it.
// Caller is responsible for freeing the result.
void *memdup(void *buff, size_t len);

// tokenize splits the string str using the string delimiter delim. If more than
// max tokens are found, the remainder of the string will be contained in the
// last token in the returns tokens array (at index max).
struct tokens *tokenize(const char *str, char *delim, int max);
void free_tokens(struct tokens *t);

// ltrim returns a pointer to the first non-space character in string str.
// Unlike rtrim, the provided string str is not modified.
char *ltrim(char *str);

// rtrim trims all whitespace from the end of a str by inserting a NULL
// byte at the start of the last sequence of whitespace.
char *rtrim(char *str);

// binstrstr is a binary safe implementation of strstr.
char *binstrstr(char *haystack, size_t len, char *needle);

// strindex takes an array of strings, arr, and returns the index of str in the array. Comparison
// is done via strcmp and is therefore case sensitive.
int strindex(char *str, char **arr, int arr_len);

// gen_random generates len random bytes of data using the ESP32 hardware RNG.
int gen_random(void *data, size_t len);

// print_chip_info prints the ESP32 chip features and specs to stdout/uart.
void print_chip_info(void);

