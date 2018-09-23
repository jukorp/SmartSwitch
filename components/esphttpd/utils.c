#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <freertos/FreeRTOS.h>
#include <esp_spi_flash.h>
#include <esp_log.h>

#include "utils.h"

// TODO: utils should become it's own component

static const char *TAG = "utils";

char *bin2hex(void *data, size_t len)
{
    size_t out_size = (len * 3) + 1;
    char *out = malloc(out_size);
    char *out_ptr = out;

    void *end = data + len;
    if (out) {
        memset(out, 0, out_size);
        while(data < end) {
            sprintf(out_ptr, "%02x ", *((char *)data++));
            out_ptr += 3;
        }
    }

    return out;
}

char *alloc_sprintf(const char *fmt, ...)
{
    LOG_FUNCTION_ENTRY();

    char *str = NULL;
    va_list args;
    va_start(args, fmt);

    int req_len = vsnprintf(NULL, 0, fmt, args);
    str = malloc(req_len + 1);
    if (!str)
        return NULL;

    int len = vsprintf(str, fmt, args);
    if (len != req_len) {
        free(str);
        return NULL;
    }

    va_end(args);
    return str;
}

void *memdup(void *buff, size_t len)
{
    void *duped = malloc(len);
    if (duped) {
        memcpy(duped, buff, len);
    }

    return duped;
}

struct tokens *tokenize(const char *str, char *delim, int max)
{
    LOG_FUNCTION_ENTRY();

    if(!str || !delim || !strlen(str) || !strlen(delim))
        return NULL;

    size_t delim_len = strlen(delim);
    int count = 0;

    const char *search_ptr = str;
    const char *token_ptr = str;
    const char *end = str + strlen(str);

    char **tokens = NULL;

    while (search_ptr <= end) {
        if (count > 0  && count == max)
            break;

        if (strncmp(search_ptr, delim, delim_len) == 0) {
            tokens = (char **)realloc(tokens, ++count * sizeof(char *));
            tokens[count - 1] = (char *)strndup(token_ptr, search_ptr - token_ptr);

            token_ptr = search_ptr + delim_len;
            search_ptr = token_ptr;
        } else {
            search_ptr++;
        }
    }

    if (token_ptr != end) {
        tokens = (char **)realloc(tokens, ++count * sizeof(char *));
        tokens[count - 1] = (char *)strdup(token_ptr);
    }

    struct tokens *t = (struct tokens *)malloc(sizeof(struct tokens));
    if (t) {
        t->count = count;
        t->tokens = tokens;
    }

    return t;
}

void free_tokens(struct tokens *t)
{
    if (t) {
        if (t->tokens) {
            for (int offset = 0; offset < t->count; offset++)
                if (t->tokens[offset])
                    free(t->tokens[offset]);

            free(t->tokens);
        }

        free(t);
    }
}

char *ltrim(char *str)
{
    char *ptr = str;
    char *end = str + strlen(str);
    while (ptr != end && (*ptr == ' ' || *ptr == '\t' || *ptr == '\r' || *ptr == '\n'))
        ptr++;

    return ptr;
}

char *rtrim(char *str)
{
    char *ptr = str + strlen(str) - 1;
    while (ptr >= str && (*ptr == ' ' || *ptr == '\t' || *ptr == '\r' || *ptr == '\n'))
        *ptr-- = 0;

    return str;
}

// TODO: this implementatinon is not working. in the meantime we are using strstr as a replacement,
// but this should eventually be fixed and used instead.
char *binstrstr(char *haystack, size_t len, char *needle)
{
    LOG_FUNCTION_ENTRY();

    if (!haystack || !needle)
        return NULL;

    size_t needle_len = strlen(needle);

    for (int haystack_offset = 0; haystack_offset < len - needle_len; haystack_offset++) {
        uint8_t found = true;
        for (int needle_offset = 0; needle_offset < needle_len; needle_offset++) {
            if (haystack[haystack_offset + needle_offset] != needle[needle_offset]) {
                found = false;
                break;
            }
        }

        if (found)
            return haystack + haystack_offset;
    }

    return NULL;
}

int strindex(char *str, char **arr, int arr_len)
{
    for (int i = 0; i < arr_len; i++) {
        if (!strcmp(str, arr[i]))
            return i;
    }

    return -1;
}

int gen_random(void *data, size_t len)
{
    uint32_t r;
    void *write_ptr = data;

    for (size_t i = 0; i < len; i++) {
        r = esp_random();
        memcpy(write_ptr, &r, sizeof(uint8_t));
        write_ptr++;
    }

    return 0;
}

void print_chip_info(void)
{
    esp_chip_info_t chip_info;
    esp_chip_info(&chip_info);
    LOG_INFO("----- device information -----");
    LOG_INFO("ESP32 cores=%d features=WiFi%s%s", chip_info.cores, (chip_info.features & CHIP_FEATURE_BT) ? "/BT" : "",
        (chip_info.features & CHIP_FEATURE_BLE) ? "/BLE" : "");
    LOG_INFO("silicon revision=%d ", chip_info.revision);
    LOG_INFO("flash=%dMB flash_loc=%s", spi_flash_get_chip_size() / (1024 * 1024),
        (chip_info.features & CHIP_FEATURE_EMB_FLASH) ? "embedded" : "external");
    LOG_INFO("------------------------------");
}