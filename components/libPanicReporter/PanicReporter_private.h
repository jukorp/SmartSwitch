// PanicReporter
// PanicReporter_private.h
// Copyright © 2018 Nik Harris. All Rights Reserved.

#ifndef _PANIC_REPORTER_PRIVATE_H_
#define _PANIC_REPORTER_PRIVATE_H_

#include <PanicReporter.h>
#include <esp_log.h>

const char * TAG = "PanicReporter";

#define PR_LOG_DEBUG(fmt, ...)  ESP_LOGD(TAG, "<%s> " fmt, __FUNCTION__, ##__VA_ARGS__)
#define PR_LOG_INFO(fmt, ...)   ESP_LOGI(TAG, fmt, ##__VA_ARGS__)
#define PR_LOG_ERROR(fmt, ...)  ESP_LOGE(TAG, fmt, ##__VA_ARGS__)
#define PR_LOG_WARN(fmt, ...)   ESP_LOGW(TAG, fmt, ##__VA_ARGS__)
#define PR_LOG_FUNCTION_ENTRY() PR_LOG_DEBUG("invoked")

typedef PR_Error_t (*PR_CoreDumpReadFunc_t)(PR_Config_t *, void *, size_t);

#define COREDUMP_MAGIC_START    0xE32C04ED
#define COREDUMP_MAGIC_END      0xE32C04ED

#endif
