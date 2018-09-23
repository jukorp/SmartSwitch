// PanicReporter
// PanicReporter.c
// Copyright © 2018 Nik Harris. All Rights Reserved.

#include "PanicReporter_private.h"
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <esp_partition.h>
#include <esp_err.h>
#include <esp_http_client.h>
#include <string.h>

static char * const kPanicReporterTaskName = "Panic Reporter";
static char * const kMemoryReporterTaskName = "Memory Reporter";


static const esp_partition_t *_getCoreDumpPartition(void)
{
    const esp_partition_t *part = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_COREDUMP, NULL);
    if (!part) {
        PR_LOG_ERROR("failed to find coredump partition!");
        return NULL;
    }

    return part;
}

static PR_Error_t _readCoreDump(PR_Config_t *config, PR_CoreDumpReadFunc_t callback)
{
    const esp_partition_t *part = _getCoreDumpPartition();
    if (!part) {
        PR_LOG_ERROR("failed to find coredump partition!");
        return PR_ERR_NO_PARTITION;
    }

    // map the parition so we can read without having to take up real memory
    void *dataStart = NULL;
    void *dataEnd = NULL;
    void *coreDumpEnd = NULL;
    size_t totalSize = part->size;
    spi_flash_mmap_handle_t mapHandle;

    esp_err_t err = esp_partition_mmap(part, 0, totalSize, SPI_FLASH_MMAP_DATA, (const void **)&dataStart, &mapHandle);
    if (err != ESP_OK) {
        PR_LOG_ERROR("failed to map coredump partition: %s (%d)", esp_err_to_name(err), err);
        return PR_ERR_MMAP;
    }

    dataEnd = dataStart + part->size;

    if (*(uint32_t *)dataStart != COREDUMP_MAGIC_START) {
        PR_LOG_DEBUG("invalid coredump start bytes (0x%04x), assuming no coredump and erasing partition", (uint32_t)dataStart);
        esp_partition_erase_range(part, 0, part->size);
        spi_flash_munmap(mapHandle);
        return PR_ERR_OK;
    }

    // we don't keep the starting magic number
    dataStart += 4;

    PR_LOG_DEBUG("coredump present");

    void *ptr = dataStart;

    while(ptr < dataEnd) {
        if (*(uint32_t *)ptr == COREDUMP_MAGIC_END) {
            coreDumpEnd = ptr - 1;
            break;
        }

        ptr++;
    }

    if (!coreDumpEnd) {
        PR_LOG_ERROR("failed to find the end of the coredump, erasing coredump partition");
        esp_partition_erase_range(part, 0, part->size);
        spi_flash_munmap(mapHandle);
        return PR_ERR_BAD_DATA;
    }

    size_t len = coreDumpEnd - dataStart;
    PR_LOG_DEBUG("coredump boundaries found start=%p end=%p size=%d", dataStart, coreDumpEnd, len);

    PR_Error_t reporterErr = callback(config, dataStart, len);
    if (reporterErr == PR_ERR_OK) {
        PR_LOG_DEBUG("callback indicated coredump report success, erasing coredump partition");
        esp_partition_erase_range(part, 0, part->size);
    }


    spi_flash_munmap(mapHandle);
    return reporterErr;
}

static PR_Error_t _readCoreDumpCallback(PR_Config_t *config, void *coreDump, size_t len)
{
    esp_http_client_config_t httpConfig = {
        .url = config->reportingURL,
        .method = HTTP_METHOD_POST,
        .port = config->reportingPort
    };

    esp_http_client_handle_t client = esp_http_client_init(&httpConfig);

    if (config->deviceModel && strlen(config->deviceModel)) {
        esp_http_client_set_header(client, "X-DeviceModel", config->deviceModel);
    }

    if (config->deviceId && strlen(config->deviceId)) {
        esp_http_client_set_header(client, "X-DeviceId", config->deviceId);
    }

    if (config->firmwareVersion && strlen(config->firmwareVersion)) {
        esp_http_client_set_header(client, "X-SoftwareVersion", config->firmwareVersion);
    }

    if (config->extraHeaderCount) {
        for (uint8_t i = 0; i < config->extraHeaderCount; i++) {
            esp_http_client_set_header(client, config->extraHeaders[0][0], config->extraHeaders[0][1]);
        }
    }

    esp_http_client_set_post_field(client, coreDump, (int)len);

    PR_LOG_DEBUG("will send %d d byte coredump to %s", len, config->reportingURL);

    esp_err_t err = esp_http_client_perform(client);
    if (err != ESP_OK) {
        PR_LOG_ERROR("error uploading coredump (HTTP %d)", esp_http_client_get_status_code(client));
    } else {
        PR_LOG_INFO("successfully uploaded coredump");
    }

    esp_http_client_cleanup(client);
    return err;
}

static void _panicReporterTask(void *param)
{
    PR_LOG_FUNCTION_ENTRY();
    PR_Config_t *config = (PR_Config_t *)param;

    uint64_t attempts = 0;

    while(config->maxRetries == 0 || attempts < config->maxRetries) {
        if (attempts != 0) {
            vTaskDelay(pdMS_TO_TICKS(1000 * config->retryIntervalSec));
        }

        PR_Error_t err = _readCoreDump(config, _readCoreDumpCallback);
        if (err == PR_ERR_OK) {
            break;
        }

        attempts++;
    }

    PR_LOG_INFO("Panic Reporter finished");
    vTaskDelete(NULL);
}

static void _memoryReporterTask(void *param)
{
    PR_LOG_FUNCTION_ENTRY();
    PR_Config_t *config = (PR_Config_t *)param;

    while (!config->memoryReporterCancel) {

    }

    PR_LOG_INFO("Memory Reporter finished");
    vTaskDelete(NULL);
}

PR_Error_t PR_StartPanicReporter(PR_Config_t *config)
{
    PR_LOG_FUNCTION_ENTRY();

    // TODO: optimize stack size
    BaseType_t err = xTaskCreate(_panicReporterTask, kPanicReporterTaskName, 4096, (void *)config, 2, NULL);
    if (err != pdPASS) {
        PR_LOG_ERROR("failed to create panic reporter task (%d)", err);
        return PR_ERR_MEM;
    }

    return PR_ERR_OK;
}

PR_Error_t PR_StartMemoryReporter(PR_Config_t *config)
{
    PR_LOG_FUNCTION_ENTRY();

    // TODO: optimize stack size
    BaseType_t err = xTaskCreate(_memoryReporterTask, kMemoryReporterTaskName, 4096, (void *)config, 2, NULL);
    if (err != pdPASS) {
        PR_LOG_ERROR("failed to create panic reporter task (%d)", err);
        return PR_ERR_MEM;
    }

    return PR_ERR_OK;
}

void PR_StopMemoryReporter(PR_Config_t *config)
{
    PR_LOG_FUNCTION_ENTRY();
    config->memoryReporterCancel = true;
}
