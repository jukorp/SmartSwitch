// PanicReporter
// PanicReporter.h
// Copyright © 2018 Nik Harris. All Rights Reserved.

#ifndef _PANIC_REPORTER_H_
#define _PANIC_REPORTER_H_

#include <stdint.h>
#include <stdbool.h>

typedef struct PR_Config_t {
    char *reportingURL;           // full URL in which the coredump upload request should be sent
    int reportingPort;            // port to be used for the HTTP connection
    char *deviceModel;            // device model to be sent in X-DeviceModel header
    char *deviceId;               // device ID to be sent in X-DeviceId header
    char *firmwareVersion;        // firmware version to be sent in X-FirmwareVersion header
    char ***extraHeaders;         // custom headers to be sent with coredump upload
    uint8_t extraHeaderCount;     // number of header key value pairs in extraHeaders
    uint8_t maxRetries;           // max coredump upload retries
    int retryIntervalSec;         // retry coredump upload frequency
    int lowMemoryWatermarkBytes;  // memory reporter threshold
    bool memoryReporterCancel;    // stop memory reporter task
} PR_Config_t;

typedef enum {
    PR_ERR_OK,
    PR_ERR_BAD_ARG,
    PR_ERR_NO_PARTITION,
    PR_ERR_MEM,
    PR_ERR_MMAP,
    PR_ERR_BAD_DATA
} PR_Error_t;


// PR_StartPanicReporter starts the panic reporter task using the configuration options defined
// in config. When the Panic Reporter is started it will check the coredump partition for rhw
// presence of a coredump, and if one is found, it's uploaded in the original binary format
// to the defined URL. Upon successfully uploading the panic report, the coredump is erased
// from the coredump partition.
//
// Returns PR_ERR_OK on succcess.
PR_Error_t PR_StartPanicReporter(PR_Config_t *config);

// PR_StartMemoryReporter starts the memory reporter task using the configuration options defined
// in config. The memory reporter will send a basic memory usage report when the available heap
// goes below lowMemoryWatermarkBytes.
//
// Returns PR_ERR_OK on success.
PR_Error_t PR_StartMemoryReporter(PR_Config_t *config);

// PR_STopMemoryReporter stops the Memory Reporter task.
void PR_StopMemoryReporter(PR_Config_t *config);

#endif
