#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <utils.h>
#include "debug.h"

static char *TAG = "heap-debugger";

 void _heap_debug_task(void *param)
 {
     for (;;) {
        LOG_DEBUG("Heap: %d", xPortGetFreeHeapSize());
        vTaskDelay(1000 / portTICK_PERIOD_MS);
     }
 }

void init_heap_debugging_task(void)
{
    xTaskCreate(_heap_debug_task, "heap debugging", 4096, NULL, 2, NULL);
}
