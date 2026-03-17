#include "esp_attr.h"
#include "esp_sleep.h"
#include <puflib.h>

// A counter that survives deep sleep (RTC memory)
RTC_DATA_ATTR volatile uint32_t puf_wake_stub_hits = 0;

// Keep the symbol from being stripped by the linker/LTO.
void __attribute__((used)) RTC_IRAM_ATTR esp_wake_deep_sleep(void)
{
    // ROM/RTC-safe only. No logging/heap/FreeRTOS.
    puf_wake_stub_hits++;          // <-- prove the stub ran
    esp_default_wake_deep_sleep();
    puflib_wake_up_stub();         // cold-capture attempt
}
