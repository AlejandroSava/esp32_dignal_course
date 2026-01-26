#include <stdio.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_attr.h"
#include "esp_err.h"
#include "esp_log.h"
#include "driver/gptimer.h"

static const char *TAG = "GPTimer";
static TaskHandle_t s_worker_task = NULL;

static bool IRAM_ATTR on_timer_alarm_cb(gptimer_handle_t timer,
                                        const gptimer_alarm_event_data_t *edata,
                                        void *user_ctx){
    BaseType_t xHigherWoken = pdFALSE;
    TaskHandle_t th = (TaskHandle_t) user_ctx;
    vTaskNotifyGiveFromISR(th, &xHigherWoken);
    return xHigherWoken == pdTRUE;
}


static void worker_task(void *arg){
    for (;;) {
        ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
        ESP_LOGI(TAG, "Tick de temporizador");
    }
}



void app_main(void)
{
    xTaskCreatePinnedToCore(worker_task, "worker", 4096, NULL, 8, &s_worker_task, tskNO_AFFINITY);
    gptimer_handle_t timer = NULL;
    gptimer_config_t cfg = {
        .clk_src = GPTIMER_CLK_SRC_DEFAULT,
        .direction = GPTIMER_COUNT_UP,
        .resolution_hz = 1 * 1000 * 1000, // 1 us
    };

    // Create a timer instance
    ESP_ERROR_CHECK(gptimer_new_timer(&cfg, &timer));
    
    gptimer_event_callbacks_t cbs = {
        .on_alarm = on_timer_alarm_cb,
    };
    ESP_ERROR_CHECK(gptimer_register_event_callbacks(timer, &cbs, s_worker_task));

  
    // Start the timer

    

    ESP_ERROR_CHECK(gptimer_enable(timer));

    gptimer_alarm_config_t alarm = {
        .reload_count = 0,
        .alarm_count = 1000000, // 1 s
        .flags.auto_reload_on_alarm = true,
    };
    ESP_ERROR_CHECK(gptimer_set_alarm_action(timer, &alarm));
    ESP_ERROR_CHECK(gptimer_start(timer));
    
}
    