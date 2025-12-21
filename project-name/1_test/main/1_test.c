#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/gpio.h"

#define PIN 2 // esp32

void app_main(void){
    gpio_set_direction(PIN, GPIO_MODE_OUTPUT);
    uint32_t is_on = 0;
    while(true){
        is_on = !is_on;
        gpio_set_level(PIN, is_on);
        vTaskDelay(1000 / portTICK_PERIOD_MS);

    } 

}