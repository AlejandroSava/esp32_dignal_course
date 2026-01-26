#include <stdio.h>
#include "driver/gpio.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#define LED_GPIO GPIO_NUM_2
#define BUTTON_GPIO GPIO_NUM_23

uint32_t read_button_debounced(void){
    const TickType_t debounce_delay = pdMS_TO_TICKS(50);
    int stable_state = gpio_get_level(BUTTON_GPIO);
    vTaskDelay(debounce_delay);

    int new_state = gpio_get_level(BUTTON_GPIO);
    if (stable_state == new_state)
        return new_state;
    else {
        vTaskDelay(debounce_delay);
        return(gpio_get_level(BUTTON_GPIO));
    }
}

void app_main(void)
{
    gpio_config_t io_config = {
        .pin_bit_mask = 1ULL << GPIO_NUM_2,          /*!< GPIO pin: set with bit mask, each bit maps to a GPIO */
        .mode = GPIO_MODE_OUTPUT,               /*!< GPIO mode: set input/output mode                     */
        .pull_up_en = GPIO_PULLUP_DISABLE ,       /*!< GPIO pull-up                                         */
        .pull_down_en = GPIO_PULLDOWN_DISABLE,  /*!< GPIO pull-down                                       */
        .intr_type = GPIO_INTR_DISABLE,      /*!< GPIO interrupt type                                  */

    };

    gpio_config_t input_config = {
        .pin_bit_mask = 1ULL << GPIO_NUM_23,
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = GPIO_PULLUP_DISABLE ,
        .pull_down_en = GPIO_PULLDOWN_ENABLE, //typical value 45k ohms
        .intr_type = GPIO_INTR_DISABLE, 
    };

    gpio_config(&io_config);
    gpio_config(&input_config);

    while (1)
    {
        if(read_button_debounced())
            gpio_set_level(LED_GPIO, 1);
        
        else
            gpio_set_level(LED_GPIO, 0);
    }
    
}
