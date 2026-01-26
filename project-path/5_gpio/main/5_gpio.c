#include <stdio.h>
#include "driver/gpio.h"
#include "freertos/FreeRTOS.h"

#define LED_GPIO GPIO_NUM_2

void app_main(void)
{
    gpio_config_t io_config = {
        .pin_bit_mask = 1ULL << GPIO_NUM_2,          /*!< GPIO pin: set with bit mask, each bit maps to a GPIO */
        .mode = GPIO_MODE_OUTPUT,               /*!< GPIO mode: set input/output mode                     */
        .pull_up_en = GPIO_PULLUP_DISABLE ,       /*!< GPIO pull-up                                         */
        .pull_down_en = GPIO_PULLDOWN_DISABLE,  /*!< GPIO pull-down                                       */
        .intr_type = GPIO_INTR_DISABLE,      /*!< GPIO interrupt type                                  */

    };

    gpio_config(&io_config);

    while (1)
    {
       gpio_set_level(LED_GPIO, 1);
       vTaskDelay(pdMS_TO_TICKS(1000));
       gpio_set_level(LED_GPIO, 0);
       vTaskDelay(pdMS_TO_TICKS(1000));
    }
    
}
