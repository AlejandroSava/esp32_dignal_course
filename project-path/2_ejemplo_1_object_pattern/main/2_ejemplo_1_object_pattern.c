#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "led_controller.h"


void app_main(void)
{
    struct led_controller led_buildin;
    led_controller_init(&led_buildin, 2);
    led_controller_turn_on(&led_buildin);

}
