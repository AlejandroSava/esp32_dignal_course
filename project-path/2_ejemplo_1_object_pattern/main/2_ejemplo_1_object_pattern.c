#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "led_controller.h"


void app_main(void)
{   
    // create the instance
    struct led_controller led_buildin;
    // init the object
    led_controller_init(&led_buildin, 2);

    //
    led_controller_turn_on(&led_buildin);

    led_controller_update_period(&led_buildin, 3);

    while(true){
        led_controller_blink(&led_buildin);
    }

    led_controller_deinit(&led_buildin);
}
