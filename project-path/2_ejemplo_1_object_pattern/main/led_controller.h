#ifndef LED_CONTROLLER_H
#define LED_CONTROLLER_H

#include <stdint.h>
#include <stdbool.h>

/*
Led object structure
Join all the fields of the leds

*/

struct led_controller{
    uint8_t gpio_pin;
    bool is_on;
    uint32_t blink_period;
    uint32_t last_toggle; // last time of change
};


/*
start the led object
*/
int led_controller_init(struct led_controller *self, uint8_t gpio_pin);

/*
unitialized the object
*/
int led_controller_deinit(struct led_controller *self);

/*
turn on the led
*/
int led_controller_turn_on(struct led_controller *self);

/*
turn off the led
*/
int led_controller_turn_off(struct led_controller *self);

/*
toggle of the led
*/
int led_controller_toggle(struct led_controller *self, uint32_t last_toggle);

/*
change the led period
*/
int led_controller_toggle(struct led_controller *self, uint32_t blink_period_ms);

#endif