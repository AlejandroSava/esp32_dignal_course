#include "led_controller.h"
#include "driver/gpio.h"
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
int led_controller_init(struct led_controller *self, uint8_t gpio_pin){
// return 0 sucess, -1 fail
/*
How works memset, memset is a standard C library function used to fill a block of memory with a byte value.
#include <string.h>
void *memset(void *ptr, int value, size_t num);
ptr → pointer to the memory block you want to fill
value → the byte value to write (converted to unsigned char)
num → number of bytes to set
*/
    memset(self, 0, sizeof(*self));
    self->gpio_pin = gpio_pin;
    self->is_on = 0;
    self->blink_period = 0;
    self->last_toggle = 0;

    // Configure the GPIO PIN
    gpio_config_t io_config = {
        .pin_bit_mask = (1ULL << gpio_pin), // 1ULL (Unsigned Long Long) 64 bits
        .mode = GPIO_MODE_OUTPUT,
        .pull_up_en = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE // ninguna interrupcion

    };
    /*
    Structure of the gpio_config_t
    uint64_t pin_bit_mask;          //!< GPIO pin: set with bit mask, each bit maps to a GPIO /
    gpio_mode_t mode;               //!< GPIO mode: set input/output mode                     /
    gpio_pullup_t pull_up_en;       //!< GPIO pull-up                                         /
    gpio_pulldown_t pull_down_en;   //!< GPIO pull-down                                       /
    gpio_int_type_t intr_type;      //!< GPIO interrupt type    /
    
    */

    esp_err_t handler_gpio = gpio_config(&io_config);
    if (handler_gpio != ESP_OK)
        return -1;
    
    // start in low level
    gpio_set_level(self->gpio_pin, 0);

    return 0; 

}

int led_controller_deinit(struct led_controller *self){
    // turn off led
    led_controller_turn_off(self);
    
    // reseet GPIO to input mode
    gpio_reset_pin(self->gpio_pin);

    // clear the strcture
    memset(self, 0, sizeof(*self));

    return 0;
}


void led_controller_turn_on(struct led_controller *self){
    self->is_on = true;
    gpio_set_level(self->gpio_pin, self->is_on);
}

/*
turn off the led
*/
void led_controller_turn_off(struct led_controller *self){
    self->is_on = false;
    gpio_set_level(self->gpio_pin, self->is_on);
}


void led_controller_toggle(struct led_controller *self){
    if(self->is_on == true){
        led_controller_turn_off(self);
        self->last_toggle = 1;
    }
    else{
        led_controller_turn_on(self);
        self->last_toggle = 0;
    }
}


void led_controller_set_blink_period(struct led_controller *self, uint32_t blink_period_ms){
    self->blink_period = blink_period_ms;
}

void led_controller_update_period(struct led_controller *self, uint32_t update_period_ms){
    self->blink_period = update_period_ms;
}

void led_controller_blink(struct led_controller *self){
    vTaskDelay(self->blink_period * 1000 / portTICK_PERIOD_MS);
    led_controller_toggle(self);
    vTaskDelay(self->blink_period * 1000 / portTICK_PERIOD_MS);
    led_controller_toggle(self);

}