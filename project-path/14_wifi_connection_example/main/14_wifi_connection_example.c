#include <string.h>
#include <stdio.h>

#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "wifi.h"


void app_main(void)
{
    // NVS is required by Wi-Fi
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ESP_ERROR_CHECK(nvs_flash_init());
    }

    wifi_init_sta();
}
