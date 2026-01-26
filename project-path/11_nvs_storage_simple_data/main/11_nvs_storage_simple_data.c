#include <stdio.h>
#include <string.h>
#include "esp_log.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "esp_err.h"      // esp_err_t, ESP_OK, esp_err_to_name()
#include "esp_log.h"      // ESP_LOGE()

#define TAG_NVS "[NVS_LOG]"

void app_main(void){
    esp_err_t err_nvs;
    ESP_LOGI(TAG_NVS, "--- INIT THE  NVS ---");
    err_nvs = nvs_flash_init(); //init the nvs flash
    if (err_nvs != ESP_OK) {
        ESP_LOGE(TAG_NVS, "NVS init failed: %s", esp_err_to_name(err_nvs));
    }

    ESP_LOGI(TAG_NVS, "--- OPENING THE  NVS ---");
    nvs_handle_t nvs_handle; // non-volatile storage handle
    nvs_open("storage", NVS_READWRITE, &nvs_handle);

    // GET THE VALUE:
    ESP_LOGI(TAG_NVS, "--- GETTING THE VALUE FROM NVS ---");
    int32_t val = 0;
    err_nvs = nvs_get_i32(nvs_handle, "val",&val);
    if (err_nvs != ESP_OK) {
        ESP_LOGE(TAG_NVS, "NVS get i32 failed: %s", esp_err_to_name(err_nvs));
    }
    ESP_LOGI(TAG_NVS, "+++ The value is %d:", val);

    // SET THE VALUE:
    ESP_LOGI(TAG_NVS, "--- SETTING THE VALUE FROM NVS ---");
    val++; // increment the val after reading
    ESP_ERROR_CHECK(nvs_set_i32(nvs_handle, "val", val));

    // Commit THE VALUE:
    ESP_LOGI(TAG_NVS, "--- COMMITTING THE VALUE FROM NVS ---");
    err_nvs = nvs_commit(nvs_handle);
    if (err_nvs != ESP_OK) {
        ESP_LOGE(TAG_NVS, "NVS commit failed: %s", esp_err_to_name(err_nvs));
    }
    
    // Close THE VALUE:
    ESP_LOGI(TAG_NVS, "--- CLOSE THE VALUE FROM NVS ---");
    nvs_close(nvs_handle);
    

    //vTaskDelay (2000 / portTICK_PERIOD_MS);

}
