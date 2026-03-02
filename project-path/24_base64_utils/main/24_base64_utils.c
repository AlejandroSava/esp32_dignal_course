#include <stdio.h>
#include "esp_random.h"
#include "esp_log.h"
#include "base64.h"
#include "cJSON.h"
#include "nvs_flash.h"
#include "wifi.h"
//#include "http_transactions.h"


void app_main(void)
{   
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ESP_ERROR_CHECK(nvs_flash_init());
    }

    wifi_init_sta();
    char *device_name = "Alex_ESP32";
    size_t iv_lenght = 16;
    uint8_t iv[iv_lenght];
    char *iv_b64 = NULL;

    size_t puf_hash_lenght = 64;
    uint8_t puf_hash[puf_hash_lenght];
    char *puf_hash_b64 = NULL;

    // IV Vector
    esp_fill_random(iv, iv_lenght);
    ESP_LOG_BUFFER_HEXDUMP("IV FORMAT", iv, iv_lenght, ESP_LOG_INFO);

    if (base64_encode_alloc(iv, iv_lenght, &iv_b64) == 0) {
        ESP_LOGI("B64", "IV(b64): %s", iv_b64);        
    }

    // HASh PUF
    esp_fill_random(puf_hash, puf_hash_lenght);
    ESP_LOG_BUFFER_HEXDUMP("PUF HASH", puf_hash, puf_hash_lenght, ESP_LOG_INFO);

    if (base64_encode_alloc(puf_hash, puf_hash_lenght, &puf_hash_b64) == 0) {
        ESP_LOGI("B64", "PUF_HASH(b64): %s", puf_hash_b64);        
    }

    cJSON *root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "Step", 0);
    cJSON_AddStringToObject(root, "DeviceID", device_name);     
    cJSON_AddNumberToObject(root, "IV_size", iv_lenght);
    cJSON_AddStringToObject(root, "IV", iv_b64);
    cJSON_AddNumberToObject(root, "Hash_size", puf_hash_lenght);
    cJSON_AddStringToObject(root, "Hash", puf_hash_b64); 

    char *json_string = cJSON_Print(root);
    printf("%s\n", json_string);
    

    // Free Memory
    cJSON_Delete(root);
    free(json_string);

}
