#include <stdio.h>
#include "esp_random.h"
#include "esp_log.h"
#include "base64.h"

void app_main(void)
{
    size_t iv_lenght = 16;
    uint8_t iv[iv_lenght];
    char *iv_b64 = NULL;
    esp_fill_random(iv, 16);
    ESP_LOG_BUFFER_HEXDUMP("IV FORMAT", iv, iv_lenght, ESP_LOG_INFO);

    if (base64_encode_alloc(iv, iv_lenght, &iv_b64) == 0) {
        ESP_LOGI("B64", "IV(b64): %s", iv_b64);        
    }
    

    uint8_t *iv_recovered = NULL;
    size_t iv_size_recovered;

    if (base64_decode_alloc(iv_b64, &iv_recovered, &iv_size_recovered) == 0) {
        ESP_LOGI("B64", "Decoded bytes: %u", (unsigned)iv_size_recovered);
        /* validate pk_len == CRYPTO_PUBLICKEYBYTES, etc. */
    }

    ESP_LOG_BUFFER_HEXDUMP("IV FORMAT RECOVERED", iv_recovered, iv_size_recovered, ESP_LOG_INFO);
    free(iv_b64); //remember to free memory
    free(iv_recovered);
}
