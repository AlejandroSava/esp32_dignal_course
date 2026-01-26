#include <stdio.h>
#include "aes_cbc.h"
#include "esp_log.h"
#include "esp_system.h"          // esp_fill_random()
#include "mbedtls/aes.h"
#include "esp_random.h"

static const char *TAG = "AES_CBC";

// ----- helpers -----
static void print_hex(const char *label, const uint8_t *buf, size_t len)
{
    printf("%s (%zu bytes): ", label, len);
    for (size_t i = 0; i < len; i++) printf("%02X", buf[i]);
    printf("\n");
}


void app_main(void)
{
    // Example key (AES-128 = 16 bytes). Use a real KDF / key management in production.
    uint8_t key[32] = {
        0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
        0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
        0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
        0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81, 
    };

    // CBC needs a fresh unpredictable IV per encryption; store/transmit IV alongside ciphertext.
    uint8_t iv[16];
    esp_fill_random(iv, sizeof(iv));

    char *msg = "Hello ESP32! AES-CBC with PKCS#7 padding Espero que esten bien y tenga el gusto de conocerme";
    uint8_t *plaintext = (uint8_t *)msg;
    size_t plaintext_len = strlen(msg);

    uint8_t *ciphertext = NULL;
    size_t ciphertext_len = 0;

    ESP_LOGI(TAG, "Plaintext: %s", msg);
    print_hex("IV", iv, 16);
    print_hex("KEY", key, sizeof(key));

    int ret = aes_cbc_encrypt_pkcs7(key, 256, iv, plaintext, plaintext_len, &ciphertext, &ciphertext_len);
    if (ret != 0) {
        ESP_LOGE(TAG, "Encrypt failed: -0x%04X", (unsigned)(-ret));
        return;
    }

    print_hex("CIPHERTEXT", ciphertext, ciphertext_len);

    // IMPORTANT: for decryption use the *same original IV*. Since our encrypt function copied iv_in,
    // iv[] still contains the original IV. In real usage, you would send/store IV with ciphertext.
    uint8_t *decrypted = NULL;
    size_t decrypted_len = 0;

    ret = aes_cbc_decrypt_pkcs7(key, 256, iv, ciphertext, ciphertext_len, &decrypted, &decrypted_len);
    free(ciphertext);

    if (ret != 0) {
        ESP_LOGE(TAG, "Decrypt failed: -0x%04X", (unsigned)(-ret));
        return;
    }

    ESP_LOGI(TAG, "Decrypted (%zu bytes): %s", decrypted_len, (char *)decrypted);
    free(decrypted);
}
