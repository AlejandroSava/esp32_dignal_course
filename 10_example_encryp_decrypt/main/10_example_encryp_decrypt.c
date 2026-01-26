// ESP-IDF example: AES-CBC encrypt/decrypt with mbedTLS + PKCS#7 padding
// Build as an ESP-IDF project (main/main.c)

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

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

// PKCS#7 padding: pad to multiple of 16 bytes (AES block size).
// output buffer is malloc'd; caller must free().
static int pkcs7_pad_16(const uint8_t *in, size_t in_len, uint8_t **out, size_t *out_len)
{
    if (!in || !out || !out_len) return -1;

    size_t pad = 16 - (in_len % 16);
    if (pad == 0) pad = 16;

    size_t total = in_len + pad;
    uint8_t *buf = (uint8_t *)malloc(total);
    if (!buf) return -2;

    memcpy(buf, in, in_len);
    memset(buf + in_len, (uint8_t)pad, pad);

    *out = buf;
    *out_len = total;
    return 0;
}

// PKCS#7 unpadding: validates and returns plaintext length.
// output buffer is malloc'd; caller must free().
static int pkcs7_unpad_16(const uint8_t *in, size_t in_len, uint8_t **out, size_t *out_len)
{
    if (!in || !out || !out_len) return -1;
    if (in_len == 0 || (in_len % 16) != 0) return -2;

    uint8_t pad = in[in_len - 1];
    if (pad == 0 || pad > 16) return -3;

    // Validate padding bytes
    for (size_t i = 0; i < pad; i++) {
        if (in[in_len - 1 - i] != pad) return -4;
    }

    size_t plain_len = in_len - pad;
    uint8_t *buf = (uint8_t *)malloc(plain_len + 1); // +1 for '\0' convenience
    if (!buf) return -5;

    memcpy(buf, in, plain_len);
    buf[plain_len] = 0;

    *out = buf;
    *out_len = plain_len;
    return 0;
}

// AES-CBC encrypt:
// - keybits: 128/192/256 (bits) :contentReference[oaicite:4]{index=4}
// - iv is 16 bytes and MUST be saved for decryption (CBC needs the same IV).
// AES-CBC encrypt + PKCS#7 padding
static int aes_cbc_encrypt_pkcs7(
    const uint8_t *key, unsigned keybits,
    const uint8_t iv_in[16],
    const uint8_t *plaintext, size_t plaintext_len,
    uint8_t **ciphertext, size_t *ciphertext_len)
{
    int ret = 0;
    mbedtls_aes_context aes;
    uint8_t iv[16];
    uint8_t *padded = NULL;
    size_t padded_len = 0;

    if (!key || !iv_in || !plaintext || !ciphertext || !ciphertext_len) return -1;

    ret = pkcs7_pad_16(plaintext, plaintext_len, &padded, &padded_len);
    if (ret != 0) return ret;

    uint8_t *out = (uint8_t *)malloc(padded_len);
    if (!out) { free(padded); return -2; }

    memcpy(iv, iv_in, 16);

    mbedtls_aes_init(&aes);

    ret = mbedtls_aes_setkey_enc(&aes, key, keybits);
    if (ret != 0) { mbedtls_aes_free(&aes); free(padded); free(out); return ret; }

    ret = mbedtls_aes_crypt_cbc(&aes,
                                MBEDTLS_AES_ENCRYPT,
                                padded_len,
                                iv,
                                padded,
                                out);
    mbedtls_aes_free(&aes);
    free(padded);

    if (ret != 0) { free(out); return ret; }

    *ciphertext = out;
    *ciphertext_len = padded_len;
    return 0;
}

// AES-CBC decrypt + PKCS#7 unpad
static int aes_cbc_decrypt_pkcs7(
    const uint8_t *key, unsigned keybits,
    const uint8_t iv_in[16],
    const uint8_t *ciphertext, size_t ciphertext_len,
    uint8_t **plaintext, size_t *plaintext_len)
{
    int ret = 0;
    mbedtls_aes_context aes;
    uint8_t iv[16];

    if (!key || !iv_in || !ciphertext || !plaintext || !plaintext_len) return -1;
    if (ciphertext_len == 0 || (ciphertext_len % 16) != 0) return -2;

    uint8_t *tmp = (uint8_t *)malloc(ciphertext_len);
    if (!tmp) return -3;

    memcpy(iv, iv_in, 16);

    mbedtls_aes_init(&aes);

    ret = mbedtls_aes_setkey_dec(&aes, key, keybits);
    if (ret != 0) { mbedtls_aes_free(&aes); free(tmp); return ret; }

    ret = mbedtls_aes_crypt_cbc(&aes,
                                MBEDTLS_AES_DECRYPT,
                                ciphertext_len,
                                iv,
                                ciphertext,
                                tmp);
    mbedtls_aes_free(&aes);

    if (ret != 0) { free(tmp); return ret; }

    uint8_t *out = NULL;
    size_t out_len = 0;
    ret = pkcs7_unpad_16(tmp, ciphertext_len, &out, &out_len);
    free(tmp);

    if (ret != 0) return ret;

    *plaintext = out;
    *plaintext_len = out_len;
    return 0;
}


void app_main(void)
{
    // Example key (AES-128 = 16 bytes). Use a real KDF / key management in production.
    uint8_t key[16] = {
        0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
        0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81
    };

    // CBC needs a fresh unpredictable IV per encryption; store/transmit IV alongside ciphertext.
    uint8_t iv[16];
    esp_fill_random(iv, sizeof(iv));

    const char *msg = "Hello ESP32! AES-CBC with PKCS#7 padding Espero que esten bien";
    const uint8_t *plaintext = (const uint8_t *)msg;
    size_t plaintext_len = strlen(msg);

    uint8_t *ciphertext = NULL;
    size_t ciphertext_len = 0;

    ESP_LOGI(TAG, "Plaintext: %s", msg);
    print_hex("IV", iv, 16);
    print_hex("KEY", key, sizeof(key));

    int ret = aes_cbc_encrypt_pkcs7(key, 128, iv, plaintext, plaintext_len, &ciphertext, &ciphertext_len);
    if (ret != 0) {
        ESP_LOGE(TAG, "Encrypt failed: -0x%04X", (unsigned)(-ret));
        return;
    }

    print_hex("CIPHERTEXT", ciphertext, ciphertext_len);

    // IMPORTANT: for decryption use the *same original IV*. Since our encrypt function copied iv_in,
    // iv[] still contains the original IV. In real usage, you would send/store IV with ciphertext.
    uint8_t *decrypted = NULL;
    size_t decrypted_len = 0;

    ret = aes_cbc_decrypt_pkcs7(key, 128, iv, ciphertext, ciphertext_len, &decrypted, &decrypted_len);
    free(ciphertext);

    if (ret != 0) {
        ESP_LOGE(TAG, "Decrypt failed: -0x%04X", (unsigned)(-ret));
        return;
    }

    ESP_LOGI(TAG, "Decrypted (%zu bytes): %s", decrypted_len, (char *)decrypted);
    free(decrypted);
}
