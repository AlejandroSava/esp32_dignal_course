#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"
#include "esp_log.h"

void sha256_stream(const uint8_t *data, size_t len, uint8_t out[32])
{
    mbedtls_sha256_context ctx;

    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);   // 0 = SHA-256
    mbedtls_sha256_update(&ctx, data, len);
    mbedtls_sha256_finish(&ctx, out);
    mbedtls_sha256_free(&ctx);
}


void sha512_stream(const uint8_t *data, size_t len, uint8_t out[64])
{
    mbedtls_sha512_context ctx;

    mbedtls_sha512_init(&ctx);
    mbedtls_sha512_starts(&ctx, 0);   // 0 = SHA-512
    mbedtls_sha512_update(&ctx, data, len);
    mbedtls_sha512_finish(&ctx, out);
    mbedtls_sha512_free(&ctx);
}


void print_hex(const char *tag, const uint8_t *buf, size_t len)
{
    char hex[2*len + 1]; //size in digest, remember that a byte is represented by 2 digest
    for (size_t i = 0; i < len; i++) {
        static const char *h = "0123456789abcdef";
        hex[2*i]     = h[(buf[i] >> 4) & 0xF]; // the highest bit shift four bits
        hex[2*i + 1] = h[buf[i] & 0xF];
    }
    hex[2*len] = 0; //Null terminator
    ESP_LOGI(tag, "%s", hex);
}



void app_main(void)
{
    printf("hi everyone!\n");
    
    const char *msg = "hello esp32";

    uint8_t h256[32], h512[64];
    sha256_stream((const uint8_t *)msg, strlen(msg), h256);
    sha512_stream((const uint8_t *)msg, strlen(msg), h512);

    print_hex("SHA256", h256, sizeof(h256));
    print_hex("SHA512", h512, sizeof(h512));
    }

/**
 * @brief Remove PKCS#7 padding for AES (16-byte block size).
 *
 * Input must be a multiple of 16 bytes (AES block size).
 * Valid PKCS#7 padding values for AES: 1..16.
 *
 * Output buffer is allocated with malloc; caller must free().
 *
 * @param[in]  input       Decrypted data that still contains PKCS#7 padding
 * @param[in]  input_len   Length of input in bytes (must be multiple of 16)
 * @param[out] output      Pointer to allocated plaintext buffer (no padding)
 * @param[out] output_len  Plaintext length (without padding)
 *
 * @return  0  Success
 * @return -1  Invalid arguments (NULL pointers)
 * @return -2  Invalid length (0 or not multiple of 16)
 * @return -3  Invalid padding length byte (must be 1..16)
 * @return -4  Padding bytes do not match expected PKCS#7 pattern
 * @return -5  Memory allocation failure
 */
static int pkcs7_unpad_16(const uint8_t *input,
                          size_t input_len,
                          uint8_t **output,
                          size_t *output_len)
{
    // 1) Basic argument validation
    if (input == NULL || output == NULL || output_len == NULL) {
        return -1;
    }

    // 2) AES-CBC plaintext after decryption must be block-aligned (16 bytes)
    if (input_len == 0 || (input_len % 16) != 0) {
        return -2;
    }

    // 3) The last byte indicates how many padding bytes were added (PKCS#7)
    uint8_t pad = input[input_len - 1];

    // 4) For AES block size 16, valid padding length is 1..16
    if (pad == 0 || pad > 16) {
        return -3;
    }

    // 5) Validate that the last 'pad' bytes all equal 'pad'
    //    Example: if pad=0x04, the last 4 bytes must be 04 04 04 04
    for (size_t i = 0; i < (size_t)pad; i++) {
        if (input[input_len - 1 - i] != pad) {
            return -4;
        }
    }

    // 6) Compute length without padding
    size_t plain_len = input_len - (size_t)pad;

    // 7) Allocate output (+1 optional null terminator for debugging prints)
    uint8_t *buf = (uint8_t *)malloc(plain_len + 1);
    if (buf == NULL) {
        return -5;
    }

    // 8) Copy only plaintext
    memcpy(buf, input, plain_len);

    // 9) Add null terminator for convenience (safe for printing)
    buf[plain_len] = 0;

    // 10) Return outputs
    *output = buf;
    *output_len = plain_len;

    return 0;
}
