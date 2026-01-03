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
