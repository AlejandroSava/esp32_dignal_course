#include <string.h>
#include <stdio.h>

#include "esp_log.h"
#include "mbedtls/md.h"
#define HMAC_LEN 64
static const char *TAG = "HMAC512";



int get_hmac(const uint8_t *key, size_t key_size,
             const uint8_t *plaintext, size_t plaintext_len,
             uint8_t *hmac)
{
    if (!key || !plaintext || !hmac) return -1;
    if (key_size == 0) return -2;

    int ret = 0;

    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
    if (!md) {
        ESP_LOGE(TAG, "SHA-512 not available");
        return -3;
    }

    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);

    ret = mbedtls_md_setup(&ctx, md, 1);
    if (ret != 0) { ESP_LOGE(TAG, "md_setup failed: %d", ret); goto cleanup; }

    ret = mbedtls_md_hmac_starts(&ctx, key, key_size);
    if (ret != 0) { ESP_LOGE(TAG, "hmac_starts failed: %d", ret); goto cleanup; }

    ret = mbedtls_md_hmac_update(&ctx, plaintext, plaintext_len);
    if (ret != 0) { ESP_LOGE(TAG, "hmac_update failed: %d", ret); goto cleanup; }

    ret = mbedtls_md_hmac_finish(&ctx, hmac);
    if (ret != 0) { ESP_LOGE(TAG, "hmac_finish failed: %d", ret); goto cleanup; }

    ESP_LOGI(TAG, "HMAC Success");
    ret = 0;

cleanup:
    mbedtls_md_free(&ctx);
    return ret;
}


bool verify_hmac(const uint8_t *hmac_1, const uint8_t *hmac_2, size_t len)
{
    if (!hmac_1 || !hmac_2) return false;

    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= (uint8_t)(hmac_1[i] ^ hmac_2[i]);
    }

    if (diff != 0) {
        ESP_LOGE(TAG, "HMAC Mismatch");
        return false;
    }

    ESP_LOGI(TAG, "HMAC Verification Success");
    return true;
}


/* Utility to print hex */
static void print_hex(const char *label, const uint8_t *buf, size_t len)
{
    printf("%s (%u bytes): ", label, (unsigned)len);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}
void app_main(void)
{
    /* Example secret key (replace with PUF / HKDF output) */
    uint8_t key[] = {
        0x10,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
        0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x01
    };

    /* Example message */
    uint8_t msg[] = "Secure Storage";

    uint8_t mac[HMAC_LEN];  // SHA-512 output size

    printf("size of msg: %u", sizeof(msg));

    int mac_status = get_hmac(&key[0], sizeof(key), &msg[0], sizeof(msg)-1, &mac[0]);
    if (mac_status == 0)
        print_hex("HMAC-SHA512", mac, sizeof(mac));

    printf("HMAC are equal: %s\n", verify_hmac(&mac[0], &mac[0], HMAC_LEN) ? "true" : "false");
}
