#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "mbedtls/base64.h"
#include "cJSON.h"

// ---------- Base64 helpers ----------
static int b64_encode_alloc(const uint8_t *in, size_t in_len, char **out_str)
{
    if (!in || !out_str) return -1;

    size_t out_max = 4 * ((in_len + 2) / 3) + 1; // +1 for '\0'
    char *buf = malloc(out_max);
    if (!buf) return -2;

    size_t out_len = 0;
    int ret = mbedtls_base64_encode((unsigned char *)buf, out_max,
                                   &out_len,
                                   (const unsigned char *)in, in_len);
    if (ret != 0) { free(buf); return -3; }

    buf[out_len] = '\0';
    *out_str = buf;
    return 0;
}

static int b64_decode_alloc(const char *in_str, uint8_t **out, size_t *out_len)
{
    if (!in_str || !out || !out_len) return -1;

    size_t in_len = strlen(in_str);

    // Query required size (mbedTLS returns BUFFER_TOO_SMALL with needed length)
    size_t needed = 0;
    int ret = mbedtls_base64_decode(NULL, 0, &needed,
                                   (const unsigned char *)in_str, in_len);
    if (ret != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) return -2;

    uint8_t *buf = malloc(needed);
    if (!buf) return -3;

    size_t wrote = 0;
    ret = mbedtls_base64_decode(buf, needed, &wrote,
                               (const unsigned char *)in_str, in_len);
    if (ret != 0) { free(buf); return -4; }

    *out = buf;
    *out_len = wrote;
    return 0;
}

// ---------- Demo: IV -> Base64 -> JSON -> Base64 -> IV ----------
void app_main(void)
{
    // Example AES IV (16 bytes)
    uint8_t iv[16] = {
        0x00, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB,
        0xCC, 0xDD, 0xEE, 0xFF
    };

    // Print decoded IV (hex)
    printf("IV: ");
    for (int i = 0; i < 16; i++)
        printf("%02X", iv[i]);
    printf("\n");

    // 1) Encode IV to Base64
    char *iv_b64 = NULL;
    if (b64_encode_alloc(iv, sizeof(iv), &iv_b64) != 0) {
        printf("Base64 encode failed\n");
        return;
    }

    // 2) Put it in JSON
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "iv_b64", iv_b64);
    cJSON_AddNumberToObject(root, "iv_len", (int)sizeof(iv)); // optional sanity check

    char *json_str = cJSON_Print(root);
    printf("JSON to send: %s\n", json_str);

    // Cleanup objects used for sending
    cJSON_Delete(root);
    free(iv_b64);

    // ---- Imagine json_str is received back from HTTP response or server ----

    // 3) Parse JSON
    cJSON *rx = cJSON_Parse(json_str);
    free(json_str); // json_str no longer needed after parsing

    if (!rx) {
        printf("JSON parse failed\n");
        return;
    }

    cJSON *iv_b64_item = cJSON_GetObjectItem(rx, "iv_b64");
    cJSON *iv_len_item = cJSON_GetObjectItem(rx, "iv_len");

    if (!cJSON_IsString(iv_b64_item) || (iv_b64_item->valuestring == NULL)) {
        printf("Missing iv_b64\n");
        cJSON_Delete(rx);
        return;
    }

    // Optional check: ensure we expect a 16-byte IV
    if (cJSON_IsNumber(iv_len_item) && iv_len_item->valueint != 16) {
        printf("Unexpected iv_len: %d\n", iv_len_item->valueint);
        cJSON_Delete(rx);
        return;
    }

    // 4) Decode Base64 back to bytes
    uint8_t *iv_dec = NULL;
    size_t iv_dec_len = 0;

    if (b64_decode_alloc(iv_b64_item->valuestring, &iv_dec, &iv_dec_len) != 0) {
        printf("Base64 decode failed\n");
        cJSON_Delete(rx);
        return;
    }

    if (iv_dec_len != 16) {
        printf("Decoded IV length is %d, expected 16\n", (int)iv_dec_len);
        free(iv_dec);
        cJSON_Delete(rx);
        return;
    }

    // Print decoded IV (hex)
    printf("Decoded IV: ");
    for (int i = 0; i < 16; i++) printf("%02X", iv_dec[i]);
    printf("\n");

    // Cleanup
    free(iv_dec);
    cJSON_Delete(rx);
}
