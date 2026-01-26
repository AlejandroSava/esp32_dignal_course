#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "esp_log.h"
#include "mbedtls/md.h"
#include "mbedtls/hkdf.h"

static const char *TAG = "HKDF";

/* Helper: print buffer in hex */
static void print_hex(const char *label, const uint8_t *buf, size_t len)
{
    printf("%s (%zu): ", label, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

/* HKDF-SHA256 wrapper */
static int hkdf_sha256(const uint8_t *salt, size_t salt_len,
                       const uint8_t *ikm,  size_t ikm_len,
                       const uint8_t *info, size_t info_len,
                       uint8_t *okm, size_t okm_len)
{
    const mbedtls_md_info_t *md =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    if (md == NULL) {
        return -1;
    }

    return mbedtls_hkdf(md,
                        salt, salt_len,
                        ikm,  ikm_len,
                        info, info_len,
                        okm,  okm_len);
}

/* ===== ESP-IDF entry point ===== */
void app_main(void)
{
    ESP_LOGI(TAG, "HKDF-SHA256 example starting");

    /* Input Keying Material (IKM) */
    uint8_t ikm[32] = {
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
        0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
        0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f
    };

    /* Salt (nonce / randomness / context) */
    uint8_t salt[16] = {
        0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,
        0xa8,0xa9,0xaa,0xab,0xac,0xad,0xae,0xaf
    };

    /* ---- Derive Ksess ---- */
    const uint8_t info_sess[] = "ESP32-IoT|Ksess|v1";
    uint8_t Ksess[32];

    int ret = hkdf_sha256(salt, sizeof(salt),
                          ikm, sizeof(ikm),
                          info_sess, sizeof(info_sess) - 1,
                          Ksess, sizeof(Ksess));

    if (ret != 0) {
        ESP_LOGE(TAG, "HKDF Ksess failed: -0x%04x", (unsigned)-ret);
        return;
    }

    /* ---- Derive Kauth ---- */
    const uint8_t info_auth[] = "ESP32-IoT|Kauth|v1";
    uint8_t Kauth[32];

    ret = hkdf_sha256(salt, sizeof(salt),
                      ikm, sizeof(ikm),
                      info_auth, sizeof(info_auth) - 1,
                      Kauth, sizeof(Kauth));

    if (ret != 0) {
        ESP_LOGE(TAG, "HKDF Kauth failed: -0x%04x", (unsigned)-ret);
        return;
    }

    /* Print results */
    print_hex("Ksess", Ksess, sizeof(Ksess));
    print_hex("Kauth", Kauth, sizeof(Kauth));

    /* Optional: zero secrets */
    memset(ikm,  0, sizeof(ikm));
    memset(Ksess,0, sizeof(Ksess));
    memset(Kauth,0, sizeof(Kauth));

    ESP_LOGI(TAG, "HKDF example finished");
}
