#include <stdio.h>
#include <stdbool.h>

#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include "esp_log.h"
#include "hkdf.h"

bool derive_hkdf_sha512(const uint8_t *ikm, size_t ikm_len,
                        const uint8_t *salt, size_t salt_len,
                        const uint8_t *info, size_t info_len,
                        uint8_t *okm, size_t okm_len)
{
    if (ikm == NULL || ikm_len == 0 || okm == NULL || okm_len == 0) {
        ESP_LOGE(TAG_HKDF, "Invalid HKDF input parameters");
        return false;
    }

    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
    if (md == NULL) {
        ESP_LOGE(TAG_HKDF, "SHA-512 not available");
        return false;
    }

    int ret = mbedtls_hkdf(md,
                           salt, salt_len,
                           ikm, ikm_len,
                           info, info_len,
                           okm, okm_len);

    if (ret != 0) {
        ESP_LOGE(TAG_HKDF, "mbedtls_hkdf failed: -0x%04X", (unsigned)(-ret));
        return false;
    }

    ESP_LOGI(TAG_HKDF, "SUCESS HMAC Derivation");
    return true;
}