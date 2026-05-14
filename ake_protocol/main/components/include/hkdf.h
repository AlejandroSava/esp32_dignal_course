#ifndef HKDF_H
#define HKDF_H

#include <stdio.h>
#include <stdbool.h>

#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include "esp_log.h"

#define TAG_HKDF "[HKDF-SHA512]"
bool derive_hkdf_sha512(const uint8_t *ikm, size_t ikm_len,
                        const uint8_t *salt, size_t salt_len,
                        const uint8_t *info, size_t info_len,
                        uint8_t *okm, size_t okm_len);

#endif