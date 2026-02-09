#ifndef HMAC_SHA512_H
#define HMAC_SHA512_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/* Length of HMAC-SHA512 output in bytes */
#define HMAC_LEN 64
#define TAG_HMAC "[HMAC]"
/**
 * @brief Compute HMAC-SHA512 over a plaintext buffer.
 *
 * @param[in]  key            Pointer to secret key
 * @param[in]  key_size       Size of the key in bytes
 * @param[in]  plaintext      Pointer to input data
 * @param[in]  plaintext_len  Length of input data in bytes
 * @param[out] hmac           Output buffer (must be at least HMAC_LEN bytes)
 *
 * @return 0 on success
 * @return <0 on error
 */
int get_hmac(const uint8_t *key, size_t key_size,
             const uint8_t *plaintext, size_t plaintext_len,
             uint8_t *hmac);

/**
 * @brief Verify two HMAC values in constant time.
 *
 * @param[in] hmac_1  First HMAC buffer
 * @param[in] hmac_2  Second HMAC buffer
 * @param[in] len     Length of HMAC (use HMAC_LEN)
 *
 * @return true  if HMACs match
 * @return false if mismatch or invalid input
 */
bool verify_hmac(const uint8_t *hmac_1,
                 const uint8_t *hmac_2,
                 size_t len);

#endif /* HMAC_SHA512_H */
