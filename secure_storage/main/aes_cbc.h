#ifndef AES_CBC_H
#define AES_CBC_H

#include <stddef.h>   // size_t
#include <stdint.h>   // uint8_t



int aes_cbc_encrypt_pkcs7(const uint8_t *key, unsigned keybits,
                          const uint8_t iv_in[16],
                          const uint8_t *plaintext, size_t plaintext_len,
                          uint8_t **ciphertext, size_t *ciphertext_len);

int aes_cbc_decrypt_pkcs7(const uint8_t *key, unsigned keybits,
                          const uint8_t iv_in[16],
                          const uint8_t *ciphertext, size_t ciphertext_len,
                          uint8_t **plaintext, size_t *plaintext_len);

#endif // AES_CBC_H
