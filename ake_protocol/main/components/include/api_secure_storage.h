#ifndef API_SECURE_STORAGE
#define API_SECURE_STORAGE

#include "aes_cbc.h"
#include "aes_cbc.h"
#include "hmac_sha512.h"
#include "pkcs_7.h"
#include "secure_storage_nvs.h"
#define PUF_HASH_LEN 64

struct puf_object{
    bool init;
    size_t puf_hash_len;
    uint8_t hash[PUF_HASH_LEN];
};


esp_err_t write_secure_storage_region(const uint8_t *plaintext, size_t plaintext_len,
                                      const char *key_name_nvs,
                                      struct aes_256_obj *self_aes);


esp_err_t read_secure_storage_region_alloc(const char *key_name_nvs,
                                           struct aes_256_obj *self_aes,
                                           uint8_t **out_plain,
                                           size_t *out_plain_len);
bool derive_key_from_puf(uint8_t *key_output, struct puf_object *self, bool source_puf);
#endif // API_SECURE_STORAGE
