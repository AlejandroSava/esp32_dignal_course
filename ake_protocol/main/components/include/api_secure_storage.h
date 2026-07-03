#ifndef API_SECURE_STORAGE
#define API_SECURE_STORAGE

#include "aes_cbc.h"
#include "hmac_sha512.h"
#include "pkcs_7.h"
#include "secure_storage_nvs.h"
#define PUF_512_HASH_LEN 64
#define API_SS_COUNTER 1

struct puf_object{
    bool init;
    size_t puf_hash_len;
    uint8_t puf_hash[PUF_512_HASH_LEN];
};


esp_err_t write_secure_storage_region(const uint8_t *plaintext, size_t plaintext_len,
                                      const char *key_name_nvs,
                                      struct aes_256_obj *self_aes,
                                      struct aes_256_obj *self_hmac);

esp_err_t read_secure_storage_region_alloc(const char *key_name_nvs,
                                           struct aes_256_obj *self_aes,
                                           struct aes_256_obj *self_hmac,
                                           uint8_t **out_plain,
                                           size_t *out_plain_len);
// bool derive_key_from_puf(uint8_t *key_output, struct puf_object *self, bool source_puf);
bool derive_aes_puf_key_from_puf(struct puf_object *puf_obj,
                                 struct aes_256_obj *aes_puf);
bool derive_hmac_puf_key_from_puf(struct puf_object *puf_obj,
                                 struct aes_256_obj *hmac_aes_puf);
bool get_puf_obj_from_puf(struct puf_object *self, bool source_puf);

#endif // API_SECURE_STORAGE
