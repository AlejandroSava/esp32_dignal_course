#include <stdio.h>
#include <stdbool.h>


#include "esp_random.h"
#include "esp_log.h"
#include "base64.h"
#include "cJSON.h"
#include "wifi.h"
#include "nvs_flash.h"
#include "http_transactions.h"
#include "esp_system.h"
#include "esp_mac.h"

#include "indcpa.h"
#include "kem.h"

#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"

#include "api_secure_storage.h"
#define DEVICE_NAME "Alex_ESP32"
#define TAG_PROT "[AKE PROTOCOL]"
#define KSESS_LEN 32


struct request_step_0{
    int step;
    const char *device_name; 
    size_t device_mac_size;
    uint8_t *device_mac;
    size_t puf_hash_size;
    uint8_t *puf_hash;

    /* base 64 params*/
    char *device_mac_b64;
    char *puf_hash_b64;
    char *http_address;
};

struct response_step_0{
    int step;
    char *server_name; // where is used it? 
    size_t kyber_pk_len;
    uint8_t *kyber_pk;
};

struct request_step_1{
    int step;
    const char *device_name; 
    char *http_address;
};

struct response_step_1{
    int step;
    const char *server_name; 
    size_t sid_len;
    uint8_t *sid;
    size_t nonce_len;
    uint8_t * nonce;
};

struct request_step_2{
    int step;
    size_t sid_len;
    uint8_t *sid;
    size_t nonce_d_len;
    uint8_t *nonce_d;
    size_t ct_kyber_len;
    uint8_t *ct_kyber;
    size_t tag_d_len;
    uint8_t *tag_d;
    
    char *http_address;

    // base 64
    char *sid_b64;
    char *nonce_d_b64;
    char *ct_kyber_b64;
    char *tag_d_b64;
};

struct response_step_2{
    int step;
    size_t sid_len;
    uint8_t *sid;
    size_t tad_s_len;
    uint8_t *tag_s;
    
    // base 64
    char *sid_b64;
    char *tad_s_b64;
};

struct ake_key{
    uint8_t *key;
    size_t key_size;
    bool ready; 
    char *key_info;
    size_t key_info_len;

};

// pending to add a kyber structure

struct kyber_object_node {
    uint8_t *pk;
    size_t pk_len;
    uint8_t *ct;
    size_t ct_len;
    uint8_t *ss;
    size_t ss_len;
};

/**
 * @brief Derive a key using HKDF-SHA512.
 *
 * Generic formula:
 *   OKM = HKDF-SHA512(salt, IKM, info, L)
 *
 * This function can be used to derive different protocol keys such as:
 * - Ksess : info = "Ksess"
 * - Kauth : info = "Kauth"
 *
 * @param[in]  ikm       Input keying material.
 * @param[in]  ikm_len   Length of input keying material.
 * @param[in]  salt      Optional salt buffer.
 * @param[in]  salt_len  Length of salt buffer.
 * @param[in]  info      Optional context/application-specific info.
 * @param[in]  info_len  Length of info buffer.
 * @param[out] okm       Output buffer for derived key.
 * @param[in]  okm_len   Desired output key length in bytes.
 *
 * @return true if the key was successfully derived, false otherwise.
 */
bool derive_hkdf_sha512(const uint8_t *ikm, size_t ikm_len,
                        const uint8_t *salt, size_t salt_len,
                        const uint8_t *info, size_t info_len,
                        uint8_t *okm, size_t okm_len)
{
    if (ikm == NULL || ikm_len == 0 || okm == NULL || okm_len == 0) {
        ESP_LOGE(TAG_PROT, "Invalid HKDF input parameters");
        return false;
    }

    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
    if (md == NULL) {
        ESP_LOGE(TAG_PROT, "SHA-512 not available");
        return false;
    }

    int ret = mbedtls_hkdf(md,
                           salt, salt_len,
                           ikm, ikm_len,
                           info, info_len,
                           okm, okm_len);

    if (ret != 0) {
        ESP_LOGE(TAG_PROT, "mbedtls_hkdf failed: -0x%04X", (unsigned)(-ret));
        return false;
    }

    return true;
}

/**
 * @brief Free all dynamic fields from request_step_2.
 *
 * @param[in,out] self Pointer to request_step_2 object.
 */
void free_request_2(struct request_step_2 *self)
{
    if (self == NULL) {
        return;
    }

    if (self->sid != NULL)
        free(self->sid);
    self->sid = NULL;
    self->sid_len = 0;

    if (self->nonce_d != NULL)
        free(self->nonce_d);
    self->nonce_d = NULL;
    self->nonce_d_len = 0;

    // if (self->ct_kyber != NULL)
    //     free(self->ct_kyber); //this structure doesn't have the ct
    self->ct_kyber = NULL;
    self->ct_kyber_len = 0;

    if (self->tag_d != NULL)
        free(self->tag_d );
    self->tag_d = NULL;
    self->tag_d_len = 0;

    if (self->sid_b64 != NULL)
        free(self->sid_b64);
    self->sid_b64 = NULL;

    if (self->nonce_d_b64 != NULL)
        free(self->nonce_d_b64);
    self->nonce_d_b64 = NULL;

    if (self->ct_kyber_b64 != NULL)
        free(self->ct_kyber_b64);
    self->ct_kyber_b64 = NULL;

    if (self->tag_d_b64 != NULL)
        free(self->tag_d_b64);
    self->tag_d_b64 = NULL;

    self->http_address = NULL;
    self->step = 0;
}

/**
 * @brief Reset ake_key object to a safe empty state.
 *
 * @param[in,out] key Pointer to key object.
 */
void reset_ake_key(struct ake_key *key)
{
    if (key == NULL) {
        return;
    }

    if (key->key != NULL)
        free(key->key);
    key->key = NULL;
    key->key_size = 0;
    key->ready = false;
    key->key_info = NULL;
    key->key_info_len = 0;
}

/**
 * @brief Build request step 2.
 *
 * The function performs:
 *   - copy SID
 *   - generate nonceD
 *   - copy Kyber ciphertext
 *   - derive Ksess from shared secret
 *   - derive Kauth from PUF hash
 *   - compute HMAC-SHA512 tagD
 *   - base64-encode transport fields
 *
 * tagD = HMAC-SHA512(Kauth, sid || nonceS || nonceD || pk || ct || DEVICE_NAME)
 *
 * @param[out] self         Request object to fill.
 * @param[in]  rsp_step_1   Response from step 1.
 * @param[in]  kyber_obj    Kyber object with pk, ct, ss.
 * @param[out] key_sess     Output session key.
 * @param[out] key_auth     Output authentication key.
 * @param[in]  puf_obj      PUF object containing hash.
 * @param[in]  http_post    HTTP endpoint string.
 *
 * @return true on success, false on failure.
 */
bool build_request_2(struct request_step_2 *self,
                     const struct response_step_1 *rsp_step_1,
                     const struct kyber_object_node *kyber_obj,
                     struct ake_key *key_sess,
                     struct ake_key *key_auth,
                     const struct puf_object *puf_obj,
                     const char *http_post)
{
    int ret;
    mbedtls_md_context_t ctx;
    const mbedtls_md_info_t *md;

    if (self == NULL || rsp_step_1 == NULL || kyber_obj == NULL ||
        key_sess == NULL || key_auth == NULL || puf_obj == NULL ||
        http_post == NULL) {
        ESP_LOGE(TAG_PROT, "Invalid input parameter");
        return false;
    }

    if (rsp_step_1->sid == NULL || rsp_step_1->sid_len == 0 ||
        rsp_step_1->nonce == NULL || rsp_step_1->nonce_len == 0) {
        ESP_LOGE(TAG_PROT, "Invalid response_step_1 content");
        return false;
    }

    if (kyber_obj->pk == NULL || kyber_obj->pk_len == 0 ||
        kyber_obj->ct == NULL || kyber_obj->ct_len == 0 ||
        kyber_obj->ss == NULL || kyber_obj->ss_len == 0) {
        ESP_LOGE(TAG_PROT, "Invalid kyber object content");
        return false;
    }

    if (puf_obj->puf_hash_len == 0) {
        ESP_LOGE(TAG_PROT, "Invalid PUF hash length");
        return false;
    }

    memset(self, 0, sizeof(*self));
    //reset_ake_key(key_sess);
    //reset_ake_key(key_auth);

    self->step = 2;
    self->http_address = http_post;

    /* Copy SID */
    self->sid_len = rsp_step_1->sid_len;
    self->sid = malloc(self->sid_len);
    if (self->sid == NULL) {
        ESP_LOGE(TAG_PROT, "Malloc failed for SID");
        goto cleanup;
    }
    memcpy(self->sid, rsp_step_1->sid, self->sid_len);

    /* Generate nonceD */
    self->nonce_d_len = 32;
    self->nonce_d = malloc(self->nonce_d_len);
    if (self->nonce_d == NULL) {
        ESP_LOGE(TAG_PROT, "Malloc failed for nonce_d");
        goto cleanup;
    }
    esp_fill_random(self->nonce_d, self->nonce_d_len);

    /* Copy Kyber ciphertext */
     // TODO: REVIEW THIS PART OF CODE
    self->ct_kyber_len = kyber_obj->ct_len;
    // self->ct_kyber = malloc(self->ct_kyber_len);
    // if (self->ct_kyber == NULL) {
    //     ESP_LOGE(TAG_PROT, "Malloc failed for ct_kyber");
    //     goto cleanup;
    // }
    // memcpy(self->ct_kyber, kyber_obj->ct, self->ct_kyber_len);
    self->ct_kyber = kyber_obj->ct;

    /* Allocate tag buffer */
    self->tag_d_len = 64;
    self->tag_d = malloc(self->tag_d_len);
    if (self->tag_d == NULL) {
        ESP_LOGE(TAG_PROT, "Malloc failed for tag_d");
        goto cleanup;
    }

    /* Derive Ksess */
    key_sess->key_size = 32;
    key_sess->key = malloc(key_sess->key_size);
    if (key_sess->key == NULL) {
        ESP_LOGE(TAG_PROT, "Malloc failed for key_sess");
        goto cleanup;
    }

    key_sess->key_info = "Ksess";
    key_sess->key_info_len = strlen(key_sess->key_info);

    if (!derive_hkdf_sha512(kyber_obj->ss,
                            kyber_obj->ss_len,
                            rsp_step_1->nonce,
                            rsp_step_1->nonce_len,
                            (const uint8_t *)key_sess->key_info,
                            key_sess->key_info_len,
                            key_sess->key,
                            key_sess->key_size)) {
        ESP_LOGE(TAG_PROT, "Failed to derive Ksess");
        goto cleanup;
    }
    key_sess->ready = true;

    /* Derive Kauth */
    key_auth->key_size = 32;
    key_auth->key = malloc(key_auth->key_size);
    if (key_auth->key == NULL) {
        ESP_LOGE(TAG_PROT, "Malloc failed for key_auth");
        goto cleanup;
    }

    key_auth->key_info = "Kauth";
    key_auth->key_info_len = strlen(key_auth->key_info);

    if (!derive_hkdf_sha512(puf_obj->puf_hash,
                            puf_obj->puf_hash_len,
                            rsp_step_1->nonce,
                            rsp_step_1->nonce_len,
                            (const uint8_t *)key_auth->key_info,
                            key_auth->key_info_len,
                            key_auth->key,
                            key_auth->key_size)) {
        ESP_LOGE(TAG_PROT, "Failed to derive Kauth");
        goto cleanup;
    }
    key_auth->ready = true;

    /* HMAC-SHA512 */
    md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
    if (md == NULL) {
        ESP_LOGE(TAG_PROT, "SHA-512 not available");
        goto cleanup;
    }

    mbedtls_md_init(&ctx);

    ret = mbedtls_md_setup(&ctx, md, 1);
    if (ret != 0) {
        ESP_LOGE(TAG_PROT, "mbedtls_md_setup failed: %d", ret);
        goto cleanup_md;
    }

    ret = mbedtls_md_hmac_starts(&ctx, key_auth->key, key_auth->key_size);
    if (ret != 0) {
        ESP_LOGE(TAG_PROT, "mbedtls_md_hmac_starts failed: %d", ret);
        goto cleanup_md;
    }

    ret = mbedtls_md_hmac_update(&ctx, self->sid, self->sid_len);
    if (ret != 0) {
        ESP_LOGE(TAG_PROT, "HMAC update SID failed: %d", ret);
        goto cleanup_md;
    }

    ret = mbedtls_md_hmac_update(&ctx, rsp_step_1->nonce, rsp_step_1->nonce_len);
    if (ret != 0) {
        ESP_LOGE(TAG_PROT, "HMAC update nonceS failed: %d", ret);
        goto cleanup_md;
    }

    ret = mbedtls_md_hmac_update(&ctx, self->nonce_d, self->nonce_d_len);
    if (ret != 0) {
        ESP_LOGE(TAG_PROT, "HMAC update nonceD failed: %d", ret);
        goto cleanup_md;
    }

    ret = mbedtls_md_hmac_update(&ctx, kyber_obj->pk, kyber_obj->pk_len);
    if (ret != 0) {
        ESP_LOGE(TAG_PROT, "HMAC update PK failed: %d", ret);
        goto cleanup_md;
    }

    ret = mbedtls_md_hmac_update(&ctx, self->ct_kyber, self->ct_kyber_len);
    if (ret != 0) {
        ESP_LOGE(TAG_PROT, "HMAC update CT failed: %d", ret);
        goto cleanup_md;
    }

    ret = mbedtls_md_hmac_update(&ctx,
                                 (const unsigned char *)DEVICE_NAME,
                                 strlen(DEVICE_NAME));
    if (ret != 0) {
        ESP_LOGE(TAG_PROT, "HMAC update DEVICE_NAME failed: %d", ret);
        goto cleanup_md;
    }

    ret = mbedtls_md_hmac_finish(&ctx, self->tag_d);
    if (ret != 0) {
        ESP_LOGE(TAG_PROT, "mbedtls_md_hmac_finish failed: %d", ret);
        goto cleanup_md;
    }

    mbedtls_md_free(&ctx);

    /* Base64 */
    if (base64_encode_alloc(self->sid, self->sid_len, &self->sid_b64) != 0) {
        ESP_LOGE(TAG_PROT, "Base64 encode failed for SID");
        goto cleanup;
    }

    if (base64_encode_alloc(self->nonce_d, self->nonce_d_len, &self->nonce_d_b64) != 0) {
        ESP_LOGE(TAG_PROT, "Base64 encode failed for nonce_d");
        goto cleanup;
    }

    if (base64_encode_alloc(self->ct_kyber, self->ct_kyber_len, &self->ct_kyber_b64) != 0) {
        ESP_LOGE(TAG_PROT, "Base64 encode failed for ct_kyber");
        goto cleanup;
    }

    if (base64_encode_alloc(self->tag_d, self->tag_d_len, &self->tag_d_b64) != 0) {
        ESP_LOGE(TAG_PROT, "Base64 encode failed for tag_d");
        goto cleanup;
    }

    ESP_LOGI(TAG_PROT, "Request step 2 built successfully");
    return true;

cleanup_md:
    mbedtls_md_free(&ctx);

cleanup:
    free_request_2(self);
    reset_ake_key(key_sess);
    reset_ake_key(key_auth);
    return false;
}

/**
 * @brief Free all dynamic memory inside a kyber_object_node.
 *
 * @param[in,out] self Pointer to kyber object node
 */
void free_kyber_object_node(struct kyber_object_node *self)
{
    if (self == NULL) {
        return;
    }

    if (self->pk != NULL) {
        free(self->pk);
        self->pk = NULL;
    }

    if (self->ct != NULL) {
        free(self->ct);
        self->ct = NULL;
    }

    if (self->ss != NULL) {
        free(self->ss);
        self->ss = NULL;
    }

    self->pk_len = 0;
    self->ct_len = 0;
    self->ss_len = 0;
}

/**
 * @brief Read Kyber public key from secure storage and generate ciphertext
 *        and shared secret using crypto_kem_enc().
 *
 * This function:
 * 1. Initializes the kyber object node
 * 2. Reads the Kyber public key from secure storage
 * 3. Verifies the public key length
 * 4. Allocates memory for ciphertext and shared secret
 * 5. Executes Kyber encapsulation
 *
 * @param[in,out] self Pointer to kyber object node
 * @param[in]     aes  Pointer to AES object used to decrypt secure storage
 *
 * @return true on success, false on failure
 */
bool get_kyber_object_node(struct kyber_object_node *self, struct aes_256_obj *aes)
{
    esp_err_t err;

    if (self == NULL || aes == NULL) {
        ESP_LOGE(TAG_PROT, "Invalid input parameter");
        return false;
    }

    /* Initialize object fields */
    self->pk = NULL;
    self->ct = NULL;
    self->ss = NULL;
    self->pk_len = 0;
    self->ct_len = 0;
    self->ss_len = 0;

    /* Read public key from secure storage */
    ESP_LOGI(TAG_PROT, "Getting Kyber public key from secure storage");

    err = read_secure_storage_region_alloc("PK_KYBER",
                                           aes,
                                           &self->pk,
                                           &self->pk_len);
    if (err != ESP_OK) {
        ESP_LOGE(TAG_PROT, "Failed to read PK_KYBER from secure storage");
        goto cleanup;
    }

    if (self->pk == NULL) {
        ESP_LOGE(TAG_PROT, "Public key is NULL");
        goto cleanup;
    }

    if (self->pk_len != CRYPTO_PUBLICKEYBYTES) {
        ESP_LOGE(TAG_PROT,
                 "Invalid public key length. Got: %u Expected: %u",
                 (unsigned)self->pk_len,
                 (unsigned)CRYPTO_PUBLICKEYBYTES);
        goto cleanup;
    }

    ESP_LOG_BUFFER_HEXDUMP("Kyber PK", self->pk, self->pk_len, ESP_LOG_INFO);

    /* Set output lengths */
    self->ct_len = CRYPTO_CIPHERTEXTBYTES;
    self->ss_len = CRYPTO_BYTES;

    /* Allocate ciphertext buffer */
   
    ESP_LOGW(TAG_PROT, "Failed to allocate memory for ciphertext");
    self->ct = malloc(self->ct_len);
    if (self->ct == NULL) {
        ESP_LOGE(TAG_PROT, "Failed to allocate memory for ciphertext");
        goto cleanup;
    }

    /* Allocate shared secret buffer */
    self->ss = malloc(self->ss_len);
    if (self->ss == NULL) {
        ESP_LOGE(TAG_PROT, "Failed to allocate memory for shared secret");
        goto cleanup;
    }

    printf("2 -------- CRYPTO_KEM_ENC ENCRYPTION -----------\n");

    if (crypto_kem_enc(self->ct, self->ss, self->pk) != 0) {
        ESP_LOGE(TAG_PROT, "crypto_kem_enc failed");
        goto cleanup;
    }

    ESP_LOG_BUFFER_HEXDUMP("Cipher Text", self->ct, self->ct_len, ESP_LOG_INFO);
    ESP_LOG_BUFFER_HEXDUMP("Shared Secret", self->ss, self->ss_len, ESP_LOG_INFO);

    return true;

cleanup:
    free_kyber_object_node(self);
    return false;
}

bool send_http_request_2(struct request_step_2 *self, char **response_output, size_t *response_length)
{
    if (self == NULL || response_output == NULL || response_length == NULL) {
        return false;
    }

    cJSON *root = cJSON_CreateObject();
    if (root == NULL) {
        return false;
    }

    cJSON_AddNumberToObject(root, "Step", self->step);
    cJSON_AddStringToObject(root, "SID", self->sid_b64);
    cJSON_AddNumberToObject(root, "SID_Len", self->sid_len);
    cJSON_AddStringToObject(root, "NonceD", self->nonce_d_b64);
    cJSON_AddNumberToObject(root, "NonceD_Len", self->nonce_d_len);
    cJSON_AddStringToObject(root, "CT", self->ct_kyber_b64);
    cJSON_AddNumberToObject(root, "CT_Len", self->ct_kyber_len);
    cJSON_AddStringToObject(root, "TagD", self->tag_d_b64);
    cJSON_AddNumberToObject(root, "TagD_Len", self->tag_d_len);
    

    char *json_string = cJSON_Print(root);
    if (json_string == NULL) {
        cJSON_Delete(root);
        return false;
    }

    printf("%s\n", json_string);

    esp_err_t err = http_post_and_get_response(
        self->http_address,
        json_string,
        response_output,
        response_length
    );

    if (err != ESP_OK) {
        ESP_LOGE(TAG_PROT, "HTTP Error transaction in step 1");
        cJSON_Delete(root);
        free(json_string);
        return false;
    }

    printf("The server is returning data\n");
    printf("Data Response: %s\n", *response_output);

    cJSON_Delete(root);
    free(json_string);
    return true;
}


void init_nvs(){
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ESP_ERROR_CHECK(nvs_flash_init());
    }
    else
        ESP_LOGI("NVS_INIT", "Starting NVS INIT");  
}

bool build_request_1(struct request_step_1 *self, char *http_post)
{
    if (self == NULL) {
        ESP_LOGE(TAG_PROT, "Invalid input parameter");
        return false;
    }
    self->step = 1;
    self->device_name = DEVICE_NAME;
    self->http_address = http_post;
    return true;
}

bool send_http_request_1(struct request_step_1 *self, char **response_output, size_t *response_length)
{
    if (self == NULL || response_output == NULL || response_length == NULL) {
        return false;
    }

    cJSON *root = cJSON_CreateObject();
    if (root == NULL) {
        return false;
    }

    cJSON_AddNumberToObject(root, "Step", self->step);
    cJSON_AddStringToObject(root, "Device_Name", self->device_name);

    char *json_string = cJSON_Print(root);
    if (json_string == NULL) {
        cJSON_Delete(root);
        return false;
    }

    printf("%s\n", json_string);

    esp_err_t err = http_post_and_get_response(
        self->http_address,
        json_string,
        response_output,
        response_length
    );

    if (err != ESP_OK) {
        ESP_LOGE(TAG_PROT, "HTTP Error transaction in step 1");
        cJSON_Delete(root);
        free(json_string);
        return false;
    }

    printf("The server is returning data\n");
    printf("Data Response: %s\n", *response_output);

    cJSON_Delete(root);
    free(json_string);
    return true;
}


bool build_request_0(struct request_step_0 *self, struct puf_object *puf, char *http_post)
{
    if (self == NULL || puf == NULL) {
        ESP_LOGE(TAG_PROT, "Invalid input parameter");
        return false;
    }

    if (!puf->init) {
        ESP_LOGI(TAG_PROT, "PUF object is not initialized");
        ESP_LOGI(TAG_PROT, "PUF HARDCODED... Debug testing");
        // return false; //hardcoded for testing
    }

    if (puf->puf_hash_len == 0 || puf->puf_hash_len > PUF_HASH_LEN) {
        ESP_LOGE(TAG_PROT, "Invalid PUF hash length: %zu", puf->puf_hash_len);
        return false;
    }

    self->device_mac = NULL;
    self->puf_hash = NULL;
    self->device_mac_b64 = NULL;
    self->puf_hash_b64 = NULL;

    self->step = 0;
    self->device_name = DEVICE_NAME;
    self->http_address = http_post;

    self->device_mac_size = 6;
    self->device_mac = malloc(self->device_mac_size);
    if (self->device_mac == NULL) {
        ESP_LOGE(TAG_PROT, "malloc failed for mac_address");
        return false;
    }

    esp_efuse_mac_get_default(self->device_mac);

    self->puf_hash_size = puf->puf_hash_len;
    self->puf_hash = malloc(self->puf_hash_size);
    if (self->puf_hash == NULL) {
        ESP_LOGE(TAG_PROT, "malloc failed for puf_hash");
        free(self->device_mac);
        self->device_mac = NULL;
        return false;
    }

    memcpy(self->puf_hash, puf->puf_hash, self->puf_hash_size);

    if (base64_encode_alloc(self->puf_hash,
                            self->puf_hash_size,
                            &self->puf_hash_b64) != 0) {
        ESP_LOGE(TAG_PROT, "BASE64 ENCODE FAILURE (PUF)");
        free(self->puf_hash);
        free(self->device_mac);
        self->puf_hash = NULL;
        self->device_mac = NULL;
        return false;
    }

    ESP_LOGI(TAG_PROT, "PUF_HASH(b64): %s", self->puf_hash_b64);

    if (base64_encode_alloc(self->device_mac,
                            self->device_mac_size,
                            &self->device_mac_b64) != 0) {
        ESP_LOGE(TAG_PROT, "BASE64 ENCODE FAILURE (MAC)");
        free(self->puf_hash_b64);
        free(self->puf_hash);
        free(self->device_mac);
        self->puf_hash_b64 = NULL;
        self->puf_hash = NULL;
        self->device_mac = NULL;
        return false;
    }

    ESP_LOGI(TAG_PROT, "MAC_ADDRESS(b64): %s", self->device_mac_b64);

    return true;
}

bool send_http_request_0(struct request_step_0 *self, char **response_output, size_t *response_length)
{
    if (self == NULL || response_output == NULL || response_length == NULL) {
        return false;
    }

    cJSON *root = cJSON_CreateObject();
    if (root == NULL) {
        return false;
    }

    cJSON_AddNumberToObject(root, "Step", self->step);
    cJSON_AddStringToObject(root, "Device_Name", self->device_name);
    cJSON_AddStringToObject(root, "Mac_Address", self->device_mac_b64);
    cJSON_AddStringToObject(root, "PUF_Hash", self->puf_hash_b64);

    char *json_string = cJSON_Print(root);
    if (json_string == NULL) {
        cJSON_Delete(root);
        return false;
    }

    printf("%s\n", json_string);

    esp_err_t err = http_post_and_get_response(
        self->http_address,
        json_string,
        response_output,
        response_length
    );

    if (err != ESP_OK) {
        ESP_LOGE(TAG_PROT, "HTTP Error transaction in step 0");
        cJSON_Delete(root);
        free(json_string);
        return false;
    }

    printf("The server is returning data\n");
    printf("Data Response: %s\n", *response_output);

    cJSON_Delete(root);
    free(json_string);
    return true;
}

void free_request_0(struct request_step_0 *self)
{
    if (self == NULL) {
        return;
    }

    free(self->device_mac);
    free(self->puf_hash);
    free(self->device_mac_b64);
    free(self->puf_hash_b64);

    self->device_mac = NULL;
    self->puf_hash = NULL;
    self->device_mac_b64 = NULL;
    self->puf_hash_b64 = NULL;

    self->device_mac_size = 0;
    self->puf_hash_size = 0;
    free(self);
}

bool get_response_0(struct response_step_0 *self, char *response_output)
{
    /*----- HOW TO PARSE THE DATA -----*/
    cJSON *receive_json_data= cJSON_Parse(response_output);
    cJSON *step = cJSON_GetObjectItem(receive_json_data, "Step");
    cJSON *server_name = cJSON_GetObjectItem(receive_json_data, "Server_Name");
    cJSON *pk_kyber_len = cJSON_GetObjectItem(receive_json_data, "Kyber_Pk_Len");
    cJSON *pk_kyber = cJSON_GetObjectItem(receive_json_data, "Kyber_Pk");

    self->step = step->valueint;
    self->kyber_pk_len = pk_kyber_len->valueint;
    self->server_name = server_name->string;
    
    // recover the key:
    uint8_t *kypber_pk_decode_b64_output = NULL; 
    size_t kypber_pk_decode_b64_len = 0;

    if (base64_decode_alloc(pk_kyber->valuestring, &kypber_pk_decode_b64_output, &kypber_pk_decode_b64_len) == 0) {
        ESP_LOGI(TAG_PROT, "Decoded bytes: %u", (unsigned)kypber_pk_decode_b64_len);
        if(self->kyber_pk_len != kypber_pk_decode_b64_len){
            ESP_LOGI(TAG_PROT, "Error Decoding Kyber Public Key, the size doesn't match");
            return false;
        }         
    }
    else{
        ESP_LOGI(TAG_PROT, "Error Decoding Kyber Public Key");
        return false;
    }


    self->kyber_pk = kypber_pk_decode_b64_output;
    cJSON_Delete(receive_json_data);
    return true;
}

bool get_response_1(struct response_step_1 *self, char *response_output ){
    /*----- HOW TO PARSE THE DATA -----*/
    cJSON *receive_json_data= cJSON_Parse(response_output);
    cJSON *step = cJSON_GetObjectItem(receive_json_data, "Step");
    cJSON *server_name = cJSON_GetObjectItem(receive_json_data, "Server_Name");
    cJSON *sid_len = cJSON_GetObjectItem(receive_json_data, "SID_Len");
    cJSON *sid = cJSON_GetObjectItem(receive_json_data, "SID");
    cJSON *nonce_len = cJSON_GetObjectItem(receive_json_data, "Nonce_Len");
    cJSON *nonce = cJSON_GetObjectItem(receive_json_data, "Nonce");

    self->step = step->valueint;
    self->server_name = server_name->string;
    self->sid_len = sid_len->valueint;
    self->nonce_len = nonce_len->valueint;

    self->sid = malloc(self->sid_len);
    self->nonce = malloc(self->nonce_len);

    // recover the key:
    uint8_t *temp_decode_b64_output = NULL; 
    size_t temp_decode_b64_len = 0;

    if (base64_decode_alloc(sid->valuestring, &temp_decode_b64_output, &temp_decode_b64_len) == 0) {
        ESP_LOGI(TAG_PROT, "Decoded bytes: %u", (unsigned)temp_decode_b64_len);
        if(self->sid_len != temp_decode_b64_len){
            ESP_LOGI(TAG_PROT, "Error Decoding SID, the size doesn't match");
            return false;
        }
        self->sid = temp_decode_b64_output;      
    }
    else{
        ESP_LOGI(TAG_PROT, "Error Decoding SID");
        return false;
    }


    if (base64_decode_alloc(nonce->valuestring, &temp_decode_b64_output, &temp_decode_b64_len) == 0) {
        ESP_LOGI(TAG_PROT, "Decoded bytes: %u", (unsigned)temp_decode_b64_len);
        if(self->nonce_len != temp_decode_b64_len){
            ESP_LOGI(TAG_PROT, "Error Decoding Nonce, the size doesn't match");
            return false;
        }
        self->nonce = temp_decode_b64_output;      
    }
    else{
        ESP_LOGI(TAG_PROT, "Error Decoding SID");
        return false;
    }

    cJSON_Delete(receive_json_data);
    return true;
}

void app_main(void)
{   ESP_LOGW(TAG_PROT, "Free heap: %u", (unsigned)esp_get_free_heap_size());
    ESP_LOGI(TAG_PROT, "Initialize the NVS");
    init_nvs();
    ESP_LOGI(TAG_PROT, "Starting WiFi Driver");
    wifi_init_sta();
    /* Provisioning Secure Storage Parameters*/
    ESP_LOGI(TAG_PROT, "Setting Parameter for PUF and Secure Storage Region");
    struct puf_object *puf_obj = malloc(sizeof(struct puf_object));
    // CREATE AES OBJECT     
    uint8_t key_sec_stor[AES_256];

    if(!derive_key_from_puf(&key_sec_stor[0], puf_obj, false)){ // change to true after provisioning
        ESP_LOGE(TAG_PROT, "Derivation Failure");
        return;
    }
    struct aes_256_obj *aes = malloc(sizeof(struct aes_256_obj));
    create_aes_256_obj(aes, &key_sec_stor[0]);

    ESP_LOGI(TAG_PROT, "****** PROTOCOL TRANSACTIONS ******");
    char *http_post = "http://192.168.1.236:5000/example"; 
    char *response_output = NULL;
    size_t response_length = 0;

    ESP_LOGI(TAG_PROT, "-------- [STEP 0] --------");
    struct request_step_0 *req_step_0 = malloc(sizeof(struct request_step_0 ));    
    if (build_request_0(req_step_0, puf_obj, http_post) == false){
        ESP_LOGE(TAG_PROT, "Build request 0 Failure");
        return;
    }    
    bool resp_0 = send_http_request_0(req_step_0, &response_output, &response_length);
    
    struct response_step_0 *response_step_0 = malloc(sizeof(struct response_step_0 ));
    bool get_res_0 = get_response_0(response_step_0, response_output);

    write_secure_storage_region(response_step_0->kyber_pk, response_step_0->kyber_pk_len, "PK_KYBER", aes);
    ESP_LOGI(TAG_PROT, "Free elements");
    free_request_0(req_step_0);
    free(response_output);
    
    
    ESP_LOGI(TAG_PROT, "-------- [STEP 1] --------");

    struct request_step_1 *req_step_1 = malloc(sizeof(struct request_step_1 ));
    if (build_request_1(req_step_1, http_post) == false){
        ESP_LOGE(TAG_PROT, "Build request 1 Failure");
        return;
    }

    bool resp_1 = send_http_request_1(req_step_1, &response_output, &response_length);
    struct response_step_1 *response_step_1 = malloc(sizeof(struct response_step_1));
    bool get_res_1 = get_response_1(response_step_1, response_output);

    ESP_LOG_BUFFER_HEXDUMP("DATA HEX FORMAT", response_step_1->nonce, response_step_1->nonce_len, ESP_LOG_INFO);
    ESP_LOG_BUFFER_HEXDUMP("DATA HEX FORMAT", response_step_1->sid, response_step_1->sid_len, ESP_LOG_INFO);
    ESP_LOGW(TAG_PROT, "PENDING TO FREE MEMORY FROM STEP 1");
    
    free(response_output);

    ESP_LOGI(TAG_PROT, "-------- [STEP 2] --------");
    //READ FROM SECURE STORAGE
    // uint8_t *plain_pk_kyber= NULL;
    // size_t plain_pk_kyber_len = 0;
    // esp_err_t err = read_secure_storage_region_alloc("PK_KYBER", aes, &plain_pk_kyber, &plain_pk_kyber_len);
    // ESP_LOG_BUFFER_HEXDUMP("HEX FORMAT", plain_pk_kyber, plain_pk_kyber_len, ESP_LOG_INFO);

    // uint8_t *ct = malloc(CRYPTO_CIPHERTEXTBYTES);
    // uint8_t *key_b = malloc(CRYPTO_BYTES);

    // printf("2 -------- CRYPTO_KEM_ENC ENCRYPTION ----------- \n");
    // crypto_kem_enc(ct, key_b, plain_pk_kyber);

    // ESP_LOG_BUFFER_HEXDUMP("Cipher Text: ", ct, CRYPTO_CIPHERTEXTBYTES, ESP_LOG_INFO);
    // ESP_LOG_BUFFER_HEXDUMP("Key B: ", key_b, CRYPTO_BYTES, ESP_LOG_INFO);
    struct request_step_2 *req_step_2 = malloc(sizeof(struct request_step_2));
    struct kyber_object_node *kyber_obj = malloc(sizeof(struct kyber_object_node));
    if (get_kyber_object_node(kyber_obj, aes) != true){
        ESP_LOGE(TAG_PROT, "Error creating Kyber Object");
        return;
    }
    ESP_LOGW(TAG_PROT, "kyber OBJECT DONE!!!!!");

    struct ake_key *key_sess = malloc(sizeof(struct ake_key));  
    struct ake_key *key_auth = malloc(sizeof(struct ake_key));    

    build_request_2(req_step_2, response_step_1, kyber_obj,
         key_sess, key_auth, puf_obj, http_post);

    // derive_ksess_hkdf_sha512(key_b, CRYPTO_BYTES, response_step_1->nonce, response_step_1->nonce_len,
    // ksess, ksess_len);

    // bool derivate_ksess = derive_hkdf_sha512(kyber_obj->ss, kyber_obj->ss_len, response_step_1->nonce, response_step_1->nonce_len,
    //                                         info_ksess, info_ksess_len, ksess, ksess_len);
    
    ESP_LOG_BUFFER_HEXDUMP("NONCE: ", response_step_1->nonce, response_step_1->nonce_len, ESP_LOG_INFO);
    ESP_LOG_BUFFER_HEXDUMP("SID", response_step_1->sid,response_step_1->sid_len, ESP_LOG_INFO);
    ESP_LOG_BUFFER_HEXDUMP("Key Session: ", key_sess->key, key_sess->key_size, ESP_LOG_INFO);
    ESP_LOG_BUFFER_HEXDUMP("Key Authentication: ", key_auth->key, key_auth->key_size, ESP_LOG_INFO);

    bool resp_2 = send_http_request_2(req_step_2, &response_output, &response_length);
    
    ESP_LOGW(TAG_PROT, "PENDING TO FREE MEMORY KYBER OBJECT");
    free(response_output);
    free_kyber_object_node(kyber_obj);
    free_request_2(req_step_2);
    ESP_LOGW(TAG_PROT, "Free heap: %u", (unsigned)esp_get_free_heap_size());
    //free(plain_pk_kyber);
}