#include <stdio.h>
#include <stdbool.h>

#include "esp_system.h"
#include "esp_mac.h"
#include "esp_log.h"
#include "cJSON.h"

#include "base64.h"
#include "ake_protocol.h"
#include "api_secure_storage.h"
#include "http_transactions.h"
#include "kem.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"

bool build_request_0(struct request_step_0 *self, const char *device_name,
                     struct puf_object *puf)
{
    if (self == NULL || puf == NULL || device_name == NULL) {
        ESP_LOGE(TAG_AKE, "Invalid input parameter");
        return false;
    }

    if (!puf->init) {
        ESP_LOGI(TAG_AKE, "PUF object is not initialized");
        ESP_LOGI(TAG_AKE, "PUF HARDCODED... Debug testing");
        /* return false; // hardcoded for testing */
    }

    if (puf->puf_hash_len == 0 || puf->puf_hash_len > PUF_HASH_LEN) {
        ESP_LOGE(TAG_AKE, "Invalid PUF hash length: %zu", puf->puf_hash_len);
        return false;
    }

    self->step = 0;
    self->device_name = device_name;

    self->mac_address_size = 6;
    self->mac_address = NULL;
    self->puf_hash_size = 0;
    self->puf_hash = NULL;
    self->mac_address_b64 = NULL;
    self->puf_hash_b64 = NULL;

    self->mac_address = malloc(self->mac_address_size);
    if (self->mac_address == NULL) {
        ESP_LOGE(TAG_AKE, "Malloc failed for mac_address");
        return false;
    }

    if (esp_efuse_mac_get_default(self->mac_address) != ESP_OK) {
        ESP_LOGE(TAG_AKE, "Error getting mac address from fuses");
        return false;
    }

    self->puf_hash_size = puf->puf_hash_len;
    self->puf_hash = malloc(self->puf_hash_size);
    if (self->puf_hash == NULL) {
        ESP_LOGE(TAG_AKE, "malloc failed for puf_hash");
        free(self->mac_address);
        self->mac_address = NULL;
        self->mac_address_size = 0;
        return false;
    }

    memcpy(self->puf_hash, puf->hash, self->puf_hash_size);

    if (base64_encode_alloc(self->puf_hash,
                            self->puf_hash_size,
                            &self->puf_hash_b64) != 0) {
        ESP_LOGE(TAG_AKE, "BASE64 ENCODE FAILURE (PUF)");
        free(self->puf_hash);
        free(self->mac_address);
        self->puf_hash = NULL;
        self->puf_hash_size = 0;
        self->mac_address = NULL;
        self->mac_address_size = 0;
        return false;
    }

    if (base64_encode_alloc(self->mac_address,
                            self->mac_address_size,
                            &self->mac_address_b64) != 0) {
        ESP_LOGE(TAG_AKE, "BASE64 ENCODE FAILURE (MAC)");
        free(self->puf_hash_b64);
        free(self->puf_hash);
        free(self->mac_address);
        self->puf_hash_b64 = NULL;
        self->puf_hash = NULL;
        self->puf_hash_size = 0;
        self->mac_address = NULL;
        self->mac_address_size = 0;
        return false;
    }

    return true;
}

void free_request_step_0(struct request_step_0 *self)
{
    if (self == NULL) {
        return;
    }

    if (self->mac_address != NULL)
        free(self->mac_address);
    if (self->puf_hash != NULL)
        free(self->puf_hash);
    if (self->mac_address_b64 != NULL)
        free(self->mac_address_b64);
    if (self->puf_hash_b64 != NULL)
        free(self->puf_hash_b64);

    self->mac_address = NULL;
    self->puf_hash = NULL;
    self->mac_address_b64 = NULL;
    self->puf_hash_b64 = NULL;

    self->mac_address_size = 0;
    self->puf_hash_size = 0;
    free(self);
}

bool send_http_request_0(struct request_step_0 *self, char **json_response_output,
                         size_t *response_length, const char *http_address)
{
    if (self == NULL || json_response_output == NULL ||
        response_length == NULL || http_address == NULL) {
        ESP_LOGE(TAG_AKE, "Invalid input parameter");
        return false;
    }

    if (self->device_name == NULL ||
        self->mac_address_b64 == NULL ||
        self->puf_hash_b64 == NULL) {
        ESP_LOGE(TAG_AKE, "Invalid request_step_0 content");
        return false;
    }

    *json_response_output = NULL;
    *response_length = 0;

    cJSON *root = cJSON_CreateObject();
    if (root == NULL) {
        ESP_LOGE(TAG_AKE, "cJSON_CreateObject failed");
        return false;
    }

    if (cJSON_AddNumberToObject(root, "Step", self->step) == NULL ||
        cJSON_AddStringToObject(root, "Device_Name", self->device_name) == NULL ||
        cJSON_AddStringToObject(root, "Mac_Address", self->mac_address_b64) == NULL ||
        cJSON_AddStringToObject(root, "PUF_Hash", self->puf_hash_b64) == NULL) {
        ESP_LOGE(TAG_AKE, "Failed to build JSON request");
        cJSON_Delete(root);
        return false;
    }

    char *json_string = cJSON_Print(root);
    if (json_string == NULL) {
        ESP_LOGE(TAG_AKE, "cJSON_Print failed");
        cJSON_Delete(root);
        return false;
    }

    ESP_LOGI(TAG_AKE, "STEP 0 JSON: %s", json_string);

    esp_err_t err = http_post_and_get_response(
        http_address,
        json_string,
        json_response_output,
        response_length
    );

    cJSON_Delete(root);
    free(json_string);

    if (err != ESP_OK) {
        ESP_LOGE(TAG_AKE, "HTTP error transaction in step 0");
        return false;
    }


    if (*json_response_output != NULL) {
        ESP_LOGI(TAG_AKE, "Data Response from step 0: %s", *json_response_output);
    }

    return true;
}

bool get_response_0(struct response_step_0 *self, char *json_response_output)
{
    if (self == NULL || json_response_output == NULL) {
        ESP_LOGE(TAG_AKE, "Invalid input parameter");
        return false;
    }

    self->step = 0;
    self->server_name = NULL;
    self->kyber_pk_len = 0;
    self->kyber_pk = NULL;

    cJSON *receive_json_data = cJSON_Parse(json_response_output);
    if (receive_json_data == NULL) {
        ESP_LOGE(TAG_AKE, "JSON parse error");
        return false;
    }

    cJSON *step = cJSON_GetObjectItemCaseSensitive(receive_json_data, "Step");
    cJSON *server_name = cJSON_GetObjectItemCaseSensitive(receive_json_data, "Server_Name");
    cJSON *pk_kyber_len = cJSON_GetObjectItemCaseSensitive(receive_json_data, "Kyber_Pk_Len");
    cJSON *pk_kyber = cJSON_GetObjectItemCaseSensitive(receive_json_data, "Kyber_Pk");

    if (!cJSON_IsNumber(step) ||
        !cJSON_IsString(server_name) ||
        !cJSON_IsNumber(pk_kyber_len) ||
        !cJSON_IsString(pk_kyber)) {
        ESP_LOGE(TAG_AKE, "Invalid JSON response format");
        cJSON_Delete(receive_json_data);
        return false;
    }

    /*verify protocol step 0*/
    if (step->valueint != 0) {
        ESP_LOGE(TAG_AKE, "Unexpected step value: %d", step->valueint);
        cJSON_Delete(receive_json_data);
        return false;
    }

    self->step = step->valueint;
    self->kyber_pk_len = (size_t)pk_kyber_len->valueint;

    
    self->server_name = strdup(server_name->valuestring);
    if (self->server_name == NULL) {
        ESP_LOGE(TAG_AKE, "malloc failed for server_name");
        cJSON_Delete(receive_json_data);
        return false;
    }

    uint8_t *kyber_pk_decode_b64_output = NULL;
    size_t kyber_pk_decode_b64_len = 0;

    if (base64_decode_alloc(pk_kyber->valuestring,
                            &kyber_pk_decode_b64_output,
                            &kyber_pk_decode_b64_len) != 0) {
        ESP_LOGE(TAG_AKE, "Error decoding Kyber public key");
        free(self->server_name);
        self->server_name = NULL;
        cJSON_Delete(receive_json_data);
        return false;
    }

    if (self->kyber_pk_len != kyber_pk_decode_b64_len) {
        ESP_LOGE(TAG_AKE, "Kyber PK size mismatch (%zu != %zu)",
                 self->kyber_pk_len, kyber_pk_decode_b64_len);
        free(kyber_pk_decode_b64_output);
        free(self->server_name);
        self->server_name = NULL;
        cJSON_Delete(receive_json_data);
        return false;
    }

    self->kyber_pk = kyber_pk_decode_b64_output;

    cJSON_Delete(receive_json_data);
    return true;
}

void free_response_step_0(struct response_step_0 *self)
{
    if (self == NULL) {
        return;
    }

    if (self->server_name != NULL) {
        free(self->server_name);
        self->server_name = NULL;
    }

    if (self->kyber_pk != NULL) {
        free(self->kyber_pk);
        self->kyber_pk = NULL;
    }

    self->kyber_pk_len = 0;
    self->step = 0;
}

bool build_request_1(struct request_step_1 *self, const char *device_name)
{
    if (self == NULL || device_name == NULL) {
        ESP_LOGE(TAG_AKE, "Invalid input parameter");
        return false;
    }
    self->step = 1;
    self->device_name = device_name;
    return true;
}

bool send_http_request_1(struct request_step_1 *self, char **json_response_output,
                         size_t *json_response_length, const char *http_address)
{
    if (self == NULL || json_response_output == NULL ||
        json_response_length == NULL || http_address == NULL) {
        ESP_LOGE(TAG_AKE, "Invalid input parameter");
        return false;
    }

    if (self->device_name == NULL) {
        ESP_LOGE(TAG_AKE, "Invalid request_step_1 content");
        return false;
    }

    *json_response_output = NULL;
    *json_response_length = 0;

    cJSON *root = cJSON_CreateObject();
    if (root == NULL) {
        ESP_LOGE(TAG_AKE, "cJSON_CreateObject failed");
        return false;
    }

    if (cJSON_AddNumberToObject(root, "Step", self->step) == NULL ||
        cJSON_AddStringToObject(root, "Device_Name", self->device_name) == NULL) {
        ESP_LOGE(TAG_AKE, "Failed to build JSON request");
        cJSON_Delete(root);
        return false;
    }

    char *json_string = cJSON_Print(root);
    if (json_string == NULL) {
        ESP_LOGE(TAG_AKE, "cJSON_Print failed");
        cJSON_Delete(root);
        return false;
    }

    ESP_LOGI(TAG_AKE, "STEP 1 JSON: %s", json_string);

    esp_err_t err = http_post_and_get_response(
        http_address,
        json_string,
        json_response_output,
        json_response_length
    );

    cJSON_Delete(root);
    free(json_string);

    if (err != ESP_OK) {
        ESP_LOGE(TAG_AKE, "HTTP error transaction in step 1");
        return false;
    }

    if (*json_response_output != NULL) {
        ESP_LOGI(TAG_AKE, "Data Response from step 1: %s", *json_response_output);
    }

    return true;
}

bool get_response_1(struct response_step_1 *self, char *json_response_output)
{
    if (self == NULL || json_response_output == NULL) {
        ESP_LOGE(TAG_AKE, "Invalid input parameter");
        return false;
    }

    self->step = 0;
    self->server_name = NULL;
    self->sid_len = 0;
    self->sid = NULL;
    self->nonce_s_len = 0;
    self->nonce_s = NULL;

    cJSON *receive_json_data = cJSON_Parse(json_response_output);
    if (receive_json_data == NULL) {
        ESP_LOGE(TAG_AKE, "JSON parse error");
        return false;
    }

    cJSON *step = cJSON_GetObjectItemCaseSensitive(receive_json_data, "Step");
    cJSON *server_name = cJSON_GetObjectItemCaseSensitive(receive_json_data, "Server_Name");
    cJSON *sid_len = cJSON_GetObjectItemCaseSensitive(receive_json_data, "SID_Len");
    cJSON *sid = cJSON_GetObjectItemCaseSensitive(receive_json_data, "SID");
    cJSON *nonce_s_len = cJSON_GetObjectItemCaseSensitive(receive_json_data, "Nonce_S_Len");
    cJSON *nonce_s = cJSON_GetObjectItemCaseSensitive(receive_json_data, "Nonce_S");

    if (!cJSON_IsNumber(step) ||
        !cJSON_IsString(server_name) ||
        !cJSON_IsNumber(sid_len) ||
        !cJSON_IsString(sid) ||
        !cJSON_IsNumber(nonce_s_len) ||
        !cJSON_IsString(nonce_s)) {
        ESP_LOGE(TAG_AKE, "Invalid JSON response format");
        cJSON_Delete(receive_json_data);
        return false;
    }

    self->step = step->valueint;
    self->sid_len = (size_t)sid_len->valueint;
    self->nonce_s_len = (size_t)nonce_s_len->valueint;

    self->server_name = strdup(server_name->valuestring);
    if (self->server_name == NULL) {
        ESP_LOGE(TAG_AKE, "malloc failed for server_name");
        cJSON_Delete(receive_json_data);
        return false;
    }

    uint8_t *sid_decoded = NULL;
    size_t sid_decoded_len = 0;

    if (base64_decode_alloc(sid->valuestring, &sid_decoded, &sid_decoded_len) != 0) {
        ESP_LOGE(TAG_AKE, "Error decoding SID");
        free(self->server_name);
        self->server_name = NULL;
        cJSON_Delete(receive_json_data);
        return false;
    }

    if (self->sid_len != sid_decoded_len) {
        ESP_LOGE(TAG_AKE, "Error decoding SID, size mismatch");
        free(sid_decoded);
        free(self->server_name);
        self->server_name = NULL;
        cJSON_Delete(receive_json_data);
        return false;
    }

    self->sid = sid_decoded;

    uint8_t *nonce_decoded = NULL;
    size_t nonce_decoded_len = 0;

    if (base64_decode_alloc(nonce_s->valuestring, &nonce_decoded, &nonce_decoded_len) != 0) {
        ESP_LOGE(TAG_AKE, "Error decoding Nonce_S");
        free(self->sid);
        self->sid = NULL;
        free(self->server_name);
        self->server_name = NULL;
        cJSON_Delete(receive_json_data);
        return false;
    }

    if (self->nonce_s_len != nonce_decoded_len) {
        ESP_LOGE(TAG_AKE, "Error decoding Nonce_S, size mismatch");
        free(nonce_decoded);
        free(self->sid);
        self->sid = NULL;
        free(self->server_name);
        self->server_name = NULL;
        cJSON_Delete(receive_json_data);
        return false;
    }

    self->nonce_s = nonce_decoded;

    cJSON_Delete(receive_json_data);
    return true;
}

void free_response_step_1(struct response_step_1 *self)
{
    if (self == NULL) {
        return;
    }

    if (self->server_name != NULL) {
        free(self->server_name);
        self->server_name = NULL;
    }

    if (self->sid != NULL) {
        free(self->sid);
        self->sid = NULL;
    }

    if (self->nonce_s != NULL) {
        free(self->nonce_s);
        self->nonce_s = NULL;
    }

    self->step = 0;
    self->sid_len = 0;
    self->nonce_s_len = 0;
}

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

bool get_kyber_object_node(struct kyber_object_node *self,
                           struct aes_256_obj *aes_key_ss)
{
    esp_err_t err;

    if (self == NULL || aes_key_ss == NULL) {
        ESP_LOGE(TAG_AKE, "Invalid input parameter");
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
    ESP_LOGI(TAG_AKE, "Getting Kyber public key from secure storage");

    err = read_secure_storage_region_alloc("PK_KYBER",
                                           aes_key_ss,
                                           &self->pk,
                                           &self->pk_len);
    if (err != ESP_OK) {
        ESP_LOGE(TAG_AKE, "Failed to read PK_KYBER from secure storage");
        goto cleanup;
    }

    if (self->pk == NULL) {
        ESP_LOGE(TAG_AKE, "Public key is NULL");
        goto cleanup;
    }

    if (self->pk_len != CRYPTO_PUBLICKEYBYTES) {
        ESP_LOGE(TAG_AKE,
                 "Invalid public key length. Got: %u Expected: %u",
                 (unsigned)self->pk_len,
                 (unsigned)CRYPTO_PUBLICKEYBYTES);
        goto cleanup;
    }

    self->ct_len = CRYPTO_CIPHERTEXTBYTES;
    self->ss_len = CRYPTO_BYTES;

    self->ct = malloc(self->ct_len);
    if (self->ct == NULL) {
        ESP_LOGE(TAG_AKE, "Failed to allocate memory for ciphertext");
        goto cleanup;
    }

    self->ss = malloc(self->ss_len);
    if (self->ss == NULL) {
        ESP_LOGE(TAG_AKE, "Failed to allocate memory for shared secret");
        goto cleanup;
    }

    if (crypto_kem_enc(self->ct, self->ss, self->pk) != 0) {
        ESP_LOGE(TAG_AKE, "crypto_kem_enc failed");
        goto cleanup;
    }

    ESP_LOG_BUFFER_HEXDUMP("Cipher Text", self->ct, self->ct_len, ESP_LOG_INFO);
    ESP_LOG_BUFFER_HEXDUMP("Shared Secret", self->ss, self->ss_len, ESP_LOG_INFO);

    return true;

cleanup:
    free_kyber_object_node(self);
    return false;
}

bool derive_hkdf_sha512(const uint8_t *ikm, size_t ikm_len,
                        const uint8_t *salt, size_t salt_len,
                        const uint8_t *info, size_t info_len,
                        uint8_t *okm, size_t okm_len)
{
    if (ikm == NULL || ikm_len == 0 || okm == NULL || okm_len == 0) {
        ESP_LOGE(TAG_AKE, "Invalid HKDF input parameters");
        return false;
    }

    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
    if (md == NULL) {
        ESP_LOGE(TAG_AKE, "SHA-512 not available");
        return false;
    }

    int ret = mbedtls_hkdf(md,
                           salt, salt_len,
                           ikm, ikm_len,
                           info, info_len,
                           okm, okm_len);

    if (ret != 0) {
        ESP_LOGE(TAG_AKE, "mbedtls_hkdf failed: -0x%04X", (unsigned)(-ret));
        return false;
    }

    return true;
}

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

    if (self->ct_kyber != NULL)
        free(self->ct_kyber); //this structure doesn't have the ct
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

    self->step = 0;
}


void free_ake_key(struct ake_key *key)
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

bool compute_tag_d_hmac_sha512(const uint8_t *key, size_t key_len,
                               const uint8_t *sid, size_t sid_len,
                               const uint8_t *nonce_s, size_t nonce_s_len,
                               const uint8_t *nonce_d, size_t nonce_d_len,
                               const uint8_t *pk, size_t pk_len,
                               const uint8_t *ct, size_t ct_len,
                               const char *device_name,
                               uint8_t *tag_d, size_t tag_d_len)
{
    int ret;
    mbedtls_md_context_t ctx;
    const mbedtls_md_info_t *md;

    if (key == NULL || key_len == 0 ||
        sid == NULL || sid_len == 0 ||
        nonce_s == NULL || nonce_s_len == 0 ||
        nonce_d == NULL || nonce_d_len == 0 ||
        pk == NULL || pk_len == 0 ||
        ct == NULL || ct_len == 0 ||
        device_name == NULL ||
        tag_d == NULL || tag_d_len != SHA512_DIGEST_SIZE) {
        ESP_LOGE(TAG_AKE, "Invalid input parameter");
        return false;
    }

    md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
    if (md == NULL) {
        ESP_LOGE(TAG_AKE, "SHA-512 not available");
        return false;
    }

    mbedtls_md_init(&ctx);

    ret = mbedtls_md_setup(&ctx, md, 1);
    if (ret != 0) {
        ESP_LOGE(TAG_AKE, "mbedtls_md_setup failed: %d", ret);
        mbedtls_md_free(&ctx);
        return false;
    }

    ret = mbedtls_md_hmac_starts(&ctx, key, key_len);
    if (ret != 0) {
        ESP_LOGE(TAG_AKE, "mbedtls_md_hmac_starts failed: %d", ret);
        mbedtls_md_free(&ctx);
        return false;
    }

    ret = mbedtls_md_hmac_update(&ctx, sid, sid_len);
    if (ret != 0) {
        ESP_LOGE(TAG_AKE, "HMAC update SID failed: %d", ret);
        mbedtls_md_free(&ctx);
        return false;
    }

    ret = mbedtls_md_hmac_update(&ctx, nonce_s, nonce_s_len);
    if (ret != 0) {
        ESP_LOGE(TAG_AKE, "HMAC update nonce_s failed: %d", ret);
        mbedtls_md_free(&ctx);
        return false;
    }

    ret = mbedtls_md_hmac_update(&ctx, nonce_d, nonce_d_len);
    if (ret != 0) {
        ESP_LOGE(TAG_AKE, "HMAC update nonce_d failed: %d", ret);
        mbedtls_md_free(&ctx);
        return false;
    }

    ret = mbedtls_md_hmac_update(&ctx, pk, pk_len);
    if (ret != 0) {
        ESP_LOGE(TAG_AKE, "HMAC update PK failed: %d", ret);
        mbedtls_md_free(&ctx);
        return false;
    }

    ret = mbedtls_md_hmac_update(&ctx, ct, ct_len);
    if (ret != 0) {
        ESP_LOGE(TAG_AKE, "HMAC update CT failed: %d", ret);
        mbedtls_md_free(&ctx);
        return false;
    }

    ret = mbedtls_md_hmac_update(&ctx,
                                 (const unsigned char *)device_name,
                                 strlen(device_name));
    if (ret != 0) {
        ESP_LOGE(TAG_AKE, "HMAC update device_name failed: %d", ret);
        mbedtls_md_free(&ctx);
        return false;
    }

    ret = mbedtls_md_hmac_finish(&ctx, tag_d);
    if (ret != 0) {
        ESP_LOGE(TAG_AKE, "mbedtls_md_hmac_finish failed: %d", ret);
        mbedtls_md_free(&ctx);
        return false;
    }

    mbedtls_md_free(&ctx);
    return true;
}

bool build_request_2(struct request_step_2 *self,
                     const struct response_step_1 *res_step_1,
                     const struct kyber_object_node *kyber_obj,
                     struct ake_key *key_sess,
                     struct ake_key *key_auth,
                     const struct puf_object *puf_obj,
                     const char *device_name)
{
    if (self == NULL || res_step_1 == NULL || kyber_obj == NULL ||
        key_sess == NULL || key_auth == NULL || puf_obj == NULL ||
        device_name == NULL) {
        ESP_LOGE(TAG_AKE, "Invalid input parameter");
        return false;
    }

    if (res_step_1->sid == NULL || res_step_1->sid_len == 0 ||
        res_step_1->nonce_s == NULL || res_step_1->nonce_s_len == 0) {
        ESP_LOGE(TAG_AKE, "Invalid response_step_1 content");
        return false;
    }

    if (kyber_obj->pk == NULL || kyber_obj->pk_len == 0 ||
        kyber_obj->ct == NULL || kyber_obj->ct_len == 0 ||
        kyber_obj->ss == NULL || kyber_obj->ss_len == 0) {
        ESP_LOGE(TAG_AKE, "Invalid kyber object content");
        return false;
    }

    if (puf_obj->puf_hash_len == 0) {
        ESP_LOGE(TAG_AKE, "Invalid PUF object content");
        return false;
    }

    memset(self, 0, sizeof(*self));
    self->step = 2;

    /* Copy SID */
    self->sid_len = res_step_1->sid_len;
    self->sid = malloc(self->sid_len);
    if (self->sid == NULL) {
        ESP_LOGE(TAG_AKE, "Malloc failed for SID");
        goto cleanup;
    }
    memcpy(self->sid, res_step_1->sid, self->sid_len);

    /* Generate nonce_d */
    self->nonce_d_len = NONCE_SIZE;
    self->nonce_d = malloc(self->nonce_d_len);
    if (self->nonce_d == NULL) {
        ESP_LOGE(TAG_AKE, "Malloc failed for nonce_d");
        goto cleanup;
    }
    esp_fill_random(self->nonce_d, self->nonce_d_len);

    /* Copy Kyber ciphertext so request_step_2 owns its own buffer */
    self->ct_kyber_len = kyber_obj->ct_len;
    self->ct_kyber = malloc(self->ct_kyber_len);
    if (self->ct_kyber == NULL) {
        ESP_LOGE(TAG_AKE, "Malloc failed for ct_kyber");
        goto cleanup;
    }
    memcpy(self->ct_kyber, kyber_obj->ct, self->ct_kyber_len);

    /* Allocate tag buffer */
    self->tag_d_len = SHA512_DIGEST_SIZE;
    self->tag_d = malloc(self->tag_d_len);
    if (self->tag_d == NULL) {
        ESP_LOGE(TAG_AKE, "Malloc failed for tag_d");
        goto cleanup;
    }

    /* Derive Ksess = HKDF(ss, nonce_s, "Ksess") */
    key_sess->key_size = KEY_SIZE;
    key_sess->key = malloc(key_sess->key_size);
    if (key_sess->key == NULL) {
        ESP_LOGE(TAG_AKE, "Malloc failed for key_sess");
        goto cleanup;
    }

    key_sess->key_info = "Ksess";
    key_sess->key_info_len = strlen(key_sess->key_info);

    if (!derive_hkdf_sha512(kyber_obj->ss,
                            kyber_obj->ss_len,
                            res_step_1->nonce_s,
                            res_step_1->nonce_s_len,
                            (const uint8_t *)key_sess->key_info,
                            key_sess->key_info_len,
                            key_sess->key,
                            key_sess->key_size)) {
        ESP_LOGE(TAG_AKE, "Failed to derive Ksess");
        goto cleanup;
    }
    key_sess->ready = true;

    /* Derive Kauth = HKDF(puf_hash, nonce_s, "Kauth") */
    key_auth->key_size = KEY_SIZE;
    key_auth->key = malloc(key_auth->key_size);
    if (key_auth->key == NULL) {
        ESP_LOGE(TAG_AKE, "Malloc failed for key_auth");
        goto cleanup;
    }

    key_auth->key_info = "Kauth";
    key_auth->key_info_len = strlen(key_auth->key_info);

    if (!derive_hkdf_sha512(puf_obj->hash,
                            puf_obj->puf_hash_len,
                            res_step_1->nonce_s,
                            res_step_1->nonce_s_len,
                            (const uint8_t *)key_auth->key_info,
                            key_auth->key_info_len,
                            key_auth->key,
                            key_auth->key_size)) {
        ESP_LOGE(TAG_AKE, "Failed to derive Kauth");
        goto cleanup;
    }
    key_auth->ready = true;

    /* Compute TagD = HMAC-SHA512(Kauth, SID || nonce_s || nonce_d || PK || CT || device_name) */
    if (!compute_tag_d_hmac_sha512(key_auth->key,
                                   key_auth->key_size,
                                   self->sid,
                                   self->sid_len,
                                   res_step_1->nonce_s,
                                   res_step_1->nonce_s_len,
                                   self->nonce_d,
                                   self->nonce_d_len,
                                   kyber_obj->pk,
                                   kyber_obj->pk_len,
                                   self->ct_kyber,
                                   self->ct_kyber_len,
                                   device_name,
                                   self->tag_d,
                                   self->tag_d_len)) {
    ESP_LOGE(TAG_AKE, "Failed to compute TagD");
    goto cleanup;
}
    ESP_LOG_BUFFER_HEXDUMP(TAG_AKE, self->tag_d, self->tag_d_len, ESP_LOG_INFO);

    /* Base64 encode all fields for transport */
    if (base64_encode_alloc(self->sid, self->sid_len, &self->sid_b64) != 0) {
        ESP_LOGE(TAG_AKE, "Base64 encode failed for SID");
        goto cleanup;
    }

    if (base64_encode_alloc(self->nonce_d, self->nonce_d_len, &self->nonce_d_b64) != 0) {
        ESP_LOGE(TAG_AKE, "Base64 encode failed for nonce_d");
        goto cleanup;
    }

    if (base64_encode_alloc(self->ct_kyber, self->ct_kyber_len, &self->ct_kyber_b64) != 0) {
        ESP_LOGE(TAG_AKE, "Base64 encode failed for ct_kyber");
        goto cleanup;
    }

    if (base64_encode_alloc(self->tag_d, self->tag_d_len, &self->tag_d_b64) != 0) {
        ESP_LOGE(TAG_AKE, "Base64 encode failed for tag_d");
        goto cleanup;
    }

    ESP_LOGI(TAG_AKE, "Request step 2 built successfully");
    return true;

cleanup:
    free_request_2(self);
    free_ake_key(key_sess);
    free_ake_key(key_auth);
    return false;
}

bool send_http_request_2(struct request_step_2 *self,
                         char **json_response_output,
                         size_t *json_response_length,
                         const char *http_address)
{
    if (self == NULL || json_response_output == NULL ||
        json_response_length == NULL || http_address == NULL) {
        ESP_LOGE(TAG_AKE, "Invalid input parameter");
        return false;
    }

    if (self->sid_b64 == NULL || self->nonce_d_b64 == NULL ||
        self->ct_kyber_b64 == NULL || self->tag_d_b64 == NULL) {
        ESP_LOGE(TAG_AKE, "Invalid request_step_2 content");
        return false;
    }

    *json_response_output = NULL;
    *json_response_length = 0;

    cJSON *root = cJSON_CreateObject();
    if (root == NULL) {
        ESP_LOGE(TAG_AKE, "cJSON_CreateObject failed");
        return false;
    }

    if (cJSON_AddNumberToObject(root, "Step", self->step) == NULL ||
        cJSON_AddStringToObject(root, "SID", self->sid_b64) == NULL ||
        cJSON_AddNumberToObject(root, "SID_Len", (double)self->sid_len) == NULL ||
        cJSON_AddStringToObject(root, "Nonce_D", self->nonce_d_b64) == NULL ||
        cJSON_AddNumberToObject(root, "Nonce_D_Len", (double)self->nonce_d_len) == NULL ||
        cJSON_AddStringToObject(root, "CT_Kyber", self->ct_kyber_b64) == NULL ||
        cJSON_AddNumberToObject(root, "CT_Kyber_Len", (double)self->ct_kyber_len) == NULL ||
        cJSON_AddStringToObject(root, "Tag_D", self->tag_d_b64) == NULL ||
        cJSON_AddNumberToObject(root, "Tag_D_Len", (double)self->tag_d_len) == NULL) {
        ESP_LOGE(TAG_AKE, "Failed to build JSON request for step 2");
        cJSON_Delete(root);
        return false;
    }

    char *json_string = cJSON_Print(root);
    if (json_string == NULL) {
        ESP_LOGE(TAG_AKE, "cJSON_Print failed");
        cJSON_Delete(root);
        return false;
    }

    ESP_LOGI(TAG_AKE, "STEP 2 JSON: %s", json_string);

    esp_err_t err = http_post_and_get_response(
        http_address,
        json_string,
        json_response_output,
        json_response_length
    );

    cJSON_Delete(root);
    free(json_string);

    if (err != ESP_OK) {
        ESP_LOGE(TAG_AKE, "HTTP error transaction in step 2");
        return false;
    }

    if (*json_response_output != NULL) {
        ESP_LOGI(TAG_AKE, "Data response from step 2: %s", *json_response_output);
    }

    return true;
}

void free_response_step_2(struct response_step_2 *self)
{
    if (self == NULL) {
        return;
    }

    if (self->sid != NULL) {
        free(self->sid);
        self->sid = NULL;
    }

    if (self->tag_s != NULL) {
        free(self->tag_s);
        self->tag_s = NULL;
    }

    self->step = 0;
    self->sid_len = 0;
    self->tag_s_len = 0;
}

bool get_response_2(struct response_step_2 *self, char *json_response_output)
{
    if (self == NULL || json_response_output == NULL) {
        ESP_LOGE(TAG_AKE, "Invalid input parameter");
        return false;
    }

    self->step = 0;
    self->sid_len = 0;
    self->sid = NULL;
    self->tag_s_len = 0;
    self->tag_s = NULL;

    cJSON *receive_json_data = cJSON_Parse(json_response_output);
    if (receive_json_data == NULL) {
        ESP_LOGE(TAG_AKE, "JSON parse error");
        return false;
    }

    cJSON *step = cJSON_GetObjectItemCaseSensitive(receive_json_data, "Step");
    cJSON *sid_len = cJSON_GetObjectItemCaseSensitive(receive_json_data, "SID_Len");
    cJSON *sid = cJSON_GetObjectItemCaseSensitive(receive_json_data, "SID");
    cJSON *tag_s_len = cJSON_GetObjectItemCaseSensitive(receive_json_data, "Tag_S_Len");
    cJSON *tag_s = cJSON_GetObjectItemCaseSensitive(receive_json_data, "Tag_S");

    if (!cJSON_IsNumber(step) ||
        !cJSON_IsNumber(sid_len) ||
        !cJSON_IsString(sid) ||
        !cJSON_IsNumber(tag_s_len) ||
        !cJSON_IsString(tag_s)) {
        ESP_LOGE(TAG_AKE, "Invalid JSON response format");
        cJSON_Delete(receive_json_data);
        return false;
    }

    if (step->valueint != 2) {
        ESP_LOGE(TAG_AKE, "Unexpected step value: %d", step->valueint);
        cJSON_Delete(receive_json_data);
        return false;
    }

    self->step = step->valueint;
    self->sid_len = (size_t)sid_len->valueint;
    self->tag_s_len = (size_t)tag_s_len->valueint;

    uint8_t *sid_decoded = NULL;
    size_t sid_decoded_len = 0;

    if (base64_decode_alloc(sid->valuestring, &sid_decoded, &sid_decoded_len) != 0) {
        ESP_LOGE(TAG_AKE, "Error decoding SID");
        cJSON_Delete(receive_json_data);
        return false;
    }

    if (self->sid_len != sid_decoded_len) {
        ESP_LOGE(TAG_AKE, "Error decoding SID, size mismatch");
        free(sid_decoded);
        cJSON_Delete(receive_json_data);
        return false;
    }

    self->sid = sid_decoded;

    uint8_t *tag_s_decoded = NULL;
    size_t tag_s_decoded_len = 0;

    if (base64_decode_alloc(tag_s->valuestring, &tag_s_decoded, &tag_s_decoded_len) != 0) {
        ESP_LOGE(TAG_AKE, "Error decoding Tag_S");
        free(self->sid);
        self->sid = NULL;
        cJSON_Delete(receive_json_data);
        return false;
    }

    if (self->tag_s_len != tag_s_decoded_len) {
        ESP_LOGE(TAG_AKE, "Error decoding Tag_S, size mismatch");
        free(tag_s_decoded);
        free(self->sid);
        self->sid = NULL;
        cJSON_Delete(receive_json_data);
        return false;
    }

    self->tag_s = tag_s_decoded;

    cJSON_Delete(receive_json_data);
    return true;
}

// HMAC-SHA512(Ksess, SID || nonce_s || nonce_d)
bool verify_tag_s(const uint8_t *expected_tag_s,
                  size_t expected_tag_s_size,
                  const struct ake_key *ksess,
                  const uint8_t *sid,
                  size_t sid_len,
                  const uint8_t *nonce_s,
                  size_t nonce_s_len,
                  const uint8_t *nonce_d,
                  size_t nonce_d_len)
{
    int ret;
    uint8_t computed_tag_s[SHA512_DIGEST_SIZE];
    mbedtls_md_context_t ctx;
    const mbedtls_md_info_t *md;

    if (expected_tag_s == NULL || ksess == NULL ||
        sid == NULL || nonce_s == NULL || nonce_d == NULL) {
        ESP_LOGE(TAG_AKE, "Invalid input parameter");
        return false;
    }

    if (expected_tag_s_size != SHA512_DIGEST_SIZE) {
        ESP_LOGE(TAG_AKE, "Invalid expected TagS size: %u",
                 (unsigned)expected_tag_s_size);
        return false;
    }

    if (ksess->key == NULL || ksess->key_size == 0 || !ksess->ready) {
        ESP_LOGE(TAG_AKE, "Invalid session key");
        return false;
    }

    if (sid_len == 0 || nonce_s_len == 0 || nonce_d_len == 0) {
        ESP_LOGE(TAG_AKE, "Invalid input buffer length");
        return false;
    }

    md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
    if (md == NULL) {
        ESP_LOGE(TAG_AKE, "SHA-512 not available");
        return false;
    }

    mbedtls_md_init(&ctx);

    ret = mbedtls_md_setup(&ctx, md, 1);
    if (ret != 0) {
        ESP_LOGE(TAG_AKE, "mbedtls_md_setup failed: %d", ret);
        mbedtls_md_free(&ctx);
        return false;
    }

    ret = mbedtls_md_hmac_starts(&ctx, ksess->key, ksess->key_size);
    if (ret != 0) {
        ESP_LOGE(TAG_AKE, "mbedtls_md_hmac_starts failed: %d", ret);
        mbedtls_md_free(&ctx);
        return false;
    }

    ret = mbedtls_md_hmac_update(&ctx, sid, sid_len);
    if (ret != 0) {
        ESP_LOGE(TAG_AKE, "HMAC update SID failed: %d", ret);
        mbedtls_md_free(&ctx);
        return false;
    }

    ret = mbedtls_md_hmac_update(&ctx, nonce_s, nonce_s_len);
    if (ret != 0) {
        ESP_LOGE(TAG_AKE, "HMAC update nonce_s failed: %d", ret);
        mbedtls_md_free(&ctx);
        return false;
    }

    ret = mbedtls_md_hmac_update(&ctx, nonce_d, nonce_d_len);
    if (ret != 0) {
        ESP_LOGE(TAG_AKE, "HMAC update nonce_d failed: %d", ret);
        mbedtls_md_free(&ctx);
        return false;
    }

    ret = mbedtls_md_hmac_finish(&ctx, computed_tag_s);
    if (ret != 0) {
        ESP_LOGE(TAG_AKE, "mbedtls_md_hmac_finish failed: %d", ret);
        mbedtls_md_free(&ctx);
        return false;
    }

    mbedtls_md_free(&ctx);

    if (memcmp(computed_tag_s, expected_tag_s, SHA512_DIGEST_SIZE) != 0) {
        ESP_LOGE(TAG_AKE, "TagS verification failed");
        return false;
    }

    ESP_LOGI(TAG_AKE, "TagS verification successful");
    ESP_LOGI(TAG_AKE, "TagS: ");
    ESP_LOG_BUFFER_HEXDUMP(TAG_AKE, computed_tag_s, SHA512_DIGEST_SIZE, ESP_LOG_INFO);
    return true;
}


bool get_context_master_key(struct master_key *self,
                 size_t sid_len, const uint8_t *sid,
                 size_t nonce_s_len, const uint8_t *nonce_s,
                 size_t nonce_d_len, const uint8_t *nonce_d)
{
    if (self == NULL || sid == NULL || nonce_s == NULL || nonce_d == NULL)
        return false;

    // Free previous context if exists (avoid memory leak)
    if (self->context != NULL) {
        free(self->context);
        self->context = NULL;
        self->context_len = 0;
    }

    self->context_len = sid_len + nonce_s_len + nonce_d_len;

    self->context = malloc(self->context_len);
    if (self->context == NULL)
        return false;

    size_t offset = 0;

    memcpy(self->context + offset, sid, sid_len);
    offset += sid_len;

    memcpy(self->context + offset, nonce_s, nonce_s_len);
    offset += nonce_s_len;

    memcpy(self->context + offset, nonce_d, nonce_d_len);
    offset += nonce_d_len;

    return true;
}

bool derive_master_key(struct master_key *self,
                       const uint8_t *puf_hash, size_t puf_hash_size,
                       const uint8_t *ss, size_t ss_len)
{
    uint8_t *temp_buf = NULL;
    size_t temp_buf_size = 0;
    size_t offset = 0;
    const uint8_t *key_info = (const uint8_t *)"AKE KEY MASTER";
    size_t key_info_len = strlen((const char *)key_info);
    bool ret = false;

    if (self == NULL || puf_hash == NULL || ss == NULL) {
        return false;
    }

    if (puf_hash_size == 0 || ss_len == 0) {
        return false;
    }

    if (self->context == NULL || self->context_len == 0) {
        return false;
    }

    temp_buf_size = puf_hash_size + ss_len;
    temp_buf = malloc(temp_buf_size);
    if (temp_buf == NULL) {
        return false;
    }

    memcpy(temp_buf + offset, puf_hash, puf_hash_size);
    offset += puf_hash_size;

    memcpy(temp_buf + offset, ss, ss_len);
    offset += ss_len;

    if (offset != temp_buf_size) {
        goto cleanup;
    }

    if (self->key != NULL) {
        free(self->key);
        self->key = NULL;
        self->key_len = 0;
    }

    self->key_len = KEY_SIZE; /* 32 bytes = 256 bits */
    self->key = malloc(self->key_len);
    if (self->key == NULL) {
        self->key_len = 0;
        goto cleanup;
    }

    if (!derive_hkdf_sha512(temp_buf, temp_buf_size,
                            self->context, self->context_len,
                            key_info, key_info_len,
                            self->key, self->key_len)) {
        free(self->key);
        self->key = NULL;
        self->key_len = 0;
        goto cleanup;
    }

    ret = true;

cleanup:
    free(temp_buf);
    return ret;
}