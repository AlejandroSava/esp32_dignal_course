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