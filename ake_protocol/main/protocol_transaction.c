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
    size_t mac_address_size;
    uint8_t *mac_address;
    size_t puf_hash_size;
    uint8_t *puf_hash;

    /* base 64 params*/
    char *mac_address_b64;
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
    size_t tad_d_len;
    uint8_t *tag_d;
    
    char *http_address;

    // base 64
    char *sid_b64;
    char *nonce_d_b64;
    char *ct_kyber_b64;
    char *tad_d_b64;
};

bool build_request_2(struct request_step_2 *self, char *http_post)
{
    if (self == NULL) {
        ESP_LOGE(TAG_PROT, "Invalid input parameter");
        return false;
    }

    self->sid = NULL;
    self->nonce_d = NULL;
    self->ct_kyber = NULL;
    self->tag_d = NULL;

    self->step = 0;
    self->http_address = http_post;

    self->mac_address = malloc(self->mac_address_size);
    if (self->mac_address == NULL) {
        ESP_LOGE(TAG_PROT, "malloc failed for mac_address");
        return false;
    }

    esp_efuse_mac_get_default(self->mac_address);

    self->puf_hash_size = puf->puf_hash_len;
    self->puf_hash = malloc(self->puf_hash_size);

    memcpy(self->puf_hash, puf->hash, self->puf_hash_size);

    if (base64_encode_alloc(self->puf_hash,
                            self->puf_hash_size,
                            &self->puf_hash_b64) != 0) {
        ESP_LOGE(TAG_PROT, "BASE64 ENCODE FAILURE (PUF)");
        free(self->puf_hash);
        free(self->mac_address);
        self->puf_hash = NULL;
        self->mac_address = NULL;
        return false;
    }

    return true;
}


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

    self->mac_address = NULL;
    self->puf_hash = NULL;
    self->mac_address_b64 = NULL;
    self->puf_hash_b64 = NULL;

    self->step = 0;
    self->device_name = DEVICE_NAME;
    self->http_address = http_post;

    self->mac_address_size = 6;
    self->mac_address = malloc(self->mac_address_size);
    if (self->mac_address == NULL) {
        ESP_LOGE(TAG_PROT, "malloc failed for mac_address");
        return false;
    }

    esp_efuse_mac_get_default(self->mac_address);

    self->puf_hash_size = puf->puf_hash_len;
    self->puf_hash = malloc(self->puf_hash_size);
    if (self->puf_hash == NULL) {
        ESP_LOGE(TAG_PROT, "malloc failed for puf_hash");
        free(self->mac_address);
        self->mac_address = NULL;
        return false;
    }

    memcpy(self->puf_hash, puf->hash, self->puf_hash_size);

    if (base64_encode_alloc(self->puf_hash,
                            self->puf_hash_size,
                            &self->puf_hash_b64) != 0) {
        ESP_LOGE(TAG_PROT, "BASE64 ENCODE FAILURE (PUF)");
        free(self->puf_hash);
        free(self->mac_address);
        self->puf_hash = NULL;
        self->mac_address = NULL;
        return false;
    }

    ESP_LOGI(TAG_PROT, "PUF_HASH(b64): %s", self->puf_hash_b64);

    if (base64_encode_alloc(self->mac_address,
                            self->mac_address_size,
                            &self->mac_address_b64) != 0) {
        ESP_LOGE(TAG_PROT, "BASE64 ENCODE FAILURE (MAC)");
        free(self->puf_hash_b64);
        free(self->puf_hash);
        free(self->mac_address);
        self->puf_hash_b64 = NULL;
        self->puf_hash = NULL;
        self->mac_address = NULL;
        return false;
    }

    ESP_LOGI(TAG_PROT, "MAC_ADDRESS(b64): %s", self->mac_address_b64);

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
    cJSON_AddStringToObject(root, "Mac_Address", self->mac_address_b64);
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

    free(self->mac_address);
    free(self->puf_hash);
    free(self->mac_address_b64);
    free(self->puf_hash_b64);

    self->mac_address = NULL;
    self->puf_hash = NULL;
    self->mac_address_b64 = NULL;
    self->puf_hash_b64 = NULL;

    self->mac_address_size = 0;
    self->puf_hash_size = 0;
    free(self);
}

bool get_response_0(struct response_step_0 *self, char *response_output ){
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
{   
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

    ESP_LOGI(TAG_PROT, "-------- [STEP 2] --------");
    //READ FROM SECURE STORAGE
    uint8_t *plain_pk_kyber= NULL;
    size_t plain_pk_kyber_len = 0;
    esp_err_t err = read_secure_storage_region_alloc("PK_KYBER", aes, &plain_pk_kyber, &plain_pk_kyber_len);
    ESP_LOG_BUFFER_HEXDUMP("HEX FORMAT", plain_pk_kyber, plain_pk_kyber_len, ESP_LOG_INFO);

    uint8_t *ct = malloc(CRYPTO_CIPHERTEXTBYTES);
    uint8_t *key_b = malloc(CRYPTO_BYTES);

    printf("2 -------- CRYPTO_KEM_ENC ENCRYPTION ----------- \n");
    crypto_kem_enc(ct, key_b, plain_pk_kyber);

    ESP_LOG_BUFFER_HEXDUMP("Cipher Text: ", ct, CRYPTO_CIPHERTEXTBYTES, ESP_LOG_INFO);
    ESP_LOG_BUFFER_HEXDUMP("Key B: ", key_b, CRYPTO_BYTES, ESP_LOG_INFO);

    size_t ksess_len = 32;
    uint8_t ksess[ksess_len];
    const uint8_t info_ksess[] = "Ksess";
    size_t info_ksess_len = sizeof(info_ksess);
    // derive_ksess_hkdf_sha512(key_b, CRYPTO_BYTES, response_step_1->nonce, response_step_1->nonce_len,
    // ksess, ksess_len);

    bool derivate_ksess = derive_hkdf_sha512(key_b, CRYPTO_BYTES, response_step_1->nonce, response_step_1->nonce_len,
                                            info_ksess, info_ksess_len, ksess, ksess_len);
    
    ESP_LOG_BUFFER_HEXDUMP("NONCE: ", response_step_1->nonce, response_step_1->nonce_len, ESP_LOG_INFO);
    ESP_LOG_BUFFER_HEXDUMP("SID", response_step_1->sid,response_step_1->sid_len, ESP_LOG_INFO);
    ESP_LOG_BUFFER_HEXDUMP("Key Session: ", ksess, ksess_len, ESP_LOG_INFO);

    free(plain_pk_kyber);

}