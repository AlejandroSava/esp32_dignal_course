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

#include "api_secure_storage.h"
#define DEVICE_NAME "Alex_ESP32"
#define TAG_PROT "[AKE PROTOCOL]"

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
    char *server_name; 
    size_t kyber_pk_len;
    uint8_t *kyber_pk;

    /* base 64 params*/
    char *kyber_pk_b64;
};

void init_nvs(){
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ESP_ERROR_CHECK(nvs_flash_init());
    }
    else
        ESP_LOGI("NVS_INIT", "Starting NVS INIT");  
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
        "http://192.168.1.236:5000/example",
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
    struct request_step_0 *req_step_0 = malloc(sizeof(struct request_step_0 ));
    char *http_post = "http://192.168.1.236:5000/example"; 
    if (build_request_0(req_step_0, puf_obj, http_post) == false){
        ESP_LOGE(TAG_PROT, "Build request 0 Failure");
        return;
    }
    char *response_output = NULL;
    size_t response_length = 0;
    bool resp_0 = send_http_request_0(req_step_0, &response_output, &response_length);
    free_request_0(req_step_0);
    free(response_output);
}