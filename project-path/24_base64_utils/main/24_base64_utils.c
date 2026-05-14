#include <stdio.h>
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
};

struct response_step_0{
    int step;
    char *server_name; 
    size_t kyber_pk_len;
    uint8_t *kyber_pk;

    /* base 64 params*/
    char *kyber_pk_b64;
};


void app_main(void)
{   
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ESP_ERROR_CHECK(nvs_flash_init());
    }

    wifi_init_sta();
    struct request_step_0 *r_step_0 = malloc(sizeof(struct request_step_0 ));
    r_step_0->step = 0;
    r_step_0->device_name = "Alex_ESP32";
    r_step_0->device_mac_size = 6;
    r_step_0->device_mac = malloc(r_step_0->device_mac_size);
    esp_efuse_mac_get_default(r_step_0->device_mac);
    r_step_0->puf_hash_size = 64;
    r_step_0->puf_hash = malloc(r_step_0->puf_hash_size);
    esp_fill_random(r_step_0->puf_hash , r_step_0->puf_hash_size);

    if (base64_encode_alloc(r_step_0->puf_hash, r_step_0->puf_hash_size, &r_step_0->puf_hash_b64) == 0) {
        ESP_LOGI("Struct", "PUF_HASH(b64): %s", r_step_0->puf_hash_b64);        
    }

    if (base64_encode_alloc(r_step_0->device_mac, r_step_0->device_mac_size , &r_step_0->device_mac_b64) == 0) {
        ESP_LOGI("Struct", "MAC_ADDRESS(b64): %s", r_step_0->device_mac_b64);        
    }

    cJSON *root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "Step", 0);
    cJSON_AddStringToObject(root, "Device_Name", r_step_0->device_name);     
    cJSON_AddStringToObject(root, "Mac_Address", r_step_0->device_mac_b64);
    cJSON_AddStringToObject(root, "PUF_Hash", r_step_0->puf_hash_b64);
    
    char *json_string = cJSON_Print(root);
    printf("%s\n", json_string);

    char *response_output;
    size_t response_length;
    char *http_post = "http://192.168.1.236:5000/example";
    esp_err_t err = http_post_and_get_response(http_post,
                                     json_string,
                                     &response_output,
                                     &response_length);
    if (err == ESP_OK){
        printf("The server is returning data\n");
        printf("Data Response: %s\n", response_output);
        
    }

    /*----- HOW TO PARSE THE DATA -----*/
    // receive the json info: 
    // 3) Parse JSON
    cJSON *receive_json_data= cJSON_Parse(response_output);
    cJSON *step = cJSON_GetObjectItem(receive_json_data, "Step");
    cJSON *pk_kyber = cJSON_GetObjectItem(receive_json_data, "kyber_pk");
    printf("Step Number: %d \n", step->valueint);
    printf("Kyber Value String: %s \n", pk_kyber->valuestring);
    // recover the key: 

    uint8_t *kypber_pk_b64_output = NULL; 
    size_t kypber_pk_b64_len = 0;

    if (base64_decode_alloc(pk_kyber->valuestring, &kypber_pk_b64_output, &kypber_pk_b64_len) == 0) {
        ESP_LOGI("B64", "Decoded bytes: %u", (unsigned)kypber_pk_b64_len);
        /* validate pk_len == CRYPTO_PUBLICKEYBYTES, etc. */
    }

    ESP_LOG_BUFFER_HEXDUMP("PK Kyber FORMAT RECOVERED", kypber_pk_b64_output, kypber_pk_b64_len, ESP_LOG_INFO);

    uint8_t *ct = malloc(CRYPTO_CIPHERTEXTBYTES);
    uint8_t *key_b = malloc(CRYPTO_BYTES);

    printf("2 -------- CRYPTO_KEM_ENC ENCRYPTION ----------- \n");
    crypto_kem_enc(ct, key_b, kypber_pk_b64_output);

    ESP_LOG_BUFFER_HEXDUMP("Cipher Text: ", ct, CRYPTO_CIPHERTEXTBYTES, ESP_LOG_INFO);
    ESP_LOG_BUFFER_HEXDUMP("Key B: ", key_b, CRYPTO_BYTES, ESP_LOG_INFO);



    // // Free Memory
    cJSON_Delete(root);
    free(response_output);
    free(json_string);
    free(receive_json_data);

    // ********** second transaction step 1

    // convert the ct to base64
    
    char *ct_b64;
    if (base64_encode_alloc(ct, CRYPTO_CIPHERTEXTBYTES, &ct_b64) == 0) {
        ESP_LOGI("Kyber", "Cipher Text(b64): %s", ct_b64);        
    }

    cJSON *root_2 = cJSON_CreateObject();
    cJSON_AddNumberToObject(root_2, "Step", 1);
    cJSON_AddStringToObject(root_2, "Cipher_Text", ct_b64);   

    char *json_string_2 = cJSON_Print(root_2);
    printf("%s\n", json_string_2);

    char *response_output_2;
    size_t response_length_2;
    err = http_post_and_get_response(http_post,
                                     json_string_2,
                                     &response_output_2,
                                     &response_length_2);
    if (err == ESP_OK){
        printf("The server is returning data\n");
        printf("Data Response: %s\n", response_output_2);
        
    }

    // char *device_name = "Alex_ESP32";
    // size_t iv_lenght = 16;
    // uint8_t iv[iv_lenght];
    // char *iv_b64 = NULL;

    // size_t puf_hash_lenght = 64;
    // uint8_t puf_hash[puf_hash_lenght];
    // char *puf_hash_b64 = NULL;

    // // IV Vector
    // esp_fill_random(iv, iv_lenght);
    // ESP_LOG_BUFFER_HEXDUMP("IV FORMAT", iv, iv_lenght, ESP_LOG_INFO);

    // if (base64_encode_alloc(iv, iv_lenght, &iv_b64) == 0) {
    //     ESP_LOGI("B64", "IV(b64): %s", iv_b64);        
    // }

    // // HASh PUF
    // esp_fill_random(puf_hash, puf_hash_lenght);
    // ESP_LOG_BUFFER_HEXDUMP("PUF HASH", puf_hash, puf_hash_lenght, ESP_LOG_INFO);

    // if (base64_encode_alloc(puf_hash, puf_hash_lenght, &puf_hash_b64) == 0) {
    //     ESP_LOGI("B64", "PUF_HASH(b64): %s", puf_hash_b64);        
    // }

    // cJSON *root = cJSON_CreateObject();
    // cJSON_AddNumberToObject(root, "Step", 0);
    // cJSON_AddStringToObject(root, "DeviceID", device_name);     
    // cJSON_AddNumberToObject(root, "IV_size", iv_lenght);
    // cJSON_AddStringToObject(root, "IV", iv_b64);
    // cJSON_AddNumberToObject(root, "Hash_size", puf_hash_lenght);
    // cJSON_AddStringToObject(root, "Hash", puf_hash_b64); 

    // char *json_string = cJSON_Print(root);
    // printf("%s\n", json_string);
    
    // char *response_output;
    // size_t response_length;
    // char *http_post = "http://192.168.1.236:5000/example";
    // esp_err_t err = http_post_and_get_response(http_post,
    //                                  json_string,
    //                                  &response_output,
    //                                  &response_length);
    // if (err == ESP_OK){
    //     printf("The server is returning data\n");
    //     printf("Data Response: %s\n", response_output);
    //     free(response_output);
    // }

    // // Free Memory
    // cJSON_Delete(root);
    // free(json_string);

}
