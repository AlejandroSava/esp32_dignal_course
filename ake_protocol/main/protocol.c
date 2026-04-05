#include <stdio.h>
#include <stdbool.h>

#include "esp_log.h"
#include "api_secure_storage.h"
#include "wifi.h"
#include "ake_protocol.h"

#define TAG_PROT "[Protocol Transactions]"

void app_main(void) 
{
    // starting the functions
    ESP_LOGI(TAG_PROT, "----- Initialize the NVS ------");
    init_nvs();
    ESP_LOGI(TAG_PROT, "----- Starting WiFi Driver -----");
    wifi_init_sta();
    ESP_LOGW(TAG_PROT, "Free heap after wifi and init: %u", (unsigned)esp_get_free_heap_size());

    /* Provisioning Secure Storage Parameters*/
    ESP_LOGI(TAG_PROT, "----- Setting Parameter for PUF and Secure Storage Region -----");
    struct puf_object *puf_obj = malloc(sizeof(struct puf_object)); /*PUF object*/   
    /*Create AES obj*/
    uint8_t key_sec_stor[AES_256]; //Key for AES Object
    struct aes_256_obj *aes_key_ss = malloc(sizeof(struct aes_256_obj));
    if(!derive_key_from_puf(&key_sec_stor[0], puf_obj, false)) { /*TODO: CHANGE TO TRUE AFTER PROVISIONING */
        ESP_LOGE(TAG_PROT, "Derivation Failure");
        return;
    }    
    create_aes_256_obj(aes_key_ss, &key_sec_stor[0]);


    /* Protocol transaction secction*/
    ESP_LOGI(TAG_PROT, "-----  PROTOCOL TRANSACTIONS -----");    
    const char *http_post = "http://192.168.1.236:5000/example"; 
    const char *device_name = "ESP_32_ALEX_SV";
    char *json_resp_out = NULL;
    size_t json_resp_len = 0;

    ESP_LOGI(TAG_PROT, "-------- [STEP 0] RoT --------");

    struct request_step_0 *req_step_0 = malloc(sizeof(struct request_step_0 ));    
    if (build_request_0(req_step_0, device_name, puf_obj) == false){
        ESP_LOGE(TAG_PROT, "Build request 0 Failure");
        return;
    }    
    if (send_http_request_0(req_step_0, &json_resp_out, &json_resp_len, http_post) != true){
        ESP_LOGE(TAG_PROT, "Error sending request 0");
        return;
    }

    struct response_step_0 *res_step_0 = malloc(sizeof(struct response_step_0 ));
    if(get_response_0(res_step_0, json_resp_out) == false){
        ESP_LOGE(TAG_PROT, "Error getting response 0");
        return;
    }
    if (write_secure_storage_region(res_step_0->kyber_pk, res_step_0->kyber_pk_len, 
        "PK_KYBER", aes_key_ss) !=ESP_OK){
        ESP_LOGE(TAG_PROT, "Error Writing in the secure storage region");
        return;
        }
    
    free(json_resp_out);

    ESP_LOGI(TAG_PROT, "-------- [STEP 1] --------");

    struct request_step_1 *req_step_1 = malloc(sizeof(struct request_step_1 ));
    if (build_request_1(req_step_1, device_name) == false) {
        ESP_LOGE(TAG_PROT, "Build request 1 Failure");
        return;
    }

    if (send_http_request_1(req_step_1, &json_resp_out, &json_resp_len, http_post) == false) {
        ESP_LOGE(TAG_PROT, "Error sending request 1");
        return;
    }
    struct response_step_1 *res_step_1 = malloc(sizeof(struct response_step_1));
    if(get_response_1(res_step_1, json_resp_out) == false){
        ESP_LOGE(TAG_PROT, "Error getting response 1");
        return;
    }
    free(json_resp_out);


    // ESP_LOG_BUFFER_HEXDUMP("DATA HEX FORMAT", response_step_1->nonce, response_step_1->nonce_len, ESP_LOG_INFO);
    // ESP_LOG_BUFFER_HEXDUMP("DATA HEX FORMAT", response_step_1->sid, response_step_1->sid_len, ESP_LOG_INFO);
    // ESP_LOGW(TAG_PROT, "PENDING TO FREE MEMORY FROM STEP 1");
    
    //free(response_output);


    // dealloacate the memory
    ESP_LOGW(TAG_PROT, "Free heap: %u", (unsigned)esp_get_free_heap_size());
    ESP_LOGI(TAG_PROT, "Free elements");
    free(puf_obj);
    free(aes_key_ss);
    free_request_step_0(req_step_0);
    free_response_step_0(res_step_0);
    // free request step 1 is not necessary!!! 
    free_response_step_1(res_step_1);

    //free(json_resp_out);
    ESP_LOGW(TAG_PROT, "Free heap: %u", (unsigned)esp_get_free_heap_size());
}