#include <stdio.h>
#include <stdbool.h>

#include "esp_log.h"
#include "api_secure_storage.h"
#include "wifi.h"
#include "ake_protocol.h"
#include "secure_channel.h"

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

    ESP_LOGI(TAG_PROT, "-------- [STEP 2] --------");
    
    struct ake_key *key_sess = malloc(sizeof(struct ake_key));  
    struct ake_key *key_auth = malloc(sizeof(struct ake_key));   
    struct request_step_2 *req_step_2 = malloc(sizeof(struct request_step_2));
    struct kyber_object_node *kyber_obj = malloc(sizeof(struct kyber_object_node));

    ESP_LOGI(TAG_PROT, "Get Kyber Object"); 
    if (get_kyber_object_node(kyber_obj, aes_key_ss) != true){
        ESP_LOGE(TAG_PROT, "Error creating Kyber Object");
        return;
    }
    
    build_request_2(req_step_2, res_step_1, kyber_obj, key_sess, key_auth, puf_obj, device_name);

    ESP_LOG_BUFFER_HEXDUMP("Key Session: ", key_sess->key, key_sess->key_size, ESP_LOG_INFO);
    ESP_LOG_BUFFER_HEXDUMP("Key Authentication: ", key_auth->key, key_auth->key_size, ESP_LOG_INFO);
 
    if (send_http_request_2(req_step_2, &json_resp_out, &json_resp_len, http_post) == false){
        ESP_LOGE(TAG_PROT, "Error sending request 2");
        return;
    }
    struct response_step_2 *res_step_2 = malloc(sizeof(struct response_step_2));
    if(get_response_2(res_step_2, json_resp_out) == false){
        ESP_LOGE(TAG_PROT, "Error getting response 2");
        return;
    }
    bool tag_s_verification = verify_tag_s(res_step_2->tag_s,
                 res_step_2->tag_s_len,
                 key_sess,
                 res_step_2->sid,
                 res_step_2->sid_len,
                 res_step_1->nonce_s,
                 res_step_1->nonce_s_len,
                 req_step_2->nonce_d,
                 req_step_2->nonce_d_len);
    
    ESP_LOGI(TAG_AKE, "Tag S verification: %s",
         tag_s_verification ? "SUCCESS" : "FAILURE");

    free(json_resp_out);

    //SECURE CHANNEL
    ESP_LOGI(TAG_AKE, "------------- SECURE CHANNEL -------------");
    struct secure_session *session = malloc(sizeof(struct secure_session));    
    start_secure_channel_session(session, 
                                 res_step_2->sid,
                                 res_step_2->sid_len,
                                 key_sess->key,
                                 key_sess->key);
    for(int i = 0; i <10; i++){
        struct secure_plain_data *plain_data= malloc(sizeof(struct secure_plain_data));
        struct secure_message *secure_chan_message = malloc(sizeof(struct secure_message));
        float temperature = 25.6f + i;
        ESP_LOGI(TAG_AKE,"the temperature is: %f", temperature);
        build_secure_plain_data_float(plain_data,
                                    (const uint8_t *)&temperature,
                                    sizeof(float));
        build_secure_message(secure_chan_message,
                            session,
                            plain_data);
        ESP_LOG_BUFFER_HEXDUMP("[Cipher Data]", secure_chan_message->ciphertext, secure_chan_message->ciphertext_len, ESP_LOG_INFO);
        send_secure_channel_message(secure_chan_message,
                                    &json_resp_out, 
                                    &json_resp_len,
                                    http_post);
        
        free_secure_plain_data(plain_data);
        free_secure_message(secure_chan_message);
        free(json_resp_out);
    }

    free_secure_channel_session(session);


    // dealloacate the memory
    ESP_LOGW(TAG_PROT, "Free heap: %u", (unsigned)esp_get_free_heap_size());
    ESP_LOGI(TAG_PROT, "Free elements");
    free(puf_obj);
    free(aes_key_ss);
    free_request_step_0(req_step_0);
    free_response_step_0(res_step_0);
    free_request_step_1(req_step_1);
    free_response_step_1(res_step_1);
    free_kyber_object_node(kyber_obj);
    free_request_2(req_step_2);
    free_ake_key(key_sess);
    free_ake_key(key_auth);
    free_response_step_2(res_step_2);

    //free(json_resp_out);
    ESP_LOGW(TAG_PROT, "The memory is Free!!!");
    ESP_LOGW(TAG_PROT, "Free heap: %u", (unsigned)esp_get_free_heap_size());
}