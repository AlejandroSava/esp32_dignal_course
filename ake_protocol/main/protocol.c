#include <stdio.h>
#include <stdbool.h>

#include "esp_log.h"
#include "api_secure_storage.h"
#include "wifi.h"
#include "ake_protocol.h"
#include "secure_channel.h"

#include "esp_timer.h"
#define TAG_PROT "[Protocol Transactions]"

struct device_info{
    const char *device_name;
    size_t device_name_size;
    uint8_t *device_mac;
    size_t device_mac_size;
    size_t puf_hash_len;
    uint8_t *puf_hash;    
};

bool get_device_info(struct device_info *self, const char *device_name, struct puf_object *puf_obj){
    self->device_name = device_name;
    self->device_name_size = strlen(device_name);
    self->device_mac_size = 6; 

    self->device_mac = malloc(self->device_mac_size);
    if (self->device_mac == NULL) {
        ESP_LOGE(TAG_AKE, "Malloc failed for mac_address");
        return false;
    }

    if (esp_efuse_mac_get_default(self->device_mac) != ESP_OK) {
        ESP_LOGE(TAG_AKE, "Error getting mac address from fuses");
        return false;
    }

    self->puf_hash_len = PUF_512_HASH_LEN;
    self->puf_hash = malloc(self->puf_hash_len);
    if (self->puf_hash == NULL) {
        ESP_LOGE(TAG_AKE, "Malloc failed for mac_address");
        return false;
    }
    memcpy(self->puf_hash, puf_obj->puf_hash, self->puf_hash_len);

}

void start_drivers(){

    ESP_LOGI(TAG_PROT, "----- Initialize the NVS ------");
    init_nvs();
    ESP_LOGI(TAG_PROT, "----- Starting WiFi Driver -----");
    wifi_init_sta();
}

void app_main(void) 
{
    // starting the functions

    ESP_LOGW(TAG_PROT, "----- STARTING THE DRIVERS ------");
    start_drivers();
    
    /* Provisioning Secure Storage Parameters*/
    ESP_LOGI(TAG_PROT, "----- Setting Parameter for PUF and Secure Storage Region -----");
    struct puf_object *puf_obj = malloc(sizeof(struct puf_object)); /*PUF object*/   
    /*Create AES obj for secure storage*/
    struct aes_256_obj *aes_key_ss = malloc(sizeof(struct aes_256_obj));
    get_puf_obj_from_puf(puf_obj, true); /*CHANGE TO TRUE AFTER PROVISIONING */
    derive_aes_puf_key_from_puf(puf_obj, aes_key_ss);

    

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

   
    
    ESP_LOGW(TAG_PROT, "Free heap end STEP 0: %u", (unsigned)esp_get_free_heap_size());

    ESP_LOGI(TAG_PROT, "-------- [STEP 1] --------");

    ESP_LOGW(TAG_PROT, "Free heap STEP 1 start: %u", (unsigned)esp_get_free_heap_size());
    

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

    
    
    ESP_LOGW(TAG_PROT, "Free heap end STEP 1: %u", (unsigned)esp_get_free_heap_size());

    ESP_LOGI(TAG_PROT, "-------- [STEP 2] --------");
    ESP_LOGW(TAG_PROT, "Free heap STEP 2 start: %u", (unsigned)esp_get_free_heap_size());
   

    struct master_key *master_key = malloc(sizeof(struct master_key));
    struct ake_key *key_sess = malloc(sizeof(struct ake_key));      
    struct ake_key *key_auth = malloc(sizeof(struct ake_key));  
    struct request_step_2 *req_step_2 = malloc(sizeof(struct request_step_2));
    struct kyber_object_node *kyber_obj = malloc(sizeof(struct kyber_object_node));
    

    ESP_LOGI(TAG_PROT, "Get Kyber Object"); 
    if (get_kyber_object_node(kyber_obj, aes_key_ss) != true){
        ESP_LOGE(TAG_PROT, "Error creating Kyber Object");
        return;
    }
    
    build_request_2(req_step_2, res_step_1, kyber_obj, master_key, key_sess, key_auth, puf_obj, device_name);
    ESP_LOG_BUFFER_HEXDUMP("Context ", master_key->context, master_key->context_len, ESP_LOG_WARN);
    ESP_LOG_BUFFER_HEXDUMP("Master Key: ", master_key->key, master_key->key_len, ESP_LOG_WARN);
    ESP_LOG_BUFFER_HEXDUMP("Key Authentication: ", key_auth->key, key_auth->key_size, ESP_LOG_WARN);
    ESP_LOG_BUFFER_HEXDUMP("Key Session: ", key_sess->key, key_sess->key_size, ESP_LOG_WARN);
    ESP_LOG_BUFFER_HEXDUMP("Tag_D: ", req_step_2->tag_d, req_step_2->tag_d_len, ESP_LOG_WARN);
    
 
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
    
    
   
    ESP_LOGW(TAG_PROT, "Free heap end STEP 2: %u", (unsigned)esp_get_free_heap_size());

    //SECURE CHANNEL
    ESP_LOGI(TAG_AKE, "------------- SECURE CHANNEL -------------");
    ESP_LOGW(TAG_PROT, "Free heap Secure channel start: %u", (unsigned)esp_get_free_heap_size());
    

    struct secure_session *session = malloc(sizeof(struct secure_session));    
    start_secure_channel_session(session, 
                                 res_step_2->sid,
                                 res_step_2->sid_len,
                                 key_sess->key,
                                 key_sess->key);
    for(int i = 0; i <1; i++){
        struct secure_plain_data *plain_data= malloc(sizeof(struct secure_plain_data));
        struct secure_message *secure_chan_message = malloc(sizeof(struct secure_message));
        struct secure_message *rsp_sec_channel_mesg = malloc(sizeof(struct secure_message));
        struct secure_plain_data *rsp_plain_data= malloc(sizeof(struct secure_plain_data));
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
        get_secure_channel_response(rsp_sec_channel_mesg, json_resp_out);
        get_response_plain_data_json(rsp_sec_channel_mesg, 
                                  session,
                                  rsp_plain_data);
        ESP_LOG_BUFFER_HEXDUMP("RESPONSE DATA FROM SECURE CHANNEL: ", rsp_plain_data->payload, rsp_plain_data->payload_len, ESP_LOG_WARN);

        free_secure_plain_data(plain_data);
        free_secure_message(secure_chan_message);
        free_secure_message(rsp_sec_channel_mesg);
        free_secure_plain_data(rsp_plain_data);
        free(json_resp_out);
    }

    free_secure_channel_session(session);

    
    
    ESP_LOGW(TAG_PROT, "Free heap end secure channel: %u", (unsigned)esp_get_free_heap_size());

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
    free_master_key(master_key);
    free_ake_key(key_sess);
    free_ake_key(key_auth);
    free_response_step_2(res_step_2);

    //free(json_resp_out);
    ESP_LOGW(TAG_PROT, "The memory is Free!!!");
    ESP_LOGW(TAG_PROT, "Free heap: %u", (unsigned)esp_get_free_heap_size());
}