#include <stdio.h>
#include <stdbool.h>

#include "esp_log.h"
#include "api_secure_storage.h"
#include "wifi.h"
#include "ake_protocol.h"
#include "secure_channel.h"

#include "esp_timer.h"
#define TAG_PROT "[Protocol Transactions]"


void start_drivers(){

    ESP_LOGI(TAG_PROT, "----- Initialize the NVS ------");
    init_nvs();
    ESP_LOGI(TAG_PROT, "----- Starting WiFi Driver -----");
    wifi_init_sta();
}

bool root_of_trust_process(const char *http_post, struct device_info *device_info, struct aes_256_obj *aes_key_ss )
{
    ESP_LOGI(TAG_PROT, "-------- [STEP 0] RoT --------");

    if (device_info == NULL || http_post == NULL) {
        ESP_LOGE(TAG_PROT, "Invalid input parameters");
        return false;
    }

    bool status = false;

    char *json_resp_out = NULL;
    size_t json_resp_len = 0;

    struct request_step_0 *req_step_0 = calloc(1, sizeof(struct request_step_0));
    if (req_step_0 == NULL) {
        ESP_LOGE(TAG_PROT, "Malloc failed for request_step_0");
        return status;
    }

    struct response_step_0 *res_step_0 = calloc(1, sizeof(struct response_step_0));
    if (res_step_0 == NULL) {
        ESP_LOGE(TAG_PROT, "Malloc failed for response_step_0");
        free(req_step_0);
        return status;
    }

    if (build_request_0(req_step_0, device_info) == false) {
        ESP_LOGE(TAG_PROT, "Build request 0 failure");
        goto cleanup;
    }

    if (send_http_request_0(req_step_0,
                            &json_resp_out,
                            &json_resp_len,
                            http_post) != true) {
        ESP_LOGE(TAG_PROT, "Error sending request 0");
        goto cleanup;
    }

    if (get_response_0(res_step_0, json_resp_out) == false) {
        ESP_LOGE(TAG_PROT, "Error getting response 0");
        goto cleanup;
    }

    if (write_secure_storage_region(res_step_0->kyber_pk,
                                    res_step_0->kyber_pk_len,
                                    "PK_KYBER",
                                    aes_key_ss) != ESP_OK) {
        ESP_LOGE(TAG_PROT, "Error writing in the secure storage region");
        goto cleanup;
    }

    status = true;

cleanup:
    free_request_step_0(req_step_0);
    free_response_step_0(res_step_0);

    free(json_resp_out);
    json_resp_out = NULL;

    return status;
}


bool ake_flow(const char *http_post,
              struct device_info *device_info,
              struct aes_256_obj *aes_key_ss,
              struct secure_session *session)
{
    ESP_LOGI(TAG_PROT, "-------- AKE FLOW STEP 1 & 2 --------");

    if (http_post == NULL || device_info == NULL || aes_key_ss == NULL || session == NULL) {
        ESP_LOGE(TAG_PROT, "Invalid input parameters");
        return false;
    }

    bool status = false;

    char *json_resp_step1_out = NULL;
    size_t json_resp_step1_len = 0;

    char *json_resp_step2_out = NULL;
    size_t json_resp_step2_len = 0;

    struct request_step_1 *req_step_1 = NULL;
    struct response_step_1 *res_step_1 = NULL;
    struct request_step_2 *req_step_2 = NULL;
    struct response_step_2 *res_step_2 = NULL;
    struct kyber_object_node *kyber_obj = NULL;
    struct master_key *master_key = NULL;
    struct ake_key *key_sess = NULL;
    struct ake_key *key_auth = NULL;
    struct ake_key *key_hmac_sec_cha = NULL;

    req_step_1 = calloc(1, sizeof(struct request_step_1));
    res_step_1 = calloc(1, sizeof(struct response_step_1));
    req_step_2 = calloc(1, sizeof(struct request_step_2));
    res_step_2 = calloc(1, sizeof(struct response_step_2));
    kyber_obj = calloc(1, sizeof(struct kyber_object_node));
    master_key = calloc(1, sizeof(struct master_key));
    key_sess = calloc(1, sizeof(struct ake_key));
    key_auth = calloc(1, sizeof(struct ake_key));
    key_hmac_sec_cha = calloc(1, sizeof(struct ake_key));

    if (req_step_1 == NULL || res_step_1 == NULL ||
        req_step_2 == NULL || res_step_2 == NULL ||
        kyber_obj == NULL || master_key == NULL ||
        key_sess == NULL || key_auth == NULL ||
        key_hmac_sec_cha == NULL) {
        ESP_LOGE(TAG_PROT, "Memory allocation failed in AKE flow");
        goto cleanup;
    }

    ESP_LOGI(TAG_PROT, "-------- [STEP 1] --------");

    if (build_request_1(req_step_1, device_info) == false) {
        ESP_LOGE(TAG_PROT, "Build request 1 failure");
        goto cleanup;
    }

    if (send_http_request_1(req_step_1,
                            &json_resp_step1_out,
                            &json_resp_step1_len,
                            http_post) == false) {
        ESP_LOGE(TAG_PROT, "Error sending request 1");
        goto cleanup;
    }

    if (get_response_1(res_step_1, json_resp_step1_out) == false) {
        ESP_LOGE(TAG_PROT, "Error getting response 1");
        goto cleanup;
    }

    ESP_LOGI(TAG_PROT, "-------- [STEP 2] --------");

    if (get_kyber_object_node(kyber_obj, aes_key_ss) == false) {
        ESP_LOGE(TAG_PROT, "Error creating Kyber object");
        goto cleanup;
    }

    if (build_request_2(req_step_2,
                        res_step_1,
                        kyber_obj,
                        master_key,
                        key_auth,
                        key_sess,
                        key_hmac_sec_cha,
                        device_info) == false) {
        ESP_LOGE(TAG_PROT, "Error creating request 2");
        goto cleanup;
    }

    ESP_LOG_BUFFER_HEXDUMP("Context", master_key->context,
                           master_key->context_len, ESP_LOG_WARN);
    ESP_LOG_BUFFER_HEXDUMP("Master Key", master_key->key,
                           master_key->key_len, ESP_LOG_WARN);
    ESP_LOG_BUFFER_HEXDUMP("Key Authentication", key_auth->key,
                           key_auth->key_size, ESP_LOG_WARN);
    ESP_LOG_BUFFER_HEXDUMP("Key Session", key_sess->key,
                           key_sess->key_size, ESP_LOG_WARN);
    ESP_LOG_BUFFER_HEXDUMP("Tag_D", req_step_2->tag_d,
                           req_step_2->tag_d_len, ESP_LOG_WARN);

    if (send_http_request_2(req_step_2,
                            &json_resp_step2_out,
                            &json_resp_step2_len,
                            http_post) == false) {
        ESP_LOGE(TAG_PROT, "Error sending request 2");
        goto cleanup;
    }

    if (get_response_2(res_step_2, json_resp_step2_out) == false) {
        ESP_LOGE(TAG_PROT, "Error getting response 2");
        goto cleanup;
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

    if (tag_s_verification == false) {
        ESP_LOGE(TAG_PROT, "Error in TAG_S verification");
        goto cleanup;
    }

    if (start_secure_channel_session(session,
                                     res_step_2->sid,
                                     res_step_2->sid_len,
                                     key_sess->key,
                                     key_hmac_sec_cha->key) == false) {
        ESP_LOGE(TAG_PROT, "Error starting secure channel session");
        goto cleanup;
    }

    status = true;

cleanup:
    free(json_resp_step1_out);
    free(json_resp_step2_out);

    free_request_step_1(req_step_1);
    free_response_step_1(res_step_1);
    free_kyber_object_node(kyber_obj);
    free_request_2(req_step_2);
    free_master_key(master_key);
    free_ake_key(key_sess);
    free_ake_key(key_hmac_sec_cha);
    free_ake_key(key_auth);
    free_response_step_2(res_step_2);

    return status;
}

void app_main(void) 
{

    /* Provisioning Secure Storage Parameters*/
    ESP_LOGW(TAG_PROT, "----- STARTING THE DRIVERS ------");
    start_drivers();

    ESP_LOGI(TAG_PROT, "----- Setting Parameter for PUF and Secure Storage Region -----");    
    struct puf_object *puf_obj = malloc(sizeof(struct puf_object)); /*PUF object*/   
    struct aes_256_obj *aes_key_ss = malloc(sizeof(struct aes_256_obj));
    get_puf_obj_from_puf(puf_obj, true); /*CHANGE TO TRUE AFTER PROVISIONING */
    derive_aes_puf_key_from_puf(puf_obj, aes_key_ss);

    
    ESP_LOGI(TAG_PROT, "-----  PROTOCOL TRANSACTIONS -----");    
    const char *http_post = "http://192.168.1.236:5000/example"; 
    char *device_name = "ESP_32_ALEX_SV";
    struct device_info *device_info = malloc(sizeof(struct device_info));
    get_device_info(device_info, device_name, puf_obj);
    char *json_resp_out = NULL;
    size_t json_resp_len = 0; 

    // uint8_t prov = 0x1;
    // esp_err_t prov_err; 

    // uint8_t *prov_received;
    // size_t prov_received_size;
    // printf("AFTER READ"); 
    // if (read_secure_storage_region_alloc("PROV", aes_key_ss,&prov_received,&prov_received_size) == ESP_OK)
    //     ESP_LOG_BUFFER_HEXDUMP("PROV RECEIVED: ", prov_received, prov_received_size, ESP_LOG_WARN);

    // printf("AFTER WRITE"); 
    // prov_err = write_secure_storage_region(&prov, sizeof(uint8_t), "PROV", aes_key_ss);


   if (root_of_trust_process(http_post, device_info, aes_key_ss) == false){
        ESP_LOGE(TAG_PROT, "ERROR IN ROOT OF TRUST PROCESS");
        return;
   }
    
    struct secure_session *session = malloc(sizeof(struct secure_session)); 
    if (ake_flow(http_post, device_info, aes_key_ss, session) == false)
    {
        ESP_LOGE(TAG_PROT, "ERROR IN AKE FLOW");
        return;
   }
    ESP_LOGI(TAG_AKE, "------------- SECURE CHANNEL -------------");
// TODO: MOVE THIS PART TO A FUNCTION
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

    

    free_device_info(device_info);
    free_secure_channel_session(session);
    free(puf_obj);
    free(aes_key_ss);
}