#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "secure_storage_nvs.h"
#include "api_secure_storage.h"
#include "secure_channel.h"
#include "ake_protocol.h"
#include "api_ake_protocol.h"

#include "esp_system.h"
#include "esp_log.h"
#include "cJSON.h"
#define HEAP_LOG(label) \
    ESP_LOGW(TAG_API_AKE, "%s | Free heap: %u | Min heap: %u", \
             label, \
             (unsigned)esp_get_free_heap_size(), \
             (unsigned)esp_get_minimum_free_heap_size())


    

bool root_of_trust_process(const char *http_post, struct device_info *device_info,
                           struct aes_256_obj *aes_key_ss, struct aes_256_obj *hmac_key_ss )
{
    ESP_LOGI(TAG_API_AKE, "-------- [STEP 0] RoT --------");

    if (device_info == NULL || http_post == NULL) {
        ESP_LOGE(TAG_API_AKE, "Invalid input parameters");
        return false;
    }

    bool status = false;

    char *json_resp_out = NULL;
    size_t json_resp_len = 0;

    struct request_step_0 *req_step_0 = calloc(1, sizeof(struct request_step_0));
    if (req_step_0 == NULL) {
        ESP_LOGE(TAG_API_AKE, "Malloc failed for request_step_0");
        return status;
    }

    struct response_step_0 *res_step_0 = calloc(1, sizeof(struct response_step_0));
    if (res_step_0 == NULL) {
        ESP_LOGE(TAG_API_AKE, "Malloc failed for response_step_0");
        free(req_step_0);
        return status;
    }

    if (build_request_0(req_step_0, device_info) == false) {
        ESP_LOGE(TAG_API_AKE, "Build request 0 failure");
        goto cleanup;
    }

    if (send_http_request_0(req_step_0,
                            &json_resp_out,
                            &json_resp_len,
                            http_post) != true) {
        ESP_LOGE(TAG_API_AKE, "Error sending request 0");
        goto cleanup;
    }

    if (get_response_0(res_step_0, json_resp_out) == false) {
        ESP_LOGE(TAG_API_AKE, "Error getting response 0");
        goto cleanup;
    }

    if (write_secure_storage_region(res_step_0->kyber_pk,
                                    res_step_0->kyber_pk_len,
                                    "PK_KYBER",
                                    aes_key_ss,
                                    hmac_key_ss) != ESP_OK) {
        ESP_LOGE(TAG_API_AKE, "Error writing in the secure storage region");
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
              struct aes_256_obj *hmac_key_ss,
              struct secure_session *session)
{
    ESP_LOGI(TAG_API_AKE, "-------- AKE FLOW STEP 1 & 2 --------");

    if (http_post == NULL || device_info == NULL || aes_key_ss == NULL || session == NULL) {
        ESP_LOGE(TAG_API_AKE, "Invalid input parameters");
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
        ESP_LOGE(TAG_API_AKE, "Memory allocation failed in AKE flow");
        goto cleanup;
    }

    ESP_LOGI(TAG_API_AKE, "-------- [STEP 1] --------");

    if (build_request_1(req_step_1, device_info) == false) {
        ESP_LOGE(TAG_API_AKE, "Build request 1 failure");
        goto cleanup;
    }

    if (send_http_request_1(req_step_1,
                            &json_resp_step1_out,
                            &json_resp_step1_len,
                            http_post) == false) {
        ESP_LOGE(TAG_API_AKE, "Error sending request 1");
        goto cleanup;
    }

    if (get_response_1(res_step_1, json_resp_step1_out) == false) {
        ESP_LOGE(TAG_API_AKE, "Error getting response 1");
        goto cleanup;
    }

    ESP_LOGI(TAG_API_AKE, "-------- [STEP 2] --------");

    if (get_kyber_object_node(kyber_obj, aes_key_ss, hmac_key_ss) == false) {
        ESP_LOGE(TAG_API_AKE, "Error creating Kyber object");
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
        ESP_LOGE(TAG_API_AKE, "Error creating request 2");
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
        ESP_LOGE(TAG_API_AKE, "Error sending request 2");
        goto cleanup;
    }

    if (get_response_2(res_step_2, json_resp_step2_out) == false) {
        ESP_LOGE(TAG_API_AKE, "Error getting response 2");
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
        ESP_LOGE(TAG_API_AKE, "Error in TAG_S verification");
        goto cleanup;
    }

    if (start_secure_channel_session(session,
                                     res_step_2->sid,
                                     res_step_2->sid_len,
                                     key_sess->key,
                                     key_hmac_sec_cha->key) == false) {
        ESP_LOGE(TAG_API_AKE, "Error starting secure channel session");
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

bool send_float_secure_channel(const char *http_post,
                               struct secure_session *session,
                               struct secure_plain_data *rsp_plain_data,
                               float data)
{
    HEAP_LOG("[SC] 0 begin");

    if (http_post == NULL || session == NULL || rsp_plain_data == NULL) {
        ESP_LOGE(TAG_API_AKE, "Invalid input parameters");
        return false;
    }

    bool return_value = false;

    char *json_resp_sec_cha_out = NULL;
    size_t json_resp_sec_cha_len = 0;

    struct secure_plain_data *plain_data =
        calloc(1, sizeof(struct secure_plain_data));


    struct secure_message *secure_chan_message =
        calloc(1, sizeof(struct secure_message));

    struct secure_message *rsp_sec_channel_mesg =
        calloc(1, sizeof(struct secure_message));

    if (plain_data == NULL ||
        secure_chan_message == NULL ||
        rsp_sec_channel_mesg == NULL) {
        ESP_LOGE(TAG_API_AKE, "Memory allocation failed");
        goto cleanup;
    }

    ESP_LOGI(TAG_AKE, "The data is: %f", data);


    if (build_secure_plain_data_float(plain_data,
                                      (const uint8_t *)&data,
                                      sizeof(float)) == false) {
        ESP_LOGE(TAG_API_AKE, "Error building secure plain data float");
        goto cleanup;
    }


    if (build_secure_message(secure_chan_message,
                             session,
                             plain_data) == false) {
        ESP_LOGE(TAG_API_AKE, "Error building secure message");
        goto cleanup;
    }


    ESP_LOG_BUFFER_HEXDUMP("[Cipher Data]",
                           secure_chan_message->ciphertext,
                           secure_chan_message->ciphertext_len,
                           ESP_LOG_INFO);


    if (send_secure_channel_message(secure_chan_message,
                                    &json_resp_sec_cha_out,
                                    &json_resp_sec_cha_len,
                                    http_post) == false) {
        ESP_LOGE(TAG_API_AKE, "Error sending secure message");
        goto cleanup;
    }


    if (get_secure_channel_response(rsp_sec_channel_mesg,
                                    json_resp_sec_cha_out) == false) {
        ESP_LOGE(TAG_API_AKE, "Error getting secure channel response");
        goto cleanup;
    }

    if (get_response_plain_data_json(rsp_sec_channel_mesg,
                                     session,
                                     rsp_plain_data) == false) {
        ESP_LOGE(TAG_API_AKE, "Error getting plain data response");
        goto cleanup;
    }


    ESP_LOG_BUFFER_HEXDUMP("RESPONSE DATA FROM SECURE CHANNEL",
                           rsp_plain_data->payload,
                           rsp_plain_data->payload_len,
                           ESP_LOG_WARN);

    return_value = true;

cleanup:
    if (json_resp_sec_cha_out != NULL){
        free(json_resp_sec_cha_out);
        json_resp_sec_cha_out = NULL;
    }


    free_secure_plain_data(plain_data);
    plain_data = NULL;

    free_secure_message(secure_chan_message);
    secure_chan_message = NULL;

    free_secure_message(rsp_sec_channel_mesg);
    rsp_sec_channel_mesg = NULL;


    return return_value;
}
