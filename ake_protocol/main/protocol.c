#include <stdio.h>
#include <stdbool.h>

#include "esp_log.h"
#include "api_secure_storage.h"
#include "wifi.h"
#include "ake_protocol.h"
#include "secure_channel.h"
#include "api_ake_protocol.h"

#include "esp_timer.h"
#define TAG_PROT "[Protocol Transactions]"


void start_drivers(){
    ESP_LOGI(TAG_PROT, "----- Initialize the NVS ------");
    init_nvs();
    ESP_LOGI(TAG_PROT, "----- Starting WiFi Driver -----");
    wifi_init_sta();
}

void app_main(void)
{
    struct puf_object *puf_obj = NULL;
    struct aes_256_obj *aes_key_ss = NULL;
    struct device_info *device_info = NULL;
    struct secure_session *session = NULL;

    const char *http_post = "http://192.168.1.236:5000/example";
    const char *device_name = "ESP_32_ALEX_SV";

    ESP_LOGW(TAG_PROT, "----- STARTING THE DRIVERS ------");
    start_drivers();

    puf_obj = calloc(1, sizeof(struct puf_object));
    aes_key_ss = calloc(1, sizeof(struct aes_256_obj));
    device_info = calloc(1, sizeof(struct device_info));
    session = calloc(1, sizeof(struct secure_session));

    get_puf_obj_from_puf(puf_obj, true) // change to true is the puf is provisioned 
    derive_aes_puf_key_from_puf(puf_obj, aes_key_ss)
    get_device_info(device_info, device_name, puf_obj)

    if (root_of_trust_process(http_post, device_info, aes_key_ss) == false) {
        ESP_LOGE(TAG_PROT, "ERROR IN ROOT OF TRUST PROCESS");
        goto cleanup;
    }

    if (ake_flow(http_post, device_info, aes_key_ss, session) == false) {
        ESP_LOGE(TAG_PROT, "ERROR IN AKE FLOW");
        goto cleanup;
    }

    ESP_LOGI(TAG_AKE, "------------- SECURE CHANNEL -------------");
    float temperature = 25.6;
    ESP_LOGW(TAG_PROT, "Free BEGIN heap: %u", (unsigned)esp_get_free_heap_size());
    for (int i = 0; i < 100; i++) {
        struct secure_plain_data *rsp_plain_data =
            calloc(1, sizeof(struct secure_plain_data));

        if (rsp_plain_data == NULL) {
            ESP_LOGE(TAG_PROT, "Malloc failed for rsp_plain_data");
            goto cleanup;
        }

        if (send_float_secure_channel(http_post, session, rsp_plain_data, temperature) == false) {
            ESP_LOGE(TAG_PROT, "Error sending float secure channel");
           
        }

        temperature += 1.0f;

        free_secure_plain_data(rsp_plain_data);
        rsp_plain_data = NULL;
    }
    ESP_LOGW(TAG_PROT, "Free END heap: %u", (unsigned)esp_get_free_heap_size());

    free(puf_obj);              // if you have this function
    free(aes_key_ss);          // if you have this function
    free_device_info(device_info);
    free_secure_channel_session(session);
    ESP_LOGW(TAG_PROT, "Free END heap: %u", (unsigned)esp_get_free_heap_size());
}


// void app_main(void) 
// {

//     /* Provisioning Secure Storage Parameters*/
//     ESP_LOGW(TAG_PROT, "----- STARTING THE DRIVERS ------");
//     start_drivers();

//     ESP_LOGI(TAG_PROT, "----- Setting Parameter for PUF and Secure Storage Region -----");    
//     struct puf_object *puf_obj = malloc(sizeof(struct puf_object)); /*PUF object*/   
//     struct aes_256_obj *aes_key_ss = malloc(sizeof(struct aes_256_obj));
//     get_puf_obj_from_puf(puf_obj, true); /*CHANGE TO TRUE AFTER PROVISIONING */
//     derive_aes_puf_key_from_puf(puf_obj, aes_key_ss);

    
//     ESP_LOGI(TAG_PROT, "-----  PROTOCOL TRANSACTIONS -----");
//     ESP_LOGW(TAG_PROT, "Free heap: %u", (unsigned)esp_get_free_heap_size());
//     const char *http_post = "http://192.168.1.236:5000/example"; // RoT
//     char *device_name = "ESP_32_ALEX_SV";
//     struct device_info *device_info = malloc(sizeof(struct device_info));
//     get_device_info(device_info, device_name, puf_obj);

//     // uint8_t prov = 0x1;
//     // esp_err_t prov_err; 

//     // uint8_t *prov_received;
//     // size_t prov_received_size;
//     // printf("AFTER READ"); 
//     // if (read_secure_storage_region_alloc("PROV", aes_key_ss,&prov_received,&prov_received_size) == ESP_OK)
//     //     ESP_LOG_BUFFER_HEXDUMP("PROV RECEIVED: ", prov_received, prov_received_size, ESP_LOG_WARN);

//     // printf("AFTER WRITE"); 
//     // prov_err = write_secure_storage_region(&prov, sizeof(uint8_t), "PROV", aes_key_ss);


//    if (root_of_trust_process(http_post, device_info, aes_key_ss) == false){
//         ESP_LOGE(TAG_PROT, "ERROR IN ROOT OF TRUST PROCESS");
//         return;
//    }
    
//     struct secure_session *session = malloc(sizeof(struct secure_session)); 
//     if (ake_flow(http_post, device_info, aes_key_ss, session) == false)
//     {
//         ESP_LOGE(TAG_PROT, "ERROR IN AKE FLOW");
//         return;
//    }
//     ESP_LOGI(TAG_AKE, "------------- SECURE CHANNEL -------------");
//     ESP_LOGI(TAG_AKE, "------------- SENDING TRANSACTIONS -------------");    
//     ESP_LOGW(TAG_PROT, "Free heap: %u", (unsigned)esp_get_free_heap_size());
// // TODO: MOVE THIS PART TO A FUNCTION
//    float temperature = 25.6;
//     for(int i = 0; i < 5; i++){
//         struct secure_plain_data *rsp_plain_data = malloc(sizeof(struct secure_plain_data));
//         send_float_secure_channel(http_post, session, rsp_plain_data, temperature);
//         temperature += 1;
//         free(rsp_plain_data);        
//     }

    
//     free(puf_obj);
//     free(aes_key_ss);
//     free_device_info(device_info);
//     free_secure_channel_session(session);
//     ESP_LOGW(TAG_PROT, "Free heap: %u", (unsigned)esp_get_free_heap_size());
// }