#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_random.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "api_secure_storage.h"



void reset(int miliseconds){
    printf("RESET ... ... ... \n");
    vTaskDelay(miliseconds / portTICK_PERIOD_MS);
    esp_restart();
}

void app_main(void)
{
    printf("***** THIS IS MY TEST FOR SECURE STORAGE REGION *****\n");
    printf("***** READINF*****\n");
     // CREATE AES OBJECT 
    uint8_t key[AES_256];
    struct puf_object *puf_obj = malloc(sizeof(struct puf_object));
    derive_key_from_puf(&key[0], puf_obj, false); // change to true after provisioning

    struct aes_256_obj *aes = malloc(sizeof(struct aes_256_obj));
    create_aes_256_obj(aes, &key[0]);

    //READ FROM SECURE STORAGE
    uint8_t *plain = NULL;
    size_t plain_len = 0;

    esp_err_t err = read_secure_storage_region_alloc("TEST", aes, &plain, &plain_len);
    ESP_LOG_BUFFER_HEXDUMP("Decrypt Data", plain, plain_len, ESP_LOG_INFO);
    err = read_secure_storage_region_alloc("TEST2", aes, &plain, &plain_len);
    ESP_LOG_BUFFER_HEXDUMP("HEX FORMAT", plain, plain_len, ESP_LOG_INFO);
    err = read_secure_storage_region_alloc("KyberPK", aes, &plain, &plain_len);
    ESP_LOG_BUFFER_HEXDUMP("HEX FORMAT", plain, plain_len, ESP_LOG_INFO);
    err = read_secure_storage_region_alloc("TEST3", aes, &plain, &plain_len);
    ESP_LOG_BUFFER_HEXDUMP("HEX FORMAT", plain, plain_len, ESP_LOG_INFO);
     // get general information of the partition
    general_partition_info(Secure_Store_Partition);
    free(plain);
    //reset(3000);

}
