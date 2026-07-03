#include <stdio.h>
#include <stdbool.h>

#include "esp_log.h"
#include "api_secure_storage.h"
#include "wifi.h"
#include "ake_protocol.h"
#include "secure_channel.h"
#include "api_ake_protocol.h"

#include "esp_random.h"
#include "esp_timer.h"
#define TAG "[Secure Storage Test]"


void app_main(void)
{
    struct puf_object *puf_obj = NULL;
    struct aes_256_obj *aes_key_ss = NULL;
    struct aes_256_obj *hmac_key_ss = NULL;

    puf_obj = calloc(1, sizeof(struct puf_object));
    aes_key_ss = calloc(1, sizeof(struct aes_256_obj));
    hmac_key_ss = calloc(1, sizeof(struct aes_256_obj));

    uint64_t start_get_puf = esp_timer_get_time();
    get_puf_obj_from_puf(puf_obj, true); // change to true if the puf is provisioned    
    uint64_t end_get_puf= esp_timer_get_time();
    printf("Time execution for get PUF: %lld us\n", (end_get_puf - start_get_puf));


    uint64_t start_aes_key_puf = esp_timer_get_time();
    derive_aes_puf_key_from_puf(puf_obj, aes_key_ss);
    uint64_t end_aes_key_puf = esp_timer_get_time();
    printf("Time execution for Derive AES Key PUF: %lld us\n", (end_aes_key_puf - start_aes_key_puf));


    uint64_t start_hmac_key_puf = esp_timer_get_time();
    derive_hmac_puf_key_from_puf(puf_obj, hmac_key_ss);
    uint64_t end_hmac_key_puf = esp_timer_get_time();
    printf("Time execution for Derive HMAC  Key PUF: %lld us\n", (end_hmac_key_puf - start_hmac_key_puf));
  
    
    
    int test_size[]= {1, 32, 64, 256, 512, 1024, 2048, 4096, 8192, 16384};
    size_t test_len = sizeof(test_size) / sizeof(test_size[0]);
    //uint64_t start; // = esp_timer_get_time();

    uint64_t measurement_writes[test_len];
    uint64_t measurement_reads[test_len];
    memset(measurement_writes, 0, sizeof(uint64_t) * test_len);
    memset(measurement_reads, 0, sizeof(uint64_t) * test_len);

    int average = 1000; 

    // the first write consumes more memory: 
    uint8_t temp = 0x1;
    write_secure_storage_region(&temp, sizeof(uint8_t), "HOLA", aes_key_ss, hmac_key_ss);

    uint64_t *array_measurements_writing = malloc(average * sizeof(uint64_t));
    uint64_t *array_measurements_reading = malloc(average * sizeof(uint64_t));
    
    ESP_LOGW(TAG, "THIS IS A TEST FOR SECURE STORAGE REGION");
    for (int i = 0; i < test_len; i++) {
        ESP_LOGW(TAG, "Test for %d bytes", test_size[i]);
        for (int n  = 0; n < average; n++){
            
            char tag_ss[12];
            snprintf(tag_ss, sizeof(tag_ss), "TstN%d", i);

            uint8_t *random_data;
            random_data = malloc(test_size[i]);
            esp_fill_random(random_data, test_size[i]);

            uint64_t start_time_write  = esp_timer_get_time();
            write_secure_storage_region(random_data, test_size[i], tag_ss, aes_key_ss, hmac_key_ss);
            uint64_t end_time_write = esp_timer_get_time();

            //printf("Time execution for writting %d bytes: %lld us\n", test_size[i], (end_time_write - start_time_write));
            measurement_writes[i] += end_time_write - start_time_write;
            array_measurements_writing[n] = end_time_write - start_time_write;
            free(random_data);

            uint8_t *plain = NULL;
            size_t plain_len = 0;
            uint64_t start_time_read  = esp_timer_get_time();
            read_secure_storage_region_alloc(tag_ss, aes_key_ss, hmac_key_ss, &plain, &plain_len);
            uint64_t end_time_read = esp_timer_get_time();

            //printf("Time execution for reading %d bytes: %lld us\n", test_size[i], (end_time_read - start_time_read));
            measurement_reads[i] += end_time_read - start_time_read;
            array_measurements_reading[n] = end_time_read - start_time_read;
            free(plain);
        }
        ESP_LOGW(TAG, "Array measurement for %d bytes writing", test_size[i]);
        for (int n  = 0; n < average; n++){
            printf("%lld, ", array_measurements_writing[n]);

        }
        printf("\n");

        ESP_LOGW(TAG, "Array measurement for %d bytes reading", test_size[i]);
        for (int n  = 0; n < average; n++){
            printf("%lld, ", array_measurements_reading[n]);

        }
        printf("\n");
    }
    printf("\n");
    for(int i = 0; i < test_len; i++){
        ESP_LOGW(TAG, "Test Average of %d for %d bytes", average, test_size[i]);
        printf("Time execution for writting %d bytes: %lld us\n", test_size[i], measurement_writes[i]/average);
        printf("Time execution for reading %d bytes: %lld us\n", test_size[i], measurement_reads[i]/average);
    }



    free(aes_key_ss);
    free(hmac_key_ss);
    free(puf_obj);

}