#include <stdio.h>
#include "esp_log.h"
#include "esp_system.h"          // esp_fill_random()
#include "esp_random.h"
#include <stdlib.h>
#include <string.h>
#include "nvs.h"
#include "esp_err.h"
#include "nvs_flash.h"
#include "esp_log_buffer.h" // dump data into hex to ascii
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "hmac_sha512.h"

#define ALEX_SS_HEADER_LEN   16       // HEADER LEN
#define ALEX_SS_IV_LEN      16        // AES-CBC IV length
#define ALEX_SS_HMAC_LEN    64        // HMAC-SHA-512 length
#define ALEX_SS_VERSION 1 
#define Secure_Store_Partition "Sec_Store"
#define Secure_Store_NameSpace "SecureStore"
#define Tag_SS "[SECURE_STORE]:"

typedef struct alex_secure_store {
    uint8_t  header[ALEX_SS_HEADER_LEN]; 
    uint16_t version;                   
    uint16_t reserved;
    uint32_t counter;                   
    uint32_t iv_size;                   
    uint8_t  iv[ALEX_SS_IV_LEN];
    uint32_t hmac_size; 
    uint8_t  hmac[ALEX_SS_HMAC_LEN];
    uint32_t data_size;
    uint8_t  data[];                    
} alex_secstore_record_t;



void create_secure_storage_structure( alex_secstore_record_t *self, uint32_t counter, uint8_t *iv,
                                      uint8_t *hmac, uint32_t data_size, uint8_t *data){
    uint8_t ALEX_SS_HEADER[ALEX_SS_HEADER_LEN] = {
    '_','_','A','l','e','x','S','e','c','S','t','o','r','e','_','_'
    };
    memcpy(self->header , ALEX_SS_HEADER, ALEX_SS_HEADER_LEN);   
    
    self->version = ALEX_SS_VERSION; 
    self->reserved = 0x0;
    self->counter = counter;

    self->iv_size = ALEX_SS_IV_LEN;
    memcpy(self->iv, iv, self->iv_size); 

    self->hmac_size = ALEX_SS_HMAC_LEN;
    memcpy(self->hmac, hmac, self->hmac_size);
    
    self->data_size = data_size;
    memcpy(self->data, data, self->data_size); 

}

void print_secure_storage_structure(alex_secstore_record_t *self){
    printf("--- SECURE STORAGE STRUCTURE ---\n");
    // Header
    printf("[+]Header: "); //ascii
    for(int i = 0; i < ALEX_SS_HEADER_LEN; i++)
        putchar(self->header[i]); //print to ascii
    printf("\n");
    // Version
    printf("[+]Version: %u\n", self->version);

    // Reserved
    printf("[+]Reserved: %u\n", self->reserved);

    // Counter
    printf("[+]Counter: %lu\n", self->counter);                  
    
    // IV Size
    printf("[+]IV Size: %lu\n", self->iv_size);  
                   
    // IV
    printf("[+]IV: "); //hex
    for(int i = 0; i < self->iv_size; i++) 
        printf("%02X", self->iv[i]);
    printf("\n");

    // HMAC Size
    printf("[+]HMAC Size: %lu\n", self->hmac_size);  
    
    //HMAC
    printf("[+]HMAC: "); //hex
    for(int i = 0; i < self->hmac_size; i++) 
        printf("%02X", self->hmac[i]);
    printf("\n");
    
    // Data Size
    printf("[+]Data Size: %lu\n", self->data_size);
    
    //Data
    printf("[+]Data: "); //hex
    for(int i = 0; i < self->data_size; i++) 
        printf("%02X", self->data[i]);
    printf("\n");

    ESP_LOG_BUFFER_HEXDUMP("HEX FORMAT", self->data, self->data_size, ESP_LOG_INFO);

}


esp_err_t sec_store_nvs_init(){
    esp_err_t err = nvs_flash_init_partition(Secure_Store_Partition);
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_LOGW(Tag_SS, "NVS partition needs erase, err=%s", esp_err_to_name(err));
        ESP_ERROR_CHECK(nvs_flash_erase_partition(Secure_Store_Partition));
        err = nvs_flash_init_partition(Secure_Store_Partition);
    }
    return err;
}

esp_err_t sec_store_nvs_open(nvs_handle_t *nvs_handle){
    return nvs_open_from_partition(Secure_Store_Partition, Secure_Store_NameSpace, NVS_READWRITE, nvs_handle);
}


esp_err_t sec_store_write_blob(const char *key_name, const void *buf, size_t len){
    if (!key_name || !buf || len == 0) return ESP_ERR_INVALID_ARG;

    nvs_handle_t h;
    esp_err_t err = sec_store_nvs_open(&h);
    if (err != ESP_OK) {
        ESP_LOGE(Tag_SS, "nvs_open_from_partition failed: %s", esp_err_to_name(err));
        return err;
    }

    err = nvs_set_blob(h, key_name, buf, len);
    if (err != ESP_OK) {
        ESP_LOGE(Tag_SS, "nvs_set_blob failed: %s", esp_err_to_name(err));
        nvs_close(h);
        return err;
    }

    err = nvs_commit(h);
    nvs_close(h);


    if (err != ESP_OK) {
        ESP_LOGE(Tag_SS, "nvs_commit failed: %s\n", esp_err_to_name(err));
        return err;
    }
    
    ESP_LOGI(Tag_SS, "THE DATA WAS WRITED TO NVS %s", Secure_Store_NameSpace);        
    
    return ESP_OK;
}

esp_err_t secstore_read_blob_alloc(const char *key, void **out_buf, size_t *out_len){

    if (!key || !out_buf || !out_len) return ESP_ERR_INVALID_ARG;

    *out_buf = NULL;
    *out_len = 0;

    nvs_handle_t h;
    esp_err_t err = sec_store_nvs_open(&h);
    if (err != ESP_OK) {
        ESP_LOGE(Tag_SS, "nvs_open_from_partition failed: %s", esp_err_to_name(err));
        return err;
    }

    size_t required = 0;
    err = nvs_get_blob(h, key, NULL, &required); // query size
    if (err != ESP_OK) {
        nvs_close(h);
        if (err == ESP_ERR_NVS_NOT_FOUND) { // not key found 
            ESP_LOGW(Tag_SS, "Blob key '%s' not found", key);
        } else {
            ESP_LOGE(Tag_SS, "nvs_get_blob(size) failed: %s", esp_err_to_name(err));
        }
        return err;
    }

    void *buf = malloc(required);
    if (!buf) {
        nvs_close(h);
        ESP_LOGE(Tag_SS, "malloc(%u) failed", (unsigned)required);
        return ESP_ERR_NO_MEM;
    }

    err = nvs_get_blob(h, key, buf, &required); // read blob
    nvs_close(h);

    if (err != ESP_OK) {
        free(buf);
        ESP_LOGE(Tag_SS, "nvs_get_blob(read) failed: %s", esp_err_to_name(err));
        return err;
    }

    *out_buf = buf;
    *out_len = required;
    ESP_LOGI(Tag_SS, "Read OK (len=%u)", (unsigned)required);
    return ESP_OK;
}


esp_err_t verify_secstore_read(void **read_buf, size_t read_len, size_t expected){
    if (read_buf == NULL || *read_buf == NULL) {
        ESP_LOGE(Tag_SS, "Invalid buffer pointer");
        return ESP_ERR_INVALID_ARG;
    }

    // Minimum: must at least contain the fixed header (sizeof works for flexible-array structs)
    if (read_len < sizeof(alex_secstore_record_t)) {
        ESP_LOGE(Tag_SS, "Blob too small: got=%zu, need>=%zu",
                 read_len, sizeof(alex_secstore_record_t));
        free(*read_buf);
        *read_buf = NULL;
        return ESP_ERR_INVALID_SIZE;
    }

    if (expected != read_len) {
        ESP_LOGE(Tag_SS, "Size mismatch: expected=%zu, got=%zu", expected, read_len);
        free(*read_buf);
        *read_buf = NULL;
        return ESP_ERR_INVALID_SIZE;
    }

    ESP_LOGI(Tag_SS, "Verification success");
    return ESP_OK;
}

void general_partition_info(const char *name_partition)
{   
    nvs_stats_t handler; 
    esp_err_t err = nvs_get_stats(name_partition, &handler);
    if (err != ESP_OK) {
        ESP_LOGE(Tag_SS, "Failed to get NVS stats for %s: %s",
                 name_partition, esp_err_to_name(err));
        return;
    }

    ESP_LOGI(Tag_SS,
             "used: %d, free: %d, total: %d, namespace count: %d",
             handler.used_entries,
             handler.free_entries,
             handler.total_entries,
             handler.namespace_count);
}

void error_handler(esp_err_t err){
    if (err != ESP_OK) {
        ESP_LOGE(Tag_SS, "FATAL ERROR: %s", esp_err_to_name(err));
        while (true) {
            vTaskDelay(pdMS_TO_TICKS(1000));
        }
    }
}

void app_main(void)
{
    // Example key (AES-128 = 16 bytes). Use a real KDF / key management in production.
    uint8_t key[32] = {
        0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
        0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
        0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
        0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81, 
    };

    // Dumping IV
    uint8_t iv[ALEX_SS_IV_LEN];
    esp_fill_random(iv, sizeof(iv));



    //plain text
    char *msg = "Hello ESP32! AES-CBC with PKCS#7 padding Espero que esten bien y tenga el gusto de conocerme";
    uint8_t *plaintext = (uint8_t *)msg; // uint8_t pointer to message
    size_t plaintext_len = strlen(msg);

    uint8_t hmac[ALEX_SS_HMAC_LEN];
    
    get_hmac(&key[0], sizeof(key), &plaintext[0],plaintext_len, &hmac[0]);
    ESP_LOG_BUFFER_HEXDUMP("HEX FORMAT", hmac, HMAC_LEN, ESP_LOG_INFO);


    size_t total_size = sizeof(alex_secstore_record_t) + plaintext_len;
    printf("the structure size: %zu\n", sizeof(alex_secstore_record_t));
    printf("the plaintext size: %zu\n", plaintext_len);
    printf("the total size: %zu\n", total_size);


    alex_secstore_record_t *secure_store = malloc(total_size ); 
    if (secure_store == NULL) {
        ESP_LOGE("SECSTORE", "malloc failed");
        return;
    }
    uint32_t counter = 0x1;

    // Create structure
    create_secure_storage_structure(secure_store, counter, &iv[0], &hmac[0],
         (uint32_t)plaintext_len, &plaintext[0]);
    
    print_secure_storage_structure(secure_store);

    //writing the secure storage

    // total_len = sizeof(record header) + ciphertext_size
    ESP_ERROR_CHECK(sec_store_nvs_init());
    esp_err_t err;
    err= sec_store_write_blob("Password", secure_store, total_size);
    

    //read from the custom partition

    ESP_LOGI(Tag_SS, "Reading blob back...");
    void *read_buf = NULL;
    size_t read_len = 0;

    err = secstore_read_blob_alloc("Password", &read_buf, &read_len);
    alex_secstore_record_t *got = (alex_secstore_record_t *)read_buf;
    size_t expected = sizeof(alex_secstore_record_t) + (size_t)got->data_size;
    err = verify_secstore_read(&read_buf, read_len, expected);
    error_handler(err);

    print_secure_storage_structure(got);
    verify_hmac(secure_store->hmac, got->hmac, ALEX_SS_HMAC_LEN);

    // get general information of the partition
    general_partition_info(Secure_Store_Partition);

    

}
