#include <stdio.h>
#include "esp_log.h"

#include "esp_random.h"
#include <stdlib.h>
#include <string.h>

#include "esp_err.h"
#include "esp_log_buffer.h" // dump data into hex to ascii

#include "hmac_sha512.h"
#include "secure_storage_nvs.h"


void app_main(void)
{
    // Example key (AES-256 = 32 bytes). Use a real KDF / key management in production.
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
