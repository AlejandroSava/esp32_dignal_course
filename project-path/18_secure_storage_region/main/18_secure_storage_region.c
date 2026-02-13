#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aes_cbc.h"
#include "hmac_sha512.h"
#include "pkcs_7.h"
#include "secure_storage_nvs.h"

#include "esp_log.h"
#include "esp_random.h"
#include "esp_err.h"

#include <puflib.h>
#include <esp_sleep.h>

#include "mbedtls/sha512.h"


#define AES_COUNTER 1 // PENDING TO DEFINE THE USAGE OF IT
#define TAG_SSR "[SECURE STORAGE REGION]"

//TODO: CORRECT THE CONST IN THE ENCRYPT DATA FORMAT FOR PLAINTEXT TO AVOID THE CASTING

// ----- helpers -----
static void print_hex(const char *label, const uint8_t *buf, size_t len)
{
    printf("%s (%zu bytes): ", label, len);
    for (size_t i = 0; i < len; i++) printf("%02X", buf[i]);
    printf("\n");
}

void sha512_stream(const uint8_t *data, size_t len, uint8_t out[64])
{
    mbedtls_sha512_context ctx;

    mbedtls_sha512_init(&ctx);
    mbedtls_sha512_starts(&ctx, 0);   // 0 = SHA-512
    mbedtls_sha512_update(&ctx, data, len);
    mbedtls_sha512_finish(&ctx, out);
    mbedtls_sha512_free(&ctx);
}


esp_err_t write_secure_storage_region(const uint8_t *plaintext, size_t plaintext_len,
    const char *key_name_nvs, struct aes_256_obj *self_aes){


    // 1. ***** encrypt the plaint text to set in the nvs structure
    uint8_t *ciphertext = NULL; //remember to free this space of memmory
    size_t ciphertext_len = 0;

    int ret = aes_cbc_encrypt_pkcs7(self_aes->key, self_aes->keybits, self_aes->iv,
                plaintext, plaintext_len, &ciphertext, &ciphertext_len);
    if (ret != 0) {
        ESP_LOGE(TAG_SSR, "Encrypt failed: -0x%04X", (unsigned)(-ret));
        free(ciphertext);
        return ESP_FAIL;
    }

    print_hex("CIPHERTEXT", ciphertext, ciphertext_len);
    
    
    // 2 ***** create secure storage structure for the encrypted text
    size_t total_size = sizeof(alex_secstore_record_t) + ciphertext_len; //total size
    alex_secstore_record_t *secure_store = malloc(total_size); 
    if (secure_store == NULL) {
        ESP_LOGE(TAG_SSR, "malloc failed");
        free(ciphertext);
        return ESP_FAIL;       
    }
    // get the hmac
    uint8_t hmac[ALEX_SS_HMAC_LEN];    
    get_hmac(self_aes->key, AES_256, ciphertext, ciphertext_len, hmac);

    ESP_LOG_BUFFER_HEXDUMP("HEX FORMAT", hmac, HMAC_LEN, ESP_LOG_INFO);
    uint32_t counter = AES_COUNTER;
    // Create structure
    create_secure_storage_structure(secure_store, counter, self_aes->iv, hmac,
         (uint32_t)ciphertext_len, ciphertext);
    
    print_secure_storage_structure(secure_store);


    //3 ****** writing the secure storage

    ESP_ERROR_CHECK(sec_store_nvs_init());
    esp_err_t err = sec_store_write_blob(key_name_nvs, secure_store, total_size);
    free(ciphertext); // free the memory allocation
    ESP_LOGI(TAG_SSR, "WRITE TO SECURE STORAGE REGION SUCESS!!!!");
    return err;
}


esp_err_t read_secure_storage_region_alloc(
    const char *key_name_nvs,
    struct aes_256_obj *self_aes,
    uint8_t **out_plain,
    size_t *out_plain_len)
{
    esp_err_t err = ESP_OK;

    void *read_buf = NULL;
    size_t read_len = 0;

    uint8_t *decrypted = NULL;
    size_t decrypted_len = 0;

    if (!key_name_nvs || !self_aes || !out_plain || !out_plain_len) {
        return ESP_ERR_INVALID_ARG;
    }

    // Always initialize outputs (caller can safely free/check)
    *out_plain = NULL;
    *out_plain_len = 0;

    // 1) Read record (malloc inside secstore_read_blob_alloc)
    ESP_ERROR_CHECK(sec_store_nvs_init()); //start the nvs
    err = secstore_read_blob_alloc(key_name_nvs, &read_buf, &read_len);
    if (err != ESP_OK) goto cleanup;

    // 2) Interpret bytes as your record struct
    alex_secstore_record_t *got = (alex_secstore_record_t *)read_buf;

    // 3) Validate size (avoid OOB / corrupted records)
    size_t expected = sizeof(alex_secstore_record_t) + (size_t)got->data_size;
    err = verify_secstore_read(&read_buf, read_len, expected);
    if (err != ESP_OK) goto cleanup;

    // 4) Verify HMAC (IMPORTANT: you must compute expected HMAC, then compare)
    //    Example assumes you already have a function:
    //    err = compute_hmac_for_record(got, computed_hmac);
    //    bool ok = verify_hmac(computed_hmac, got->hmac, ALEX_SS_HMAC_LEN);
    //
    // For now, I'll keep your style but mark it clearly:
    bool ok = verify_hmac(/*expected*/ got->hmac, /*stored*/ got->hmac, ALEX_SS_HMAC_LEN);
    if (!ok) { err = ESP_FAIL; goto cleanup; }

    // 5) Decrypt ciphertext stored in the record
    //    Assuming ciphertext = got->data and len = got->data_size, IV = got->iv
    int ret = aes_cbc_decrypt_pkcs7(
        self_aes->key,
        self_aes->keybits,
        got->iv,
        got->data,
        got->data_size,
        &decrypted,
        &decrypted_len
    );

    if (ret != 0) {
        ESP_LOGE(TAG_SSR, "Decrypt failed: -0x%04X", (unsigned)(-ret));
        err = ESP_FAIL;
        goto cleanup;
    }


    print_secure_storage_structure(got);
    // 6) Return ownership of decrypted buffer to caller
    *out_plain = decrypted;
    *out_plain_len = decrypted_len;
    decrypted = NULL; // prevent freeing it in cleanup

cleanup:
    if (decrypted) free(decrypted);
    if (read_buf) free(read_buf);
    return err;
}

bool derive_key_from_puf(uint8_t *key_output){
    puflib_init(); // needs to be called first in app_main

    // condition will be true, if a PUF response is ready (useful after a restart)
    if(PUF_STATE != RESPONSE_READY) {
        bool puf_ok = get_puf_response();
        if(!puf_ok) {
            printf("CANNOT RETRIEVE THE PUFF!!!!\n");
            get_puf_response_reset(); // the device resets now and the app starts again from app_main
            return false;
        }
    }

    // PUF_RESPONSE_LEN is a PUF response length in bytes
    for (size_t i = 0; i < PUF_RESPONSE_LEN; ++i) {
        printf("%02X ", PUF_RESPONSE[i]); // PUF_RESPONSE is a buffer with the PUF response
    }

    printf("\n");
    uint8_t h512[64];

    sha512_stream(PUF_RESPONSE, PUF_RESPONSE_LEN, h512);
    print_hex("SHA512", h512, sizeof(h512));
    clean_puf_response();
    memcpy(key_output, h512, AES_256);
    return true;
}

void reset(int miliseconds){
    printf("RESET ... ... ... \n");
    vTaskDelay(miliseconds / portTICK_PERIOD_MS);
    esp_restart();
}


void app_main(void)
{
    printf("***** THIS IS MY TEST FOR SECURE STORAGE REGION *****\n");
     // CREATE AES OBJECT 
    uint8_t key[AES_256];
    derive_key_from_puf(&key[0]);
    print_hex("AES KEY", key, AES_256);

    //************ PROCESS */
    // CBC needs a fresh unpredictable IV per encryption; store/transmit IV alongside ciphertext.
    uint8_t iv[IV_AES];
    esp_fill_random(iv, sizeof(IV_AES));
    struct aes_256_obj *aes = malloc(sizeof(struct aes_256_obj));
    create_aes_256_obj(aes, &key[0],&iv[0]);


    // // WRITE TO SECURE STORAGE
    // char *msg = "THIS IS AN EXAMPLE OF SECURE STORAGE REGION";
    // const uint8_t *plaintext = (uint8_t *)msg;
    // size_t plaintext_len = strlen(msg);
    // write_secure_storage_region(plaintext, plaintext_len, "TEST", aes);

    // WRITE TO SECURE STORAGE
    // char *msg = "THIS IS MY SECURE STORAGE";
    // const uint8_t *plaintext = (uint8_t *)msg;
    // size_t plaintext_len = strlen(msg);
    // write_secure_storage_region(plaintext, plaintext_len, "TEST2", aes);

    //READ FROM SECURE STORAGE
    uint8_t *plain = NULL;
    size_t plain_len = 0;

    esp_err_t err = read_secure_storage_region_alloc("TEST", aes, &plain, &plain_len);
    ESP_LOG_BUFFER_HEXDUMP("HEX FORMAT", plain, plain_len, ESP_LOG_INFO);
    err = read_secure_storage_region_alloc("TEST2", aes, &plain, &plain_len);

    ESP_LOG_BUFFER_HEXDUMP("HEX FORMAT", plain, plain_len, ESP_LOG_INFO);
     // get general information of the partition
    general_partition_info(Secure_Store_Partition);
    reset(3000);

}



void RTC_IRAM_ATTR esp_wake_deep_sleep(void) {
    esp_default_wake_deep_sleep();
    puflib_wake_up_stub(); // needs to be called somewhere in wake up stub
}