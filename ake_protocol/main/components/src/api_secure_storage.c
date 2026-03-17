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
#include "api_secure_storage.h"

#define AES_COUNTER 1 // PENDING TO DEFINE THE USAGE OF IT
#define TAG_SSR "[SECURE STORAGE REGION]"

void sha512_stream(const uint8_t *data, size_t len, uint8_t out[64])
{
    mbedtls_sha512_context ctx;

    mbedtls_sha512_init(&ctx);
    mbedtls_sha512_starts(&ctx, 0);   // 0 = SHA-512
    mbedtls_sha512_update(&ctx, data, len);
    mbedtls_sha512_finish(&ctx, out);
    mbedtls_sha512_free(&ctx);
}

/**
 * @brief Encrypts plaintext data, wraps it into a secure storage record,
 *        computes its HMAC, and stores it as a blob in NVS.
 *
 * This function takes an input plaintext buffer and encrypts it using
 * AES-CBC with PKCS#7 padding. Then, it creates an
 * `alex_secstore_record_t` structure containing metadata, IV, temporary HMAC,
 * and ciphertext. After that, the real HMAC is computed over the secure
 * storage structure and updated in the record. Finally, the complete blob
 * is written into NVS under the provided key name.
 *
 * Memory for the ciphertext buffer and secure storage structure is allocated
 * dynamically inside this function and released before returning.
 *
 * @param[in] plaintext
 *     Pointer to the input plaintext buffer to be encrypted and stored.
 *
 * @param[in] plaintext_len
 *     Length, in bytes, of the plaintext buffer.
 *
 * @param[in] key_name_nvs
 *     Null-terminated string used as the NVS key name under which the
 *     secure storage blob will be stored.
 *
 * @param[in] self_aes
 *     Pointer to an AES context structure containing the encryption key,
 *     key size, and IV required for AES-CBC encryption.
 *
 * @return
 *     - ESP_OK on success.
 *     - ESP_ERR_INVALID_ARG if any input argument is NULL.
 *     - ESP_ERR_NO_MEM if memory allocation fails.
 *     - ESP_FAIL if encryption or HMAC generation fails.
 *     - Any error returned by NVS initialization or blob writing functions.
 */
esp_err_t write_secure_storage_region(const uint8_t *plaintext, size_t plaintext_len,
                                      const char *key_name_nvs,
                                      struct aes_256_obj *self_aes)
{
    /* Status returned by this function */
    esp_err_t status = ESP_OK;

    /* Auxiliary variable for ESP-IDF function return values */
    esp_err_t err = ESP_OK;

    /* Auxiliary variable for cryptographic helper return values */
    int ret = 0;

    /* Buffer that will hold the encrypted plaintext */
    uint8_t *ciphertext = NULL;

    /* Length in bytes of the encrypted ciphertext buffer */
    size_t ciphertext_len = 0;

    /* Pointer to the dynamically allocated secure storage structure */
    alex_secstore_record_t *secure_store = NULL;

    /* 0. Validate input arguments */
    if (plaintext == NULL || key_name_nvs == NULL || self_aes == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    // Update the AES IV for each write
    update_iv_aes(self_aes);

    /* 1. Encrypt plaintext using AES-CBC with PKCS#7 padding */
    ret = aes_cbc_encrypt_pkcs7(self_aes->key,
                                self_aes->keybits,
                                self_aes->iv,
                                plaintext,
                                plaintext_len,
                                &ciphertext,
                                &ciphertext_len);
    if (ret != 0) {
        ESP_LOGE(TAG_SSR, "Encrypt failed: -0x%04X", (unsigned)(-ret));
        status = ESP_FAIL;
        goto cleanup;
    }

    /* 2. Compute total size required for the secure storage record
     *    including the variable-length ciphertext payload
     */
    size_t total_size = sizeof(alex_secstore_record_t) + ciphertext_len;

    /* 2.1 Allocate memory for the secure storage structure */
    secure_store = malloc(total_size);
    if (secure_store == NULL) {
        ESP_LOGE(TAG_SSR, "Malloc failed");
        status = ESP_ERR_NO_MEM;
        goto cleanup;
    }

    /* 2.2 Create a temporary HMAC placeholder.
     *     This placeholder is used while building the structure before
     *     calculating the final HMAC value.
     */
    uint8_t hmac[ALEX_SS_HMAC_LEN];
    memset(hmac, 0xff, sizeof(hmac));

    /* 2.3 Define the counter value associated with this secure record */
    uint32_t counter = AES_COUNTER;

    /* 2.4 Fill the secure storage structure with header, metadata,
     *     IV, temporary HMAC, ciphertext length, and ciphertext data
     */
    create_secure_storage_structure(secure_store,
                                    counter,
                                    self_aes->iv,
                                    hmac,
                                    (uint32_t)ciphertext_len,
                                    ciphertext);

    /* 2.5 Compute the real HMAC over the secure storage structure */
    ret = get_hmac_secure_storage(self_aes->key,
                                  AES_256,
                                  secure_store,
                                  hmac);
    if (ret != 0) {
        ESP_LOGE(TAG_SSR, "HMAC generation failed: %d", ret);
        status = ESP_FAIL;
        goto cleanup;
    }

    /* 2.6 Replace the temporary HMAC in the structure with the real HMAC */
    update_hmac_secure_storage_structure(secure_store, hmac);
    
    /* 3. Initialize the NVS subsystem used for secure storage */
    err = sec_store_nvs_init();
    if (err != ESP_OK) {
        ESP_LOGE(TAG_SSR, "sec_store_nvs_init failed: %s", esp_err_to_name(err));
        status = err;
        goto cleanup;
    }

    /* 4. Write the secure storage structure as a blob into NVS */
    err = sec_store_write_blob(key_name_nvs, secure_store, total_size);
    if (err != ESP_OK) {
        ESP_LOGE(TAG_SSR, "Error writing blob to NVS: %s", esp_err_to_name(err));
        status = err;
        goto cleanup;
    }

    /* 5. Log success and optionally print the stored structure */
    ESP_LOGI(TAG_SSR, "Write to secure storage region success");
    print_secure_storage_structure(secure_store);
    
cleanup:
    /* Release dynamically allocated resources before returning */
    free(ciphertext);
    free(secure_store);

    return status;
}

/**
 * @brief Read, verify, and decrypt a Secure Storage record from NVS.
 *
 * This function retrieves a secure storage blob from NVS, validates its
 * structure, verifies its HMAC for integrity/authenticity,
 * decrypts the stored ciphertext, and returns the plaintext in a newly
 * allocated buffer.
 *
 * The function uses a callee-allocates style:
 * - The plaintext buffer is allocated inside this function.
 * - On success, ownership of the plaintext buffer is transferred to the caller.
 * - The caller is responsible for freeing the returned buffer.
 *
 * Processing flow:
 *  1. Validate input arguments.
 *  2. Initialize output parameters.
 *  3. Initialize NVS for secure storage access.
 *  4. Read the stored blob from NVS.
 *  5. Validate that the blob is large enough for the fixed record header.
 *  6. Validate the full expected size of the record.
 *  7. Recompute and verify the stored HMAC.
 *  8. Decrypt the ciphertext using AES-CBC with PKCS7 unpadding.
 *  9. Return the plaintext buffer to the caller.
 *  10. Cleanup temporary resources
 * @param[in]  key_name_nvs   NVS key name where the secure record is stored.
 * @param[in]  self_aes       AES context object containing key material.
 * @param[out] out_plain      Pointer to the output plaintext buffer.
 *                            On success, this receives an allocated buffer
 *                            that must be freed by the caller.
 * @param[out] out_plain_len  Pointer to the output plaintext length.
 *
 * @return
 *      - ESP_OK on success
 *      - ESP_ERR_INVALID_ARG if any input parameter is invalid
 *      - ESP_ERR_INVALID_SIZE if the stored record size/metadata is invalid
 *      - ESP_FAIL if HMAC verification or decryption fails
 *      - Other ESP-IDF error codes propagated from NVS/helper functions
 *
 * @note On failure, *out_plain is set to NULL and *out_plain_len to 0.
 * @note The caller must free(*out_plain) after successful use.
 */
esp_err_t read_secure_storage_region_alloc(const char *key_name_nvs,
                                           struct aes_256_obj *self_aes,
                                           uint8_t **out_plain,
                                           size_t *out_plain_len)
{
    /* Generic function return status */
    esp_err_t err = ESP_OK;

    /* Raw buffer that will hold the complete record read from NVS */
    void *read_buf = NULL;
    size_t read_len = 0;

    /* Buffer that will hold the decrypted plaintext */
    uint8_t *decrypted = NULL;
    size_t decrypted_len = 0;

    /* ---------------------------------------------------------
     * 1. Validate function arguments
     * ---------------------------------------------------------
     * All pointers required by the function must be valid.
     * This prevents null pointer dereferences later.
     */
    if (!key_name_nvs || !self_aes || !out_plain || !out_plain_len) {
        ESP_LOGE(TAG_SSR, "Invalid Arguments");
        return ESP_ERR_INVALID_ARG;
    }

    /* ---------------------------------------------------------
     * 2. Initialize outputs to safe defaults
     * ---------------------------------------------------------
     * This guarantees that, even on failure, the caller receives:
     *   - a NULL plaintext pointer
     *   - a plaintext length of 0
     */
    *out_plain = NULL;
    *out_plain_len = 0;

    /* ---------------------------------------------------------
     * 3. Initialize NVS access for secure storage
     * ---------------------------------------------------------
     * This prepares the NVS partition/namespace before attempting
     * to read the secure storage blob.
     */
    err = sec_store_nvs_init();
    if (err != ESP_OK) {
        ESP_LOGE(TAG_SSR, "sec_store_nvs_init failed: %s", esp_err_to_name(err));
        goto cleanup;
    }

    /* ---------------------------------------------------------
     * 4. Read the raw secure storage blob from NVS
     * ---------------------------------------------------------
     * secstore_read_blob_alloc() allocates memory for read_buf,
     * so this function becomes responsible for freeing it.
     */
    err = secstore_read_blob_alloc(key_name_nvs, &read_buf, &read_len);
    if (err != ESP_OK) {
        ESP_LOGE(TAG_SSR, "Error reading blob: %s", esp_err_to_name(err));
        goto cleanup;
    }

    /* ---------------------------------------------------------
     * 5. Validate minimum blob size
     * ---------------------------------------------------------
     * Before interpreting the raw bytes as alex_secstore_record_t,
     * ensure that the buffer is at least large enough to contain
     * the fixed part of the structure.
     *
     * This prevents reading fields like got->data_size from a
     * truncated/corrupted buffer.
     */
    if (read_len < sizeof(alex_secstore_record_t)) {
        err = ESP_ERR_INVALID_SIZE;
        ESP_LOGE(TAG_SSR, "Blob too small");
        goto cleanup;
    }

    /* Now it is safe to interpret the buffer as a record */
    alex_secstore_record_t *got = (alex_secstore_record_t *)read_buf;

    /* Expected total size of the stored record:
     *   fixed metadata + encrypted payload
     */
    size_t expected = sizeof(alex_secstore_record_t) + (size_t)got->data_size;

    /* ---------------------------------------------------------
     * 6. Verify the record length against the expected size
     * ---------------------------------------------------------
     * This confirms that the blob length matches the record
     * definition and helps detect corruption or truncation.
     */
    err = verify_secstore_read(&read_buf, read_len, expected);
    if (err != ESP_OK) {
        ESP_LOGE(TAG_SSR, "Verify blob structure failed: %s", esp_err_to_name(err));
        goto cleanup;
    }


    /* ---------------------------------------------------------
     * 7. Recompute the HMAC over the secure storage record
     * ---------------------------------------------------------
     * The recomputed HMAC is compared against the stored HMAC to
     * validate integrity and authenticity of the record contents.
     */
    uint8_t hmac_recovered[ALEX_SS_HMAC_LEN];

    if (get_hmac_secure_storage(self_aes->key, AES_256, got, hmac_recovered) != 0) {
        ESP_LOGE(TAG_SSR, "Failed to compute HMAC");
        err = ESP_FAIL;
        goto cleanup;
    }

    /* Compare calculated HMAC with the HMAC stored in the record */
    if (!verify_hmac(hmac_recovered, got->hmac, ALEX_SS_HMAC_LEN)) {
        ESP_LOGE(TAG_SSR, "HMAC mismatch");
        err = ESP_FAIL;
        goto cleanup;
    }

    /* ---------------------------------------------------------
     * 8. Decrypt the ciphertext
     * ---------------------------------------------------------
     * The ciphertext is stored in got->data with length got->data_size.
     * The IV is stored in got->iv.
     *
     * Output plaintext is dynamically allocated by
     * aes_cbc_decrypt_pkcs7().
     */
     // Update the AES IV object
    read_and_update_iv_aes(self_aes, got->iv);
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

    /* ---------------------------------------------------------
     * 9. Transfer ownership of plaintext to caller
     * ---------------------------------------------------------
     * At this point, decryption succeeded. The caller becomes
     * responsible for freeing the plaintext buffer.
     */
    *out_plain = decrypted;
    *out_plain_len = decrypted_len;

    /* Prevent cleanup from freeing memory now owned by caller */
    decrypted = NULL;

cleanup:
    /* ---------------------------------------------------------
     * 10. Cleanup temporary resources
     * ---------------------------------------------------------
     * Free any allocated buffers that are still owned here.
     */

    /* If decryption buffer still belongs to this function, free it */
    if (decrypted) {
        memset(decrypted, 0, decrypted_len);
        free(decrypted);
    }

    /* Free the raw NVS blob buffer */
    if (read_buf) {
        free(read_buf);
    }

    return err;
}

bool derive_key_from_puf(uint8_t *key_output, struct puf_object *self, bool source_puf){
    uint8_t h512[64];
    if (source_puf){
        puflib_init(); // needs to be called first in app_main

        // condition will be true, if a PUF response is ready (useful after a restart)
        if(PUF_STATE != RESPONSE_READY) {
            bool puf_ok = get_puf_response();
            if(!puf_ok) {
                ESP_LOGE(TAG_SSR, "CANNOT RETRIEVE THE PUF!!!");
                get_puf_response_reset(); // the device resets now and the app starts again from app_main
                return false;
            }
        }

        // PUF_RESPONSE_LEN is a PUF response length in bytes
        for (size_t i = 0; i < PUF_RESPONSE_LEN; ++i) {
            printf("%02X ", PUF_RESPONSE[i]); // PUF_RESPONSE is a buffer with the PUF response
        }

        printf("\n");
        

        sha512_stream(PUF_RESPONSE, PUF_RESPONSE_LEN, h512);
        //print_hex("SHA512", h512, sizeof(h512));
        clean_puf_response();
        printf("PRINTINF AFTER CLEANING\n");
        // PUF_RESPONSE_LEN is a PUF response length in bytes
        for (size_t i = 0; i < PUF_RESPONSE_LEN; ++i) {
            printf("%02X ", PUF_RESPONSE[i]); // PUF_RESPONSE is a buffer with the PUF response
        }
        memcpy(key_output, h512, AES_256);
        memcpy(self->hash, h512, PUF_HASH_LEN); // data to hash puf
        self->init = true;
        ESP_LOGI(TAG_SSR, "PUF Object Updated");
        return true;
    }

    else{
        printf("TESTING SECURE STORAGE... HARDCODING KEY\n");
        uint8_t key[16] = {
        0x10,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
        0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x01
        }; 

        sha512_stream(key, 16, h512);
        //print_hex("SHA512", h512, sizeof(h512));
        memcpy(key_output, h512, AES_256);
        if(self != NULL){
            memcpy(self->hash, h512, PUF_HASH_LEN); // data to hash puf
            self->init = false;
            ESP_LOGI(TAG_SSR, "PUF Object Updated --> hardcoding object, PUF FEAK!");
        }
        else
            ESP_LOGI(TAG_SSR, "There isn't PUF object");
        return true;
    }

}

// void get_puf_hash(uint8_t *buffer){
//     uint8_t h512[64];
//     puflib_init(); // needs to be called first in app_main

//     // condition will be true, if a PUF response is ready (useful after a restart)
//     if(PUF_STATE != RESPONSE_READY) {
//         bool puf_ok = get_puf_response();
//         if(!puf_ok) {
//             ESP_LOGE(TAG_SSR, "CANNOT RETRIEVE THE PUFF!!!");
//             get_puf_response_reset(); // the device resets now and the app starts again from app_main
//             return;
//         }
//     }   
//     // PUF_RESPONSE_LEN is a PUF response length in bytes
//     for (size_t i = 0; i < PUF_RESPONSE_LEN; ++i) {
//         printf("%02X ", PUF_RESPONSE[i]); // PUF_RESPONSE is a buffer with the PUF response
//     }
//     sha512_stream(PUF_RESPONSE, PUF_RESPONSE_LEN, buffer);
//     clean_puf_response();
//     // PUF_RESPONSE_LEN is a PUF response length in bytes
//     for (size_t i = 0; i < PUF_RESPONSE_LEN; ++i) {
//         printf("%02X ", PUF_RESPONSE[i]); // PUF_RESPONSE is a buffer with the PUF response
//     }

//     ESP_LOGI(TAG_SSR, "Getting the hash digest (sha512) from puf");
// }

void RTC_IRAM_ATTR esp_wake_deep_sleep(void) { // this function is needed
    esp_default_wake_deep_sleep();
    puflib_wake_up_stub(); // needs to be called somewhere in wake up stub
}