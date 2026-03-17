/* secure_storage_nvs.h
 *
 * Secure Storage interface using a custom NVS partition.
 *
 * This module defines:
 *  - Secure storage record format (variable-length blob)
 *  - NVS helper APIs to write/read encrypted blobs
 *  - Utility functions for validation, debugging, and error handling
 */

#ifndef SECURE_STORAGE_NVS_H
#define SECURE_STORAGE_NVS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "esp_log.h"
#include "esp_err.h"
#include "esp_log_buffer.h"

#include "nvs.h"
#include "nvs_flash.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"


/* ======================= Configuration Macros ======================= */

/** @brief Secure storage header length (magic value) */
#define ALEX_SS_HEADER_LEN        16

/** @brief AES-CBC IV length in bytes */
#define ALEX_SS_IV_LEN            16

/** @brief HMAC-SHA-512 output length in bytes */
#define ALEX_SS_HMAC_LEN          64

/** @brief Secure storage format version */
#define ALEX_SS_VERSION           1

/** @brief Label of the custom NVS partition */
#define Secure_Store_Partition    "Sec_Store"

/** @brief Namespace used inside the secure storage NVS partition */
#define Secure_Store_NameSpace    "SecureStore"

/** @brief Logging tag for secure storage */
#define Tag_SS                    "[SECURE_STORE]"


/* ======================= Secure Storage Record ======================= */

/**
 * @brief Secure storage record format.
 *
 * This structure represents a **single secure record** stored as a
 * variable-length blob in NVS.
 *
 * Layout on flash:
 * ```
 * [ fixed header fields ][ encrypted data (data[]) ]
 * ```
 *
 * Notes:
 * - `sizeof(alex_secstore_record_t)` returns the size of the fixed header.
 * - `data[]` contains variable-length encrypted payload.
 * - The whole structure is stored contiguously as a single blob.
 */
typedef struct __attribute__((packed)) alex_secure_store {
    uint8_t  header[ALEX_SS_HEADER_LEN]; /**< Magic header for identification */
    uint16_t version;                    /**< Secure storage format version */
    uint16_t reserved;                   /**< Reserved for future use */
    uint32_t counter;                    /**< Anti-rollback / monotonic counter */

    uint32_t iv_size;                    /**< Size of IV (must be 16) */
    uint8_t  iv[ALEX_SS_IV_LEN];          /**< AES-CBC initialization vector */

    uint32_t hmac_size;                  /**< Size of HMAC (must be 64) */
    uint8_t  hmac[ALEX_SS_HMAC_LEN];      /**< HMAC-SHA-512 authentication tag */

    uint32_t data_size;                  /**< Size of encrypted data[] */
    uint8_t  data[];                     /**< Encrypted payload (variable length) */
} alex_secstore_record_t;


/* ======================= API Functions ======================= */

/**
 * @brief Initialize the secure storage NVS partition.
 *
 * This function initializes the custom NVS partition used for secure storage.
 * If the partition is full or uses an old format, it will be erased and
 * re-initialized.
 *
 * @return
 *  - ESP_OK on success
 *  - ESP_ERR_* on failure
 */
esp_err_t sec_store_nvs_init(void);


/**
 * @brief Open the secure storage NVS namespace.
 *
 * Opens the namespace defined by `Secure_Store_NameSpace` inside the
 * custom partition.
 *
 * @param[out] nvs_handle Pointer to an NVS handle
 *
 * @return
 *  - ESP_OK on success
 *  - ESP_ERR_* on failure
 */
esp_err_t sec_store_nvs_open(nvs_handle_t *nvs_handle);


/**
 * @brief Write a binary blob to secure storage.
 *
 * Stores an arbitrary binary buffer as a value associated with a key.
 * Existing data under the same key will be overwritten.
 *
 * @param[in] key_name NVS key name (max 15 characters)
 * @param[in] buf      Pointer to data buffer
 * @param[in] len      Size of data buffer in bytes
 *
 * @return
 *  - ESP_OK on success
 *  - ESP_ERR_INVALID_ARG if parameters are invalid
 *  - ESP_ERR_* on NVS failure
 */
esp_err_t sec_store_write_blob(const char *key_name,
                               const void *buf,
                               size_t len);


/**
 * @brief Read a blob from secure storage (allocates memory).
 *
 * Reads a blob associated with a given key. Memory is allocated internally
 * and must be freed by the caller.
 *
 * @param[in]  key      NVS key name
 * @param[out] out_buf  Pointer to allocated buffer pointer
 * @param[out] out_len  Size of the returned buffer
 *
 * @return
 *  - ESP_OK on success
 *  - ESP_ERR_NVS_NOT_FOUND if key does not exist
 *  - ESP_ERR_NO_MEM if allocation fails
 *  - ESP_ERR_* on other failures
 */
esp_err_t secstore_read_blob_alloc(const char *key,
                                   void **out_buf,
                                   size_t *out_len);


/**
 * @brief Verify the integrity of a read secure storage blob.
 *
 * Performs basic validation checks:
 *  - Buffer existence
 *  - Minimum size
 *  - Expected size match
 *
 * On failure, the buffer is freed and set to NULL.
 *
 * @param[in,out] read_buf Pointer to buffer pointer
 * @param[in]     read_len Actual length of read buffer
 * @param[in]     expected Expected total length
 *
 * @return
 *  - ESP_OK if validation succeeds
 *  - ESP_ERR_INVALID_ARG or ESP_ERR_INVALID_SIZE on failure
 */
esp_err_t verify_secstore_read(void **read_buf,
                               size_t read_len,
                               size_t expected);


/**
 * @brief Populate a secure storage record structure.
 *
 * Fills all fields of the secure storage record, including header,
 * IV, HMAC, and encrypted payload.
 *
 * @param[out] self      Pointer to secure storage record
 * @param[in]  counter   Anti-rollback counter value
 * @param[in]  iv        Pointer to IV buffer (16 bytes)
 * @param[in]  hmac      Pointer to HMAC buffer (64 bytes)
 * @param[in]  data_size Size of encrypted payload
 * @param[in]  data      Pointer to encrypted payload
 */
void create_secure_storage_structure(alex_secstore_record_t *self,
                                     uint32_t counter,
                                     uint8_t *iv,
                                     uint8_t *hmac,
                                     uint32_t data_size,
                                     uint8_t *data);


/**
 * @brief Print a secure storage record for debugging.
 *
 * Dumps all fields of the record in human-readable and hexadecimal form.
 *
 * @param[in] self Pointer to secure storage record
 */
void print_secure_storage_structure(alex_secstore_record_t *self);


/**
 * @brief Print NVS partition statistics.
 *
 * Displays used, free, total entries and namespace count for the given
 * NVS partition.
 *
 * @param[in] name_partition NVS partition label
 */
void general_partition_info(const char *name_partition);


/**
 * @brief Fatal error handler.
 *
 * Logs the error and enters an infinite delay loop to halt execution.
 *
 * @param[in] err ESP-IDF error code
 */
void error_handler(esp_err_t err);

void update_hmac_secure_storage_structure(alex_secstore_record_t *self, uint8_t *hmac);

#endif /* SECURE_STORAGE_NVS_H */
