#ifndef HTTP_CLIENT_HELPER_H
#define HTTP_CLIENT_HELPER_H

#include <stddef.h>
#include "esp_err.h"
#include "esp_http_client.h"

/* ============================================================
 *                      TYPE DEFINITIONS
 * ============================================================ */

/**
 * @struct http_resp_t
 * @brief Dynamic container used to accumulate HTTP response data.
 *
 * This structure is used by the HTTP event handler to progressively
 * build the response body as chunks are received from the server.
 *
 * The buffer is dynamically resized using realloc() when needed.
 *
 * @note
 *  - The buffer is always NULL-terminated to allow safe use with
 *    string-based APIs (e.g., cJSON).
 *  - Memory ownership is transferred to the caller after a successful
 *    HTTP transaction.
 */
typedef struct {
    char  *buf;   /*!< Pointer to dynamically allocated response buffer (NULL-terminated). */
    size_t len;   /*!< Number of valid bytes stored (excluding NULL terminator). */
    size_t cap;   /*!< Total allocated capacity in bytes. */
} http_resp_t;


/* ============================================================
 *                      FUNCTION PROTOTYPES
 * ============================================================ */

/**
 * @brief Perform an HTTP GET request and retrieve the response body.
 *
 * This function sends an HTTP GET request to the specified URL.
 * If successful, the response body is dynamically allocated and
 * returned to the caller.
 *
 * @param[in]  http_address   Null-terminated URL string.
 * @param[out] output_base    Pointer to receive allocated response buffer.
 * @param[out] output_length  Pointer to receive response length.
 *
 * @return
 *      - ESP_OK               : Success.
 *      - ESP_ERR_INVALID_ARG  : Invalid argument.
 *      - ESP_ERR_NO_MEM       : Memory allocation failed.
 *      - ESP_FAIL             : HTTP error.
 *
 * @note
 *  - The response buffer is NULL-terminated.
 *  - Caller must free(*output_base).
 *  - Requires server to provide Content-Length.
 */
esp_err_t http_get_and_parse(const char *http_address,
                             char **output_base,
                             size_t *output_length);


/**
 * @brief HTTP event handler used to accumulate response data.
 *
 * This callback is invoked internally by the ESP-IDF HTTP client.
 * It appends received data chunks into a dynamically growing buffer.
 *
 * @param[in] evt  Pointer to HTTP client event structure.
 *
 * @return
 *      - ESP_OK          : Success.
 *      - ESP_ERR_NO_MEM  : Memory allocation failed.
 *
 * @note
 *  Must be assigned to esp_http_client_config_t.event_handler.
 */
esp_err_t http_event_handler(esp_http_client_event_t *evt);


/**
 * @brief Perform an HTTP POST request and retrieve the response body.
 *
 * Sends a JSON payload using HTTP POST and collects the response
 * body using the event-driven accumulation mechanism.
 *
 * @param[in]  http_address        Null-terminated URL string.
 * @param[in]  json_body_to_post   JSON payload to send.
 * @param[out] response_output     Pointer to receive allocated response buffer.
 * @param[out] response_length     Pointer to receive response size.
 *
 * @return
 *      - ESP_OK               : Success.
 *      - ESP_ERR_INVALID_ARG  : Invalid argument.
 *      - ESP_ERR_NO_MEM       : Memory allocation failure.
 *      - ESP_FAIL             : HTTP error.
 *
 * @note
 *  - Supports chunked transfer encoding.
 *  - Response buffer is NULL-terminated.
 *  - Caller must free(*response_output).
 */
esp_err_t http_post_and_get_response(const char *http_address,
                                     const char *json_body_to_post,
                                     char **response_output,
                                     size_t *response_length);

#endif /* HTTP_CLIENT_HELPER_H */