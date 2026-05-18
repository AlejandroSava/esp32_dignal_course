#include <string.h>
#include <stdlib.h>
#include "esp_log.h"
#include "esp_http_client.h"
#include "cJSON.h"
#include "http_transactions.h"

/* ============================
 * Logging Tags
 * ============================ */
#define TAG_HTTP_GET   "HTTP_GET"
#define TAG_HTTP_POST  "HTTP_POST"

/**
 * @brief Perform an HTTP GET request and retrieve the response body.
 *
 * This function sends an HTTP GET request to the specified URL using
 * the ESP-IDF HTTP client. If the request succeeds and the server
 * returns a valid HTTP status code (2xx), the response body is read
 * into dynamically allocated memory.
 *
 * The response buffer is NULL-terminated to allow safe usage with
 * string-based APIs (e.g., JSON parsing with cJSON).
 *
 * @param[in]  http_address     Null-terminated string containing the full
 *                               HTTP URL (e.g., "http://192.168.1.100/api").
 *
 * @param[out] output_base      Pointer to a char pointer that will receive
 *                               the dynamically allocated response buffer.
 *                               On success, the caller takes ownership and
 *                               must free() the memory.
 *
 * @param[out] output_length    Pointer to a size_t that will contain the
 *                               number of bytes read (excluding NULL terminator).
 *
 * @return
 *      - ESP_OK               : Success.
 *      - ESP_ERR_INVALID_ARG  : One or more input arguments are NULL.
 *      - ESP_ERR_NO_MEM       : Memory allocation failed.
 *      - ESP_FAIL             : HTTP error, invalid status, or read failure.
 *
 * @note
 *  - This implementation requires the server to send a valid
 *    Content-Length header.
 *  - If the server uses "Transfer-Encoding: chunked", this function
 *    will fail because Content-Length will be -1.
 *  - The caller is responsible for calling free(*output_base)
 *    when the buffer is no longer needed.
 *
 * @warning
 *  Always verify the HTTP server response size before using this
 *  function in production environments with large payloads.
 */
esp_err_t http_get_and_parse(const char *http_address,
                             char **output_base,
                             size_t *output_length)
{
    if (!http_address || !output_base || !output_length) {
        return ESP_ERR_INVALID_ARG;
    }

    /* Initialize outputs to safe default state */
    *output_base = NULL;
    *output_length = 0;

    /* Configure HTTP client */
    esp_http_client_config_t config = {
        .url = http_address,
        .method = HTTP_METHOD_GET,
        //.timeout_ms = 8000,
        .timeout_ms = 15000,
    };

    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (!client) {
        ESP_LOGE(TAG_HTTP_GET, "HTTP Client doesn't start");
        return ESP_FAIL;
    }

    /* Perform HTTP transaction */
    esp_err_t err = esp_http_client_perform(client);
    if (err != ESP_OK) {
        ESP_LOGE(TAG_HTTP_GET, "HTTP perform failed: %s", esp_err_to_name(err));
        esp_http_client_cleanup(client);
        return err;
    }

    /* Validate HTTP status code */
    int status = esp_http_client_get_status_code(client);
    if (status < 200 || status >= 300) {
        ESP_LOGE(TAG_HTTP_GET, "HTTP status error: %d", status);
        esp_http_client_cleanup(client);
        return ESP_FAIL;
    }

    /* Retrieve Content-Length header */
    int content_length = esp_http_client_get_content_length(client);
    if (content_length <= 0) {
        /* 0 = empty body, -1 = chunked or unknown */
        ESP_LOGE(TAG_HTTP_GET, "Invalid or unknown Content-Length: %d", content_length);
        esp_http_client_cleanup(client);
        return ESP_FAIL;
    }

    /* Allocate buffer (+1 for NULL terminator) */
    char *buf = (char *)malloc((size_t)content_length + 1);
    if (!buf) {
        ESP_LOGE(TAG_HTTP_GET, "Memory allocation failed");
        esp_http_client_cleanup(client);
        return ESP_ERR_NO_MEM;
    }

    /* Read HTTP response body */
    int read_len = esp_http_client_read_response(client, buf, content_length);
    if (read_len < 0) {
        ESP_LOGE(TAG_HTTP_GET, "Response read failed");
        free(buf);
        esp_http_client_cleanup(client);
        return ESP_FAIL;
    }

    /* NULL-terminate to make it a valid C-string */
    buf[read_len] = '\0';

    /* Transfer ownership to caller */
    *output_base = buf;
    *output_length = (size_t)read_len;

    ESP_LOGI(TAG_HTTP_GET, "HTTP response received (%d bytes)", read_len);

    esp_http_client_cleanup(client);
    return ESP_OK;
}

/**
 * @brief HTTP client event handler used to accumulate response data.
 *
 * This callback is invoked by the ESP-IDF HTTP client during
 * different stages of the HTTP transaction. When response body
 * data is received (HTTP_EVENT_ON_DATA), the function appends
 * the incoming chunk to a dynamically growing buffer.
 *
 * @param[in] evt  Pointer to the HTTP client event structure.
 *                 The user_data field must contain a valid
 *                 pointer to an initialized http_resp_t structure.
 *
 * @return
 *      - ESP_OK          : Event handled successfully.
 *      - ESP_ERR_NO_MEM  : Memory reallocation failed.
 *
 * @note
 *  - The response buffer is automatically resized (doubling strategy)
 *    when additional space is required.
 *  - The buffer is kept NULL-terminated to support JSON parsing.
 *
 * @warning
 *  The user_data pointer must be properly initialized before
 *  calling esp_http_client_perform().
 */
esp_err_t http_event_handler(esp_http_client_event_t *evt)
{
    http_resp_t *resp = (http_resp_t *)evt->user_data;

    switch (evt->event_id) {

    case HTTP_EVENT_ON_DATA:
        if (resp && evt->data && evt->data_len > 0) {

            /* Calculate required buffer size (+1 for NULL terminator) */
            size_t needed = resp->len + (size_t)evt->data_len + 1;

            /* Resize buffer if necessary */
            if (needed > resp->cap) {

                size_t new_cap = (resp->cap == 0) ? 512 : resp->cap;
                while (new_cap < needed)
                    new_cap *= 2;

                char *new_buf = (char *)realloc(resp->buf, new_cap);
                if (!new_buf) {
                    ESP_LOGE(TAG_HTTP_POST, "realloc failed");
                    return ESP_ERR_NO_MEM;
                }

                resp->buf = new_buf;
                resp->cap = new_cap;
            }

            /* Append new data chunk */
            memcpy(resp->buf + resp->len,
                   evt->data,
                   (size_t)evt->data_len);

            resp->len += (size_t)evt->data_len;

            /* Maintain NULL-termination */
            resp->buf[resp->len] = '\0';
        }
        break;

    default:
        break;
    }

    return ESP_OK;
}


/**
 * @brief Perform an HTTP POST request and retrieve the response body.
 *
 * This function sends a JSON payload to the specified HTTP endpoint
 * using the POST method. The response body is received incrementally
 * through the HTTP event handler and stored in a dynamically
 * allocated buffer.
 *
 * Upon success, ownership of the response buffer is transferred
 * to the caller.
 *
 * @param[in]  http_address        Null-terminated URL string.
 * @param[in]  json_body_to_post   JSON payload to be sent (NULL-terminated).
 * @param[out] response_output     Pointer to char pointer that will receive
 *                                  the allocated response buffer.
 * @param[out] response_length     Pointer to size_t that will receive
 *                                  the response size in bytes.
 *
 * @return
 *      - ESP_OK               : Success.
 *      - ESP_ERR_INVALID_ARG  : One or more arguments are NULL.
 *      - ESP_ERR_NO_MEM       : Memory allocation failed.
 *      - ESP_FAIL             : HTTP error or invalid server response.
 *
 * @note
 *  - The response buffer is NULL-terminated.
 *  - The caller must free(*response_output) after use.
 *  - This implementation supports both Content-Length and chunked
 *    transfer encoding.
 *
 * @warning
 *  Failure to free the returned buffer will result in a memory leak.
 */
esp_err_t http_post_and_get_response(const char *http_address,
                                     const char *json_body_to_post,
                                     char **response_output,
                                     size_t *response_length)
{
    if (!http_address || !json_body_to_post ||
        !response_output || !response_length) {
        return ESP_ERR_INVALID_ARG;
    }

    /* Initialize output parameters */
    *response_output = NULL;
    *response_length = 0;

    /* Allocate response container */
    http_resp_t *resp = (http_resp_t *)calloc(1, sizeof(http_resp_t));
    if (!resp) {
        return ESP_ERR_NO_MEM;
    }

    /* Configure HTTP client */
    esp_http_client_config_t config = {
        .url = http_address,
        .method = HTTP_METHOD_POST,
        .event_handler = http_event_handler,
        .user_data = resp,
        .timeout_ms = 8000,
    };

    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (!client) {
        free(resp);
        return ESP_FAIL;
    }

    /* Configure headers */
    esp_http_client_set_header(client, "Content-Type", "application/json");
    esp_http_client_set_header(client, "Accept", "application/json");

    /* Attach POST payload */
    esp_http_client_set_post_field(client,
                                   json_body_to_post,
                                   (int)strlen(json_body_to_post));

    /* Perform HTTP transaction */
    esp_err_t err = esp_http_client_perform(client);
    if (err != ESP_OK) {
        ESP_LOGE(TAG_HTTP_POST,
                 "HTTP POST failed: %s",
                 esp_err_to_name(err));
        goto cleanup_fail;
    }

    /* Validate HTTP status code */
    int status = esp_http_client_get_status_code(client);
    if (status < 200 || status >= 300) {
        ESP_LOGE(TAG_HTTP_POST,
                 "Server returned error status %d",
                 status);
        err = ESP_FAIL;
        goto cleanup_fail;
    }

    /* Validate response content */
    if (!resp->buf || resp->len == 0) {
        ESP_LOGE(TAG_HTTP_POST, "Empty response body");
        err = ESP_FAIL;
        goto cleanup_fail;
    }

    /* Transfer ownership to caller */
    *response_output = resp->buf;
    *response_length = resp->len;

    /* Detach buffer to prevent double free */
    resp->buf = NULL;
    resp->len = 0;
    resp->cap = 0;

    esp_http_client_cleanup(client);
    free(resp);

    return ESP_OK;

cleanup_fail:
    esp_http_client_cleanup(client);
    free(resp->buf);
    free(resp);
    return err;
}