#include <string.h>
#include <stdio.h>

#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "wifi.h"
#include "esp_http_client.h"
#define TAG "HTTP_ESP32"
void http_get_and_read(void)
{
    esp_http_client_config_t config = {
        .url = "http://192.168.1.236:5000/example",
        .method = HTTP_METHOD_GET,
    };

    esp_http_client_handle_t client = esp_http_client_init(&config);

    esp_err_t err = esp_http_client_perform(client);

    if (err == ESP_OK) {

        int content_length = esp_http_client_get_content_length(client);
        ESP_LOGI("HTTP", "Content-Length: %d", content_length);

        char *buffer = malloc(content_length + 1);
        if (!buffer) {
            ESP_LOGE("HTTP", "Memory allocation failed");
            return;
        }

        int read_len = esp_http_client_read_response(
                            client,
                            buffer,
                            content_length);

        buffer[read_len] = '\0';   // null terminate

        ESP_LOGI("HTTP", "Response: %s", buffer);
        printf("HTTP_Response: %s\n", buffer);

        free(buffer);
    }

    esp_http_client_cleanup(client);
}

void http_get_read_body()
{
    esp_http_client_config_t config = {
        .url = "http://192.168.1.236:5000/example",
        .method = HTTP_METHOD_GET,
        .timeout_ms = 10000,
        .buffer_size = 2000,   // helps with bigger payloads
    };

    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (!client) {
        ESP_LOGE(TAG, "Failed to init http client");
        return;
    }

    esp_err_t err = esp_http_client_open(client, 0);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "open failed: %s", esp_err_to_name(err));
        esp_http_client_cleanup(client);
        return;
    }

    int content_length = esp_http_client_fetch_headers(client);
    int status = esp_http_client_get_status_code(client);

    ESP_LOGI(TAG, "HTTP status: %d", status);
    ESP_LOGI(TAG, "Content-Length: %d", content_length);

    // Content-Length can be -1 if chunked, so handle both cases
    int buf_cap = (content_length > 0) ? (content_length + 1) : (4096);
    char *buf = malloc(buf_cap);
    if (!buf) {
        ESP_LOGE(TAG, "malloc failed");
        esp_http_client_close(client);
        esp_http_client_cleanup(client);
        return;
    }

    int total = 0;
    while (1) {
        int to_read = buf_cap - 1 - total;
        if (to_read <= 0) break;

        int r = esp_http_client_read(client, buf + total, to_read);
        if (r < 0) {
            ESP_LOGE(TAG, "read error");
            break;
        }
        if (r == 0) {
            // no more data
            break;
        }
        total += r;

        // If content length known, stop exactly there
        if (content_length > 0 && total >= content_length) break;
    }

    buf[total] = '\0';

    ESP_LOGI(TAG, "Read bytes: %d", total);

    // Important: print using length (safe even if body has '\0')
    ESP_LOGI(TAG, "Response (first 200 chars): %.*s", (total > 200 ? 200 : total), buf);
    printf("HTTP_Response: %s\n", buf);

    free(buf);
    esp_http_client_close(client);
    esp_http_client_cleanup(client);
}

void app_main(void)
{
    // NVS is required by Wi-Fi
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ESP_ERROR_CHECK(nvs_flash_init());
    }

    wifi_init_sta();
    http_get_and_read();
    http_get_read_body();
}
