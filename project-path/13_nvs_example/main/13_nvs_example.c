#include <stdio.h>
#include <string.h>
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_log.h"

static const char *TAG = "NVS_BASIC";

/* Estructura para el ejemplo de BLOB */
typedef struct {
    uint8_t id;
    uint16_t value;
} config_t;

void app_main(void)
{
    esp_err_t err;
    nvs_handle_t nvs_handle; // manejador, llave que usamos para todas las funciones 

    /* 1. Inicializar NVS */
    err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES ||
        err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        nvs_flash_init();
    }

    
    ESP_LOGI(TAG, "NVS inicializado correctamente");

    /* 2. Abrir namespace */
    err = nvs_open("storage", NVS_READWRITE, &nvs_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Error al abrir NVS");
        return;
    }

    /* ==========================================================
     * ESCRITURA DE DATOS
     * ========================================================== */

    /* Entero */
    uint8_t counter = 10;
    nvs_set_u8(nvs_handle, "counter", counter);

    /* String */
    const char *device_name = "ESP32-NVS";
    nvs_set_str(nvs_handle, "name", device_name);

    /* Blob */
    config_t config_write = {
        .id = 1,
        .value = 500
    };
    nvs_set_blob(nvs_handle, "config", &config_write, sizeof(config_write));

    /* Confirmar escritura */
    nvs_commit(nvs_handle);
    ESP_LOGI(TAG, "Datos escritos en NVS");

    /* ==========================================================
     * LECTURA DE DATOS
     * ========================================================== */

    /* Leer entero */
    uint8_t counter_read = 0;
    nvs_get_u8(nvs_handle, "counter", &counter_read);
    ESP_LOGI(TAG, "Counter leído: %d", counter_read);

    /* Leer string */
    size_t required_size = 0;
    nvs_get_str(nvs_handle, "name", NULL, &required_size);

    char name_read[required_size];
    nvs_get_str(nvs_handle, "name", name_read, &required_size);
    ESP_LOGI(TAG, "Nombre leído: %s", name_read);

    /* Leer blob */
    config_t config_read;
    size_t blob_size = sizeof(config_read);
    nvs_get_blob(nvs_handle, "config", &config_read, &blob_size);

    ESP_LOGI(TAG, "Config leída -> id: %d, value: %d",
             config_read.id, config_read.value);

    /* 3. Cerrar NVS */
    nvs_close(nvs_handle);

    ESP_LOGI(TAG, "Práctica NVS finalizada");
}
