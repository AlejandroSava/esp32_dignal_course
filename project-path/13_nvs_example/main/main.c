#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_wifi.h"

static const char *TAG = "NVS_WIFI";

// Definición de namespace para configuración WiFi
#define NVS_NAMESPACE_WIFI "wifi_config"

// Claves NVS para diferentes parámetros
#define NVS_KEY_SSID           "ssid"
#define NVS_KEY_PASSWORD       "password"
#define NVS_KEY_AUTH_MODE      "auth_mode"
#define NVS_KEY_CHANNEL        "channel"
#define NVS_KEY_MAX_CONN       "max_conn"
#define NVS_KEY_DHCP_ENABLED   "dhcp_en"
#define NVS_KEY_STATIC_IP      "static_ip"
#define NVS_KEY_GATEWAY        "gateway"
#define NVS_KEY_NETMASK        "netmask"
#define NVS_KEY_DNS_PRIMARY    "dns_pri"
#define NVS_KEY_DNS_SECONDARY  "dns_sec"
#define NVS_KEY_HOSTNAME       "hostname"
#define NVS_KEY_CONFIG_VALID   "cfg_valid"

/**
 * @brief Estructura de configuración WiFi completa
 * 
 * Esta estructura contiene todos los parámetros necesarios para
 * configurar una conexión WiFi, incluyendo modo STA y AP.
 */
typedef struct {
    char ssid[32];              // SSID de la red (máximo 32 caracteres)
    char password[64];          // Contraseña (máximo 64 caracteres WPA2)
    wifi_auth_mode_t auth_mode; // Modo de autenticación
    uint8_t channel;            // Canal WiFi (1-13)
    uint8_t max_connections;    // Máximo de conexiones en modo AP
    bool dhcp_enabled;          // DHCP habilitado/deshabilitado
    uint32_t static_ip;         // IP estática (formato uint32_t)
    uint32_t gateway;           // Puerta de enlace
    uint32_t netmask;           // Máscara de subred
    uint32_t dns_primary;       // DNS primario
    uint32_t dns_secondary;     // DNS secundario
    char hostname[32];          // Nombre del host
    bool config_valid;          // Flag de validación de configuración
} app_wifi_config_t;

/**
 * @brief Inicializa la partición NVS
 * 
 * Esta función debe llamarse antes de cualquier operación NVS.
 * Maneja automáticamente la corrupción de datos y reinicialización.
 * 
 * @return esp_err_t ESP_OK si la inicialización fue exitosa
 */
esp_err_t nvs_init(void)
{
    esp_err_t ret = nvs_flash_init();
    
    // Si NVS está lleno o tiene una versión incompatible, borramos y reiniciamos
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_LOGW(TAG, "NVS partición requiere borrado. Reinicializando...");
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    
    if (ret == ESP_OK) {
        ESP_LOGI(TAG, "NVS inicializado correctamente");
    } else {
        ESP_LOGE(TAG, "Error al inicializar NVS: %s", esp_err_to_name(ret));
    }
    
    return ret;
}

/**
 * @brief Guarda la configuración WiFi en NVS
 * 
 * Esta función almacena todos los parámetros de configuración WiFi
 * en memoria no volátil. Utiliza transacciones para garantizar
 * consistencia de datos.
 * 
 * @param config Puntero a la estructura de configuración
 * @return esp_err_t ESP_OK si se guardó correctamente
 */
esp_err_t save_wifi_config(const  app_wifi_config_t *config)
{
    if (config == NULL) {
        ESP_LOGE(TAG, "Configuración NULL");
        return ESP_ERR_INVALID_ARG;
    }
    
    nvs_handle_t nvs_handle;
    esp_err_t ret;
    
    // Abrimos el namespace en modo lectura/escritura
    ret = nvs_open(NVS_NAMESPACE_WIFI, NVS_READWRITE, &nvs_handle);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Error abriendo NVS: %s", esp_err_to_name(ret));
        return ret;
    }
    
    ESP_LOGI(TAG, "Guardando configuración WiFi...");
    
    // Guardamos cada campo individualmente
    // nvs_set_str almacena strings (automáticamente añade '\0')
    ret = nvs_set_str(nvs_handle, NVS_KEY_SSID, config->ssid);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Error guardando SSID: %s", esp_err_to_name(ret));
        goto close_handle;
    }
    
    ret = nvs_set_str(nvs_handle, NVS_KEY_PASSWORD, config->password);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Error guardando password: %s", esp_err_to_name(ret));
        goto close_handle;
    }
    
    // nvs_set_u8, nvs_set_u32 para tipos numéricos
    ret = nvs_set_u8(nvs_handle, NVS_KEY_AUTH_MODE, (uint8_t)config->auth_mode);
    if (ret != ESP_OK) goto close_handle;
    
    ret = nvs_set_u8(nvs_handle, NVS_KEY_CHANNEL, config->channel);
    if (ret != ESP_OK) goto close_handle;
    
    ret = nvs_set_u8(nvs_handle, NVS_KEY_MAX_CONN, config->max_connections);
    if (ret != ESP_OK) goto close_handle;
    
    // Para booleanos, usamos u8 (0 o 1)
    ret = nvs_set_u8(nvs_handle, NVS_KEY_DHCP_ENABLED, config->dhcp_enabled ? 1 : 0);
    if (ret != ESP_OK) goto close_handle;
    
    // Parámetros de red como uint32_t
    ret = nvs_set_u32(nvs_handle, NVS_KEY_STATIC_IP, config->static_ip);
    if (ret != ESP_OK) goto close_handle;
    
    ret = nvs_set_u32(nvs_handle, NVS_KEY_GATEWAY, config->gateway);
    if (ret != ESP_OK) goto close_handle;
    
    ret = nvs_set_u32(nvs_handle, NVS_KEY_NETMASK, config->netmask);
    if (ret != ESP_OK) goto close_handle;
    
    ret = nvs_set_u32(nvs_handle, NVS_KEY_DNS_PRIMARY, config->dns_primary);
    if (ret != ESP_OK) goto close_handle;
    
    ret = nvs_set_u32(nvs_handle, NVS_KEY_DNS_SECONDARY, config->dns_secondary);
    if (ret != ESP_OK) goto close_handle;
    
    ret = nvs_set_str(nvs_handle, NVS_KEY_HOSTNAME, config->hostname);
    if (ret != ESP_OK) goto close_handle;
    
    // Flag de validación - indica que la configuración está completa
    ret = nvs_set_u8(nvs_handle, NVS_KEY_CONFIG_VALID, config->config_valid ? 1 : 0);
    if (ret != ESP_OK) goto close_handle;
    
    // CRÍTICO: commit() hace permanentes los cambios en flash
    // Sin commit, los datos solo están en cache RAM
    ret = nvs_commit(nvs_handle);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Error en commit: %s", esp_err_to_name(ret));
    } else {
        ESP_LOGI(TAG, "Configuración WiFi guardada exitosamente");
        ESP_LOGI(TAG, "  SSID: %s", config->ssid);
        ESP_LOGI(TAG, "  Canal: %d", config->channel);
        ESP_LOGI(TAG, "  Auth: %d", config->auth_mode);
    }
    
close_handle:
    // Siempre cerramos el handle
    nvs_close(nvs_handle);
    return ret;
}

/**
 * @brief Carga la configuración WiFi desde NVS
 * 
 * Lee todos los parámetros guardados y los carga en la estructura.
 * Si algún valor no existe, usa valores por defecto.
 * 
 * @param config Puntero a estructura donde se cargará la configuración
 * @return esp_err_t ESP_OK si se cargó correctamente
 */
esp_err_t load_wifi_config(app_wifi_config_t *config)
{
    if (config == NULL) {
        ESP_LOGE(TAG, "Configuración NULL");
        return ESP_ERR_INVALID_ARG;
    }
    
    nvs_handle_t nvs_handle;
    esp_err_t ret;
    
    // Abrimos en modo solo lectura (más eficiente si solo vamos a leer)
    ret = nvs_open(NVS_NAMESPACE_WIFI, NVS_READONLY, &nvs_handle);
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "No se pudo abrir NVS (¿primera vez?): %s", esp_err_to_name(ret));
        return ret;
    }
    
    ESP_LOGI(TAG, "Cargando configuración WiFi...");
    
    // Para strings, necesitamos el tamaño del buffer
    size_t required_size;
    
    // SSID
    required_size = sizeof(config->ssid);
    ret = nvs_get_str(nvs_handle, NVS_KEY_SSID, config->ssid, &required_size);
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "SSID no encontrado, usando default");
        strcpy(config->ssid, "ESP32_Default");
    }
    
    // Password
    required_size = sizeof(config->password);
    ret = nvs_get_str(nvs_handle, NVS_KEY_PASSWORD, config->password, &required_size);
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "Password no encontrado, usando default");
        strcpy(config->password, "");
    }
    
    // Modo de autenticación
    uint8_t temp_u8;
    ret = nvs_get_u8(nvs_handle, NVS_KEY_AUTH_MODE, &temp_u8);
    config->auth_mode = (ret == ESP_OK) ? (wifi_auth_mode_t)temp_u8 : WIFI_AUTH_WPA2_PSK;
    
    // Canal
    ret = nvs_get_u8(nvs_handle, NVS_KEY_CHANNEL, &config->channel);
    if (ret != ESP_OK) config->channel = 1;
    
    // Conexiones máximas
    ret = nvs_get_u8(nvs_handle, NVS_KEY_MAX_CONN, &config->max_connections);
    if (ret != ESP_OK) config->max_connections = 4;
    
    // DHCP habilitado
    ret = nvs_get_u8(nvs_handle, NVS_KEY_DHCP_ENABLED, &temp_u8);
    config->dhcp_enabled = (ret == ESP_OK) ? (temp_u8 != 0) : true;
    
    // IP estática
    ret = nvs_get_u32(nvs_handle, NVS_KEY_STATIC_IP, &config->static_ip);
    if (ret != ESP_OK) config->static_ip = 0xC0A80164; // 192.168.1.100
    
    // Gateway
    ret = nvs_get_u32(nvs_handle, NVS_KEY_GATEWAY, &config->gateway);
    if (ret != ESP_OK) config->gateway = 0xC0A80101; // 192.168.1.1
    
    // Netmask
    ret = nvs_get_u32(nvs_handle, NVS_KEY_NETMASK, &config->netmask);
    if (ret != ESP_OK) config->netmask = 0xFFFFFF00; // 255.255.255.0
    
    // DNS primario
    ret = nvs_get_u32(nvs_handle, NVS_KEY_DNS_PRIMARY, &config->dns_primary);
    if (ret != ESP_OK) config->dns_primary = 0x08080808; // 8.8.8.8
    
    // DNS secundario
    ret = nvs_get_u32(nvs_handle, NVS_KEY_DNS_SECONDARY, &config->dns_secondary);
    if (ret != ESP_OK) config->dns_secondary = 0x08080404; // 8.8.4.4
    
    // Hostname
    required_size = sizeof(config->hostname);
    ret = nvs_get_str(nvs_handle, NVS_KEY_HOSTNAME, config->hostname, &required_size);
    if (ret != ESP_OK) {
        strcpy(config->hostname, "esp32-device");
    }
    
    // Flag de validación
    ret = nvs_get_u8(nvs_handle, NVS_KEY_CONFIG_VALID, &temp_u8);
    config->config_valid = (ret == ESP_OK) ? (temp_u8 != 0) : false;
    
    nvs_close(nvs_handle);
    
    ESP_LOGI(TAG, "Configuración cargada:");
    ESP_LOGI(TAG, "  SSID: %s", config->ssid);
    ESP_LOGI(TAG, "  Canal: %d", config->channel);
    ESP_LOGI(TAG, "  DHCP: %s", config->dhcp_enabled ? "Habilitado" : "Deshabilitado");
    ESP_LOGI(TAG, "  Hostname: %s", config->hostname);
    ESP_LOGI(TAG, "  Config válida: %s", config->config_valid ? "Sí" : "No");
    
    return ESP_OK;
}

/**
 * @brief Borra toda la configuración WiFi
 * 
 * Elimina todas las claves del namespace WiFi.
 * Útil para reset de fábrica.
 * 
 * @return esp_err_t ESP_OK si se borró correctamente
 */
esp_err_t erase_wifi_config(void)
{
    nvs_handle_t nvs_handle;
    esp_err_t ret;
    
    ret = nvs_open(NVS_NAMESPACE_WIFI, NVS_READWRITE, &nvs_handle);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Error abriendo NVS para borrar: %s", esp_err_to_name(ret));
        return ret;
    }
    
    // nvs_erase_all() borra todas las claves del namespace
    ret = nvs_erase_all(nvs_handle);
    if (ret == ESP_OK) {
        ret = nvs_commit(nvs_handle);
        ESP_LOGI(TAG, "Configuración WiFi borrada completamente");
    } else {
        ESP_LOGE(TAG, "Error borrando configuración: %s", esp_err_to_name(ret));
    }
    
    nvs_close(nvs_handle);
    return ret;
}

/**
 * @brief Función auxiliar para convertir uint32_t a string IP
 */
void uint32_to_ip_string(uint32_t ip, char *buffer)
{
    sprintf(buffer, "%d.%d.%d.%d",
            (int)(ip & 0xFF),
            (int)((ip >> 8) & 0xFF),
            (int)((ip >> 16) & 0xFF),
            (int)((ip >> 24) & 0xFF));
}

/**
 * @brief Tarea principal de demostración
 */
void app_main(void)
{
    ESP_LOGI(TAG, "=== Práctica 13.1 Persistencia de parametros de red ===");
    
    // Inicializamos NVS
    ESP_ERROR_CHECK(nvs_init());
    
    /******************* NVS STATS ******************** */
    // ... después de nvs_flash_init() ...

    nvs_stats_t nvs_stats;
    esp_err_t err = nvs_get_stats(NULL, &nvs_stats);

    if (err == ESP_OK) {
        ESP_LOGI(TAG, "=== Estadísticas NVS ===");
        ESP_LOGI(TAG, "Total de entradas: %d", nvs_stats.total_entries);
        ESP_LOGI(TAG, "Entradas usadas:   %d", nvs_stats.used_entries);
        ESP_LOGI(TAG, "Entradas libres:   %d", nvs_stats.free_entries);
        ESP_LOGI(TAG, "Namespaces:        %d", nvs_stats.namespace_count);
    } else {
        ESP_LOGE(TAG, "Falló al leer estadísticas NVS");
    }

    /************************************************** */
    // Intentamos cargar configuración existente
    app_wifi_config_t config;
    esp_err_t ret = load_wifi_config(&config);
    
    if (ret != ESP_OK || !config.config_valid) {
        // Primera vez o configuración inválida - creamos una nueva
        ESP_LOGI(TAG, "Creando configuración inicial...");
        
        strcpy(config.ssid, "MiRedWiFi");
        strcpy(config.password, "MiPassword123");
        config.auth_mode = WIFI_AUTH_WPA2_PSK;
        config.channel = 6;
        config.max_connections = 4;
        config.dhcp_enabled = false;
        config.static_ip = 0xC0A8010A;      // 192.168.1.10
        config.gateway = 0xC0A80101;        // 192.168.1.1
        config.netmask = 0xFFFFFF00;        // 255.255.255.0
        config.dns_primary = 0x08080808;    // 8.8.8.8
        config.dns_secondary = 0x08080404;  // 8.8.4.4
        strcpy(config.hostname, "esp32-sensor-01");
        config.config_valid = true;
        
        // Guardamos
        ret = save_wifi_config(&config);
        if (ret == ESP_OK) {
            ESP_LOGI(TAG, "✓ Configuración inicial guardada");
        }
    } else {
        ESP_LOGI(TAG, "✓ Configuración existente cargada correctamente");
        
        // Mostramos detalles
        char ip_str[16];
        uint32_to_ip_string(config.static_ip, ip_str);
        ESP_LOGI(TAG, "IP Estática: %s", ip_str);
        
        uint32_to_ip_string(config.gateway, ip_str);
        ESP_LOGI(TAG, "Gateway: %s", ip_str);
    }
    
    // Simulamos modificación de configuración
    vTaskDelay(pdMS_TO_TICKS(3000));
    ESP_LOGI(TAG, "\n--- Modificando configuración ---");
    
    strcpy(config.ssid, "2025 red");
    config.channel = 10;
    config.dhcp_enabled = false;
    
    ret = save_wifi_config(&config);
    if (ret == ESP_OK) {
        ESP_LOGI(TAG, "✓ Configuración actualizada");
    }
    
    // Verificamos persistencia reiniciando
    vTaskDelay(pdMS_TO_TICKS(2000));
    ESP_LOGI(TAG, "\n--- Verificando persistencia ---");
    
    app_wifi_config_t loaded_config;
    load_wifi_config(&loaded_config);
    
    if (strcmp(loaded_config.ssid, "NuevaRed_2024") == 0) {
        ESP_LOGI(TAG, "✓ Datos persistentes verificados");
    }else{
        ESP_LOGI(TAG, "Datos de persistencia no coinciden");
    }
    
    ESP_LOGI(TAG, "\n=== Práctica completada ===");
    ESP_LOGI(TAG, "Los datos permanecerán después del reinicio");
    
    // Descomentar para reset de fábrica:
    //erase_wifi_config();
}