#include <stdio.h>
#include <string.h>
#include "cJSON.h"
#include "mbedtls/base64.h"
#include "esp_random.h"

#define IV_AES 16

// ----- helpers -----
static void print_hex(const char *label, const uint8_t *buf, size_t len){
    printf("%s (%zu bytes): ", label, len);
    for (size_t i = 0; i < len; i++) printf("%02X", buf[i]);
    printf("\n");
}

void create_json_example(){
    cJSON *root = cJSON_CreateObject();

    cJSON_AddStringToObject(root, "device_id", "ESP32_01");
    cJSON_AddNumberToObject(root, "counter", 10);
    cJSON_AddStringToObject(root, "iv", "AQIDBAUGBwg=");
    char *json_string = cJSON_Print(root);
    printf("%s\n", json_string);

    cJSON_Delete(root);
    free(json_string);
}


void app_main(void){   
    uint8_t iv[IV_AES];
    esp_fill_random(iv, sizeof(IV_AES));
    print_hex("IV SIZE", iv, IV_AES);

    char *iv_b64 = NULL; 
    size_t iv_len_b64 = 0;

    /* First get required size */
    mbedtls_base64_encode(NULL, 0, &iv_len_b64, iv, IV_AES);

    /* Allocate */
    iv_b64 = malloc(iv_len_b64 + 1);

    /* Encode */
    mbedtls_base64_encode((unsigned char*)iv_b64, iv_len_b64,
                        &iv_len_b64, iv, IV_AES);

    iv_b64[iv_len_b64] = '\0';
    printf("IV Base64: %s\n", iv_b64);
    
    /*JSON format*/
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "iv", iv_b64);
    cJSON_AddNumberToObject(root, "iv_size", IV_AES);
    char *json_string = cJSON_Print(root);
    printf("%s\n", json_string);
    /*Remember to deallocate the memory */
    cJSON_Delete(root);

    /*----- HOW TO PARSE THE DATA -----*/
    // receive the json info: 
    // 3) Parse JSON
    cJSON *receive_json_data= cJSON_Parse(json_string);
    free(json_string); // json_str no longer needed after parsing
    
    cJSON *iv_b64_item = cJSON_GetObjectItem(receive_json_data, "iv");
    cJSON *iv_b64_item_size = cJSON_GetObjectItem(receive_json_data, "iv_size");
    // verification of the content, if the data is string and has data
    if (!cJSON_IsNumber(iv_b64_item_size) || !cJSON_IsString(iv_b64_item) || (iv_b64_item->valuestring == NULL)) {
        printf("Missing iv_b64\n");
        cJSON_Delete(receive_json_data);
        return;
    }

    printf("iv base 64%s\n", iv_b64_item->valuestring);
    printf("iv size %d \n", iv_b64_item_size->valueint);

    // allocate memory for the base64 decode
    const char *iv_b64_input = cJSON_GetObjectItem(receive_json_data, "iv")->valuestring;
    uint8_t *iv_b64_output = NULL; 
    size_t iv_len_b64_output = 0;
    size_t olen;

    /* First get required size */
    mbedtls_base64_decode(NULL, 0, &olen, (const unsigned char *)iv_b64_input , strlen(iv_b64_input));

    /* Allocate */
    iv_len_b64_output = olen;
    iv_b64_output = malloc(iv_len_b64_output + 1);
    
    /* Encode */
    mbedtls_base64_decode(iv_b64_output, iv_len_b64_output, &olen, (const unsigned char *)iv_b64_input, strlen(iv_b64_input));

    // Print decoded IV (hex)
    printf("Decoded IV: ");
    for (int i = 0; i < 16; i++) printf("%02X", iv_b64_output[i]);
        printf("\n");
    /*Remember to deallocate the memory */

    cJSON_Delete(receive_json_data);

    /*remember to free iv_b64*/
    
    free(iv_b64);
}
