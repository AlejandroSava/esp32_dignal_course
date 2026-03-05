#include <stdlib.h>
#include <string.h>
#include "mbedtls/base64.h"
#include "base64.h"
#include "esp_log.h"

#define BASE64_TAG "[BASE64]"
/* Optional safety cap to avoid huge allocations from untrusted inputs */
#define BASE64_MAX_OUTPUT (32 * 1024)   /* 32 KB, tune for your use-case */

/* --------------------------------------------------------- */
/*                 Base64 ENCODE                             */
/* --------------------------------------------------------- */
int base64_encode_alloc(const uint8_t *in, size_t in_len, char **out_b64)
{
    if (!in || !out_b64){
        ESP_LOGE(BASE64_TAG, "There is not a valiad in or in_len");  
        return -1;
    }
        
    *out_b64 = NULL;
    size_t olen = 0;

    /* Step  1: query required output length (olen) */
    /*Call this function with dlen = 0 to obtain the required buffer size in *olen*/
    int ret = mbedtls_base64_encode(NULL, 0, &olen, in, in_len);

    /* It will typically return MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL, that's OK.
       What matters is that olen is populated. */
    if (olen == 0){
        ESP_LOGE(BASE64_TAG, "The size is 0, empty. Nothing to decode");  
        return -2;
    }
         
    if (olen > BASE64_MAX_OUTPUT){  
        ESP_LOGE(BASE64_TAG, "The size exceeded the MAX OUTPUT, preventing overflow");
        return -3;
    } 

    /* Allocate exactly olen bytes. mbedTLS's olen for encode includes space
       for the terminating '\0' in practice on many builds, but DON'T assume.
       We'll allocate olen + 1 and add our own '\0'. */
    char *buf = (char *)malloc(olen + 1);
    if (!buf){
        ESP_LOGE(BASE64_TAG, "Not Allocating Memory");  
        return -4;
    }

    size_t actual_size = 0;

    /* step 2: encode for real */
    ret = mbedtls_base64_encode((unsigned char *)buf, olen + 1, &actual_size, in, in_len);
    if (ret != 0) {
        free(buf);
        ESP_LOGE(BASE64_TAG, "Not Decoding");  
        return -5;
    }

    /* Ensure null termination for safe printing / JSON usage */
    buf[actual_size] = '\0';

    *out_b64 = buf;
    return 0;
}


/* --------------------------------------------------------- */
/*                 Base64 DECODE (2-pass)                    */
/* --------------------------------------------------------- */
int base64_decode_alloc(const char *in_b64, uint8_t **out, size_t *out_len)
{
    if (!in_b64 || !out || !out_len){
        ESP_LOGE(BASE64_TAG, "There is not a valid in or in_len"); 
        return -1;
    }

    *out = NULL;
    *out_len = 0;

    const size_t in_len = strlen(in_b64);
    if (in_len == 0){
        ESP_LOGE(BASE64_TAG, "The size is 0, empty. Nothing to decode");  
        return -2;
    }

    size_t olen = 0;

    /* step 1: query required decoded length (olen) */
    int ret = mbedtls_base64_decode(NULL, 0, &olen,
                                    (const unsigned char *)in_b64, in_len);

    /* Same deal: ret may be BUFFER_TOO_SMALL; we only require olen > 0 */
    if (olen == 0){
        ESP_LOGE(BASE64_TAG, "Buffer to small");  
        return -3;
    }
    if (olen > BASE64_MAX_OUTPUT){
        ESP_LOGE(BASE64_TAG, "The size exceeded the MAX OUTPUT, preventing overflow");
        return -4;
    }

    uint8_t *buf = (uint8_t *)malloc(olen);
    if (!buf){
        ESP_LOGE(BASE64_TAG, "Not Allocating Memory");  
        return -5;
    }

    size_t actual_size = 0;

    /* step 2: decode for real */
    ret = mbedtls_base64_decode(buf, olen, &actual_size,
                                (const unsigned char *)in_b64, in_len);
    if (ret != 0) {
        free(buf);
        ESP_LOGE(BASE64_TAG, "Not Decoding");  
        return -6;
    }

    *out = buf;
    *out_len = actual_size;
    return 0;
}