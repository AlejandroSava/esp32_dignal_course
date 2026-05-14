#include <stdlib.h>
#include <string.h>

#include "esp_log.h"
#include "esp_system.h"
#include "mbedtls/md.h"
#include "esp_random.h"
#include "cJSON.h"

#include "secure_channel.h"
#include "aes_cbc.h"
#include "base64.h"
#include "http_transactions.h"


bool start_secure_channel_session(struct secure_session *self,
                                  const uint8_t *sid,
                                  size_t sid_len,
                                  const uint8_t *kenc,
                                  const uint8_t *kmac)
{
    ESP_LOGI(TAG_SEC_CHAN, "START SECURE CHANNEL SESSION");
    if (self == NULL || sid == NULL || sid_len == 0 ||
        kenc == NULL || kmac == NULL) {
        ESP_LOGE(TAG_SEC_CHAN, "Invalid input parameters");
        return false;
    }


    self->sid = malloc(sid_len);
    if (self->sid == NULL) {
        ESP_LOGE(TAG_SEC_CHAN, "Failed to allocate SID buffer");
        return false;
    }

    memcpy(self->sid, sid, sid_len);
    self->sid_len = (uint32_t) sid_len;

    memcpy(self->kenc, kenc, KEY_SEC_CHAN_SIZE);
    memcpy(self->kmac, kmac, KEY_SEC_CHAN_SIZE);

    self->tx_seq = 0;
    self->rx_seq = 0;

    return true;
}

void free_secure_channel_session(struct secure_session *self)
{
    if (self == NULL) {
        return;
    }

    if (self->sid != NULL) {
        free(self->sid);
        self->sid = NULL;
    }

    self->sid_len = 0;
    self->tx_seq = 0;
    self->rx_seq = 0;

    memset(self->kenc, 0, KEY_SEC_CHAN_SIZE);
    memset(self->kmac, 0, KEY_SEC_CHAN_SIZE);
    ESP_LOGI(TAG_SEC_CHAN, "SECURE CHANNEL SESSION IS FREE");
}

bool build_secure_plain_data_float(struct secure_plain_data *self,
                                   const uint8_t *payload,
                                   uint32_t payload_len)
{
    if (self == NULL || payload == NULL) {
        ESP_LOGE(TAG_SEC_CHAN, "Invalid input parameters");
        return false;
    }

    if (payload_len != sizeof(float)) {
        ESP_LOGE(TAG_SEC_CHAN, "Invalid float payload length: %lu",
                 (unsigned long)payload_len);
        return false;
    }

    //memset(self, 0, sizeof(*self));

    self->payload = malloc(payload_len);
    if (self->payload == NULL) {
        ESP_LOGE(TAG_SEC_CHAN, "Failed to allocate payload buffer");
        return false;
    }

    memcpy(self->payload, payload, payload_len);

    self->version = SEC_CHAN_VERSION;
    self->payload_type = PAYLOAD_TYPE_FLOAT;
    self->reserved = 0;
    self->payload_len = payload_len;

    return true;
}



void free_secure_plain_data(struct secure_plain_data *self)
{
    if (self == NULL) {
        return;
    }

    if (self->payload != NULL) {
        free(self->payload);
        self->payload = NULL;
    }

    self->payload_len = 0;
    self->payload_type = 0;
    self->version = 0;
    self->reserved = 0;
    ESP_LOGI(TAG_SEC_CHAN, "SECURE PLAIN DATA IS FREE");
}


bool hmac_update_u32_be(mbedtls_md_context_t *ctx, uint32_t value)
{
    uint8_t buf[4];

    buf[0] = (uint8_t)((value >> 24) & 0xFF);
    buf[1] = (uint8_t)((value >> 16) & 0xFF);
    buf[2] = (uint8_t)((value >> 8) & 0xFF);
    buf[3] = (uint8_t)(value & 0xFF);

    return mbedtls_md_hmac_update(ctx, buf, sizeof(buf)) == 0;
}

bool get_tag_sc(struct secure_message *self,
                const struct secure_session *session)
{
    int ret;
    mbedtls_md_context_t ctx;
    const mbedtls_md_info_t *md;

    if (self == NULL || session == NULL) {
        ESP_LOGE(TAG_SEC_CHAN, "Invalid NULL parameter");
        return false;
    }

    if (self->sid == NULL || self->sid_len == 0 ||
        self->ciphertext == NULL || self->ciphertext_len == 0 ||
        self->iv_len != AES_CBC_IV_SIZE) {
        ESP_LOGE(TAG_SEC_CHAN, "Invalid secure_message fields");
        return false;
    }

    md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
    if (md == NULL) {
        ESP_LOGE(TAG_SEC_CHAN, "SHA-512 not available");
        return false;
    }

    mbedtls_md_init(&ctx);

    ret = mbedtls_md_setup(&ctx, md, 1);
    if (ret != 0) {
        ESP_LOGE(TAG_SEC_CHAN, "mbedtls_md_setup failed: %d", ret);
        mbedtls_md_free(&ctx);
        return false;
    }

    ret = mbedtls_md_hmac_starts(&ctx,
                                 session->kmac,
                                 KEY_SEC_CHAN_SIZE);
    if (ret != 0) {
        ESP_LOGE(TAG_SEC_CHAN, "mbedtls_md_hmac_starts failed: %d", ret);
        mbedtls_md_free(&ctx);
        return false;
    }

    /*
     * HMAC input:
     * step || sid_len || sid || seq ||
     * iv_len || iv || ciphertext_len || ciphertext
     */

    if (!hmac_update_u32_be(&ctx, self->step)) {
        ESP_LOGE(TAG_SEC_CHAN, "HMAC update STEP failed");
        mbedtls_md_free(&ctx);
        return false;
    }

    if (!hmac_update_u32_be(&ctx, self->sid_len)) {
        ESP_LOGE(TAG_SEC_CHAN, "HMAC update SID_LEN failed");
        mbedtls_md_free(&ctx);
        return false;
    }

    ret = mbedtls_md_hmac_update(&ctx, self->sid, self->sid_len);
    if (ret != 0) {
        ESP_LOGE(TAG_SEC_CHAN, "HMAC update SID failed: %d", ret);
        mbedtls_md_free(&ctx);
        return false;
    }

    if (!hmac_update_u32_be(&ctx, self->seq)) {
        ESP_LOGE(TAG_SEC_CHAN, "HMAC update SEQ failed");
        mbedtls_md_free(&ctx);
        return false;
    }

    if (!hmac_update_u32_be(&ctx, self->iv_len)) {
        ESP_LOGE(TAG_SEC_CHAN, "HMAC update IV_LEN failed");
        mbedtls_md_free(&ctx);
        return false;
    }

    ret = mbedtls_md_hmac_update(&ctx, self->iv, self->iv_len);
    if (ret != 0) {
        ESP_LOGE(TAG_SEC_CHAN, "HMAC update IV failed: %d", ret);
        mbedtls_md_free(&ctx);
        return false;
    }

    if (!hmac_update_u32_be(&ctx, self->ciphertext_len)) {
        ESP_LOGE(TAG_SEC_CHAN, "HMAC update CIPHERTEXT_LEN failed");
        mbedtls_md_free(&ctx);
        return false;
    }

    ret = mbedtls_md_hmac_update(&ctx,
                                 self->ciphertext,
                                 self->ciphertext_len);
    if (ret != 0) {
        ESP_LOGE(TAG_SEC_CHAN, "HMAC update CIPHERTEXT failed: %d", ret);
        mbedtls_md_free(&ctx);
        return false;
    }

    ret = mbedtls_md_hmac_finish(&ctx, self->tag_sc);
    if (ret != 0) {
        ESP_LOGE(TAG_SEC_CHAN, "mbedtls_md_hmac_finish failed: %d", ret);
        mbedtls_md_free(&ctx);
        return false;
    }

    self->tag_sc_len = HMAC_SHA512_SIZE;

    mbedtls_md_free(&ctx);
    return true;
}

bool build_secure_message(struct secure_message *self,
                          struct secure_session *session,
                          const struct secure_plain_data *plain_data)
{
    bool status = false;
    uint8_t *temp_buf = NULL;
    size_t temp_buf_size = 0;
    size_t offset = 0;
    struct aes_256_obj *aes = malloc(sizeof(struct aes_256_obj));

    if (self == NULL || session == NULL || plain_data == NULL) {
        ESP_LOGE(TAG_SEC_CHAN, "Invalid NULL parameter");
        return false;
    }

    if (session->sid == NULL || session->sid_len == 0 ||
        plain_data->payload == NULL || plain_data->payload_len == 0) {
        ESP_LOGE(TAG_SEC_CHAN, "Invalid input fields");
        return false;
    }

    self->step = STEP_SEC_CHAN;

    self->sid_len = session->sid_len;
    self->sid = malloc((size_t)self->sid_len);
    if (self->sid == NULL) {
        ESP_LOGE(TAG_SEC_CHAN, "Failed to allocate SID");
        goto cleanup;
    }

    memcpy(self->sid, session->sid, (size_t)self->sid_len);

    
    self->seq = session->tx_seq;
    session->tx_seq++;

    self->iv_len = AES_CBC_IV_SIZE;
    esp_fill_random(self->iv, AES_CBC_IV_SIZE);

    create_aes_256_obj(aes, session->kenc);
    read_and_update_iv_aes(aes, self->iv);

    /*
     * Plaintext format:
     * version      : 1 byte
     * payload_type : 1 byte
     * reserved     : 2 bytes
     * payload_len  : 4 bytes
     * payload      : variable
     */
    temp_buf_size = 1U + 1U + 2U + 4U + (size_t)plain_data->payload_len;

    temp_buf = malloc(temp_buf_size);
    if (temp_buf == NULL) {
        ESP_LOGE(TAG_SEC_CHAN, "Failed to allocate plaintext buffer");
        goto cleanup;
    }

    temp_buf[offset++] = plain_data->version;
    temp_buf[offset++] = plain_data->payload_type;

    temp_buf[offset++] = (uint8_t)((plain_data->reserved >> 8) & 0xFF);
    temp_buf[offset++] = (uint8_t)(plain_data->reserved & 0xFF);

    temp_buf[offset++] = (uint8_t)((plain_data->payload_len >> 24) & 0xFF);
    temp_buf[offset++] = (uint8_t)((plain_data->payload_len >> 16) & 0xFF);
    temp_buf[offset++] = (uint8_t)((plain_data->payload_len >> 8) & 0xFF);
    temp_buf[offset++] = (uint8_t)(plain_data->payload_len & 0xFF);

    memcpy(temp_buf + offset,
           plain_data->payload,
           (size_t)plain_data->payload_len);

    offset += (size_t)plain_data->payload_len;

    if (offset != temp_buf_size) {
        ESP_LOGE(TAG_SEC_CHAN, "Plaintext serialization size mismatch");
        goto cleanup;
    }
    size_t ct_len = 0;

    
    if (aes_cbc_encrypt_pkcs7(aes->key,
                               aes->keybits,
                               aes->iv,
                               temp_buf,
                               temp_buf_size,
                               &self->ciphertext,
                               &ct_len) != 0){
        ESP_LOGE(TAG_SEC_CHAN, "AES-CBC encryption failed");
        goto cleanup;
    }

    self->ciphertext_len = (uint32_t)ct_len; //temp variable

    if (!get_tag_sc(self, session)) {
        ESP_LOGE(TAG_SEC_CHAN, "Failed to calculate TagSC");
        goto cleanup;
    }

    status = true;

cleanup:
    if (temp_buf != NULL) {
        memset(temp_buf, 0, temp_buf_size);
        free(temp_buf);
    }

    if (!status) {
        free_secure_message(self);
    }

    return status;
}

void free_secure_message(struct secure_message *self)
{
    if (self == NULL) {
        return;
    }

    if (self->sid != NULL) {
        free(self->sid);
        self->sid = NULL;
    }

    if (self->ciphertext != NULL) {
        free(self->ciphertext);
        self->ciphertext = NULL;
    }

    self->sid_len = 0;
    self->ciphertext_len = 0;
    self->tag_sc_len = 0;
    self->seq = 0;
    self->step = 0;
    self->iv_len = 0;

    memset(self->iv, 0, AES_CBC_IV_SIZE);
    memset(self->tag_sc, 0, HMAC_SHA512_SIZE);
    ESP_LOGI(TAG_SEC_CHAN, "SECURE MESSAGE IS FREE");
}



bool send_secure_channel_message(const struct secure_message *message,
                                 char **json_response_output,
                                 size_t *response_length,
                                 const char *http_address)
{
    bool status = false;
    esp_err_t err;

    cJSON *root = NULL;
    char *json_string = NULL;

    char *sid_b64 = NULL;
    char *iv_b64 = NULL;
    char *ciphertext_b64 = NULL;
    char *tag_sc_b64 = NULL;

    if (message == NULL ||
        json_response_output == NULL || response_length == NULL ||
        http_address == NULL) {
        ESP_LOGE(TAG_SEC_CHAN, "Invalid NULL parameter");
        return false;
    }

    if (message->sid == NULL || message->sid_len == 0 ||
        message->ciphertext == NULL || message->ciphertext_len == 0 ||
        message->iv_len != AES_CBC_IV_SIZE ||
        message->tag_sc_len != HMAC_SHA512_SIZE) {
        ESP_LOGE(TAG_SEC_CHAN, "Invalid secure message fields");
        return false;
    }

    *json_response_output = NULL;
    *response_length = 0;

    if (base64_encode_alloc(message->sid,
                             message->sid_len,
                             &sid_b64) != 0||
        base64_encode_alloc(message->iv,
                             message->iv_len,
                             &iv_b64) != 0||
        base64_encode_alloc(message->ciphertext,
                             message->ciphertext_len,
                             &ciphertext_b64) != 0||
        base64_encode_alloc(message->tag_sc,
                             message->tag_sc_len,
                             &tag_sc_b64)!= 0) {
        ESP_LOGE(TAG_SEC_CHAN, "Base64 encoding failed");
        goto cleanup;
    }

    root = cJSON_CreateObject();
    if (root == NULL) {
        ESP_LOGE(TAG_SEC_CHAN, "cJSON_CreateObject failed");
        goto cleanup;
    }

    if (cJSON_AddNumberToObject(root, "Step", message->step) == NULL ||
        cJSON_AddNumberToObject(root, "SID_Len", message->sid_len) == NULL ||
        cJSON_AddStringToObject(root, "SID", sid_b64) == NULL ||
        cJSON_AddNumberToObject(root, "Seq", message->seq) == NULL ||
        cJSON_AddNumberToObject(root, "IV_Len", message->iv_len) == NULL ||
        cJSON_AddStringToObject(root, "IV", iv_b64) == NULL ||
        cJSON_AddNumberToObject(root, "CipherText_Len", message->ciphertext_len) == NULL ||
        cJSON_AddStringToObject(root, "CipherText", ciphertext_b64) == NULL ||
        cJSON_AddNumberToObject(root, "Tag_SC_Len", message->tag_sc_len) == NULL ||
        cJSON_AddStringToObject(root, "Tag_SC", tag_sc_b64) == NULL) {
        ESP_LOGE(TAG_SEC_CHAN, "Failed to build JSON request");
        goto cleanup;
    }

    json_string = cJSON_PrintUnformatted(root);
    if (json_string == NULL) {
        ESP_LOGE(TAG_SEC_CHAN, "cJSON_PrintUnformatted failed");
        goto cleanup;
    }

    ESP_LOGI(TAG_SEC_CHAN, "SECURE CHANNEL MESSAGE JSON: %s", json_string);

    err = http_post_and_get_response(http_address,
                                     json_string,
                                     json_response_output,
                                     response_length);
    if (err != ESP_OK) {
        ESP_LOGE(TAG_SEC_CHAN, "HTTP error transaction in secure channel message");
        goto cleanup;
    }

    if (*json_response_output != NULL) {
        ESP_LOGI(TAG_SEC_CHAN, "Secure channel response: %s",
                 *json_response_output);
    }


    status = true;

cleanup:
    if (root != NULL) {
        cJSON_Delete(root);
    }

    free(json_string);
    free(sid_b64);
    free(iv_b64);
    free(ciphertext_b64);
    free(tag_sc_b64);

    return status;
}

bool get_secure_channel_response(struct secure_message *response,
                                 const char *json_response_output)
{
    cJSON *receive_json_data = NULL;
    uint8_t *sid_decoded = NULL;
    uint8_t *iv_decoded = NULL;
    uint8_t *ciphertext_decoded = NULL;
    uint8_t *tag_sc_decoded = NULL;

    size_t sid_decoded_len = 0;
    size_t iv_decoded_len = 0;
    size_t ciphertext_decoded_len = 0;
    size_t tag_sc_decoded_len = 0;

    if (response == NULL || json_response_output == NULL) {
        ESP_LOGE(TAG_SEC_CHAN, "Invalid input parameter");
        return false;
    }

    receive_json_data = cJSON_Parse(json_response_output);
    if (receive_json_data == NULL) {
        ESP_LOGE(TAG_SEC_CHAN, "JSON parse error");
        return false;
    }

    cJSON *step = cJSON_GetObjectItemCaseSensitive(receive_json_data, "Step");
    cJSON *sid_len = cJSON_GetObjectItemCaseSensitive(receive_json_data, "SID_Len");
    cJSON *sid = cJSON_GetObjectItemCaseSensitive(receive_json_data, "SID");
    cJSON *seq = cJSON_GetObjectItemCaseSensitive(receive_json_data, "Seq");
    cJSON *iv_len = cJSON_GetObjectItemCaseSensitive(receive_json_data, "IV_Len");
    cJSON *iv = cJSON_GetObjectItemCaseSensitive(receive_json_data, "IV");
    cJSON *ciphertext_len = cJSON_GetObjectItemCaseSensitive(receive_json_data, "CipherText_Len");
    cJSON *ciphertext = cJSON_GetObjectItemCaseSensitive(receive_json_data, "CipherText");
    cJSON *tag_sc_len = cJSON_GetObjectItemCaseSensitive(receive_json_data, "Tag_SC_Len");
    cJSON *tag_sc = cJSON_GetObjectItemCaseSensitive(receive_json_data, "Tag_SC");

    if (!cJSON_IsNumber(step) ||
        !cJSON_IsNumber(sid_len) ||
        !cJSON_IsString(sid) ||
        !cJSON_IsNumber(seq) ||
        !cJSON_IsNumber(iv_len) ||
        !cJSON_IsString(iv) ||
        !cJSON_IsNumber(ciphertext_len) ||
        !cJSON_IsString(ciphertext) ||
        !cJSON_IsNumber(tag_sc_len) ||
        !cJSON_IsString(tag_sc)) {
        ESP_LOGE(TAG_SEC_CHAN, "Invalid JSON response format");
        goto fail;
    }

    if ((uint32_t)iv_len->valueint != AES_CBC_IV_SIZE ||
        (uint32_t)tag_sc_len->valueint != HMAC_SHA512_SIZE) {
        ESP_LOGE(TAG_SEC_CHAN, "Invalid IV or TAG length");
        goto fail;
    }

    response->step = (uint32_t)step->valueint;
    response->sid_len = (uint32_t)sid_len->valueint;
    response->seq = (uint32_t)seq->valueint;
    response->iv_len = (uint32_t)iv_len->valueint;
    response->ciphertext_len = (uint32_t)ciphertext_len->valueint;
    response->tag_sc_len = (uint32_t)tag_sc_len->valueint;

    if (base64_decode_alloc(sid->valuestring, &sid_decoded, &sid_decoded_len) != 0 ||
        sid_decoded_len != response->sid_len) {
        ESP_LOGE(TAG_SEC_CHAN, "Error decoding SID");
        goto fail;
    }

    response->sid = malloc((size_t)response->sid_len);
    if (response->sid == NULL) {
        ESP_LOGE(TAG_SEC_CHAN, "Failed to allocate SID");
        goto fail;
    }
    memcpy(response->sid, sid_decoded, sid_decoded_len);

    if (base64_decode_alloc(iv->valuestring, &iv_decoded, &iv_decoded_len) != 0 ||
        iv_decoded_len != response->iv_len ) {
        ESP_LOGE(TAG_SEC_CHAN, "Error decoding IV");
        goto fail;
    }
    memcpy(response->iv, iv_decoded, response->iv_len );

    if (base64_decode_alloc(ciphertext->valuestring,
                            &ciphertext_decoded,
                            &ciphertext_decoded_len) != 0 ||
        ciphertext_decoded_len != response->ciphertext_len) {
        ESP_LOGE(TAG_SEC_CHAN, "Error decoding CipherText");
        goto fail;
    }

    response->ciphertext = malloc((size_t)response->ciphertext_len);
    if (response->ciphertext == NULL) {
        ESP_LOGE(TAG_SEC_CHAN, "Failed to allocate ciphertext");
        goto fail;
    }
    memcpy(response->ciphertext, ciphertext_decoded, ciphertext_decoded_len);

    if (base64_decode_alloc(tag_sc->valuestring,
                            &tag_sc_decoded,
                            &tag_sc_decoded_len) != 0 ||
        tag_sc_decoded_len != response->tag_sc_len ) {
        ESP_LOGE(TAG_SEC_CHAN, "Error decoding Tag SC");
        goto fail;
    }
    memcpy(response->tag_sc, tag_sc_decoded, response->tag_sc_len );

    cJSON_Delete(receive_json_data);
    free(sid_decoded);
    free(iv_decoded);
    free(ciphertext_decoded);
    free(tag_sc_decoded);

    return true;

fail:
    if (receive_json_data != NULL) {
        cJSON_Delete(receive_json_data);
    }

    if (sid_decoded != NULL)
        free(sid_decoded);
    if (iv_decoded != NULL)
        free(iv_decoded);
    if (ciphertext_decoded != NULL)
        free(ciphertext_decoded);
    if (tag_sc_decoded != NULL)
        free(tag_sc_decoded);

    // free_secure_message(response); // pending to free memory from caller
    return false;
}

// bool get_response_plain_data_json(struct secure_message *rsp_sec_msg,
//     struct secure_session *session, struct secure_plain_data *rsp_plain_data)
                          
// {
//     // 0. start the objects
//     struct aes_256_obj *aes = malloc(sizeof(struct aes_256_obj));
//     self->iv_len = AES_CBC_IV_SIZE;
//     esp_fill_random(self->iv, AES_CBC_IV_SIZE);
//     create_aes_256_obj(aes, session->kenc);
//     read_and_update_iv_aes(aes, self->iv);

//     uint8_t *temp_buf;
//     size_t temp_buf_size;


//     //1 . decode b64 the encrypted info
//     uint8_t *cipher_data_decoded;
//     size_t cipher_data_decoded_len;

//     base64_decode_alloc(rsp_sec_msg->ciphertext, &cipher_data_decoded, &cipher_data_decoded_len);

//     //2. decrypt the data
//     aes_cbc_decrypt_pkcs7(aes->key, aes->keybits,
//                           aes->iv,
//                           cipher_data_decoded, cipher_data_decoded_len,
//                           &temp_buf, &temp_buf_size);


//     //3. format the data 
//     int offset = 0;
//     memcpy(rsp_plain_data->version, temp_buf + offset, sizeof(rsp_plain_data->version));
//     offset += sizeof(rsp_plain_data->version);
    
//     memcpy(rsp_plain_data->payload_type, temp_buf + offset, sizeof(rsp_plain_data->payload_type));
//     offset += sizeof(rsp_plain_data->payload_type);
    
//     memcpy(rsp_plain_data->payload_type, temp_buf + offset, sizeof(rsp_plain_data->payload_type));
//     offset += sizeof(rsp_plain_data->payload_type);

//     memcpy(rsp_plain_data->reserved, temp_buf + offset, sizeof(rsp_plain_data->reserved));
//     offset += sizeof(rsp_plain_data->reserved);

//     memcpy(rsp_plain_data->payload_len, temp_buf + offset, sizeof(rsp_plain_data->payload_len));
//     offset += sizeof(rsp_plain_data->payload_len);

//     memcpy(rsp_plain_data->payload_len, temp_buf + offset, rsp_plain_data->payload_len);


//     free(aes);
//     free(temp_buf);
// }


bool get_response_plain_data_json(const struct secure_message *rsp_sec_msg,
                                  const struct secure_session *session,
                                  struct secure_plain_data *rsp_plain_data)
{
    int ret;
    uint8_t *temp_buf = NULL;
    size_t temp_buf_size = 0;
    size_t offset = 0;
    struct aes_256_obj aes;

    if (rsp_sec_msg == NULL || session == NULL || rsp_plain_data == NULL) {
        ESP_LOGE(TAG_SEC_CHAN, "Invalid NULL parameter");
        return false;
    }

    if (rsp_sec_msg->ciphertext == NULL ||
        rsp_sec_msg->ciphertext_len == 0 ||
        rsp_sec_msg->iv_len != AES_CBC_IV_SIZE ||
        rsp_sec_msg->tag_sc_len != HMAC_SHA512_SIZE) {
        ESP_LOGE(TAG_SEC_CHAN, "Invalid secure message");
        return false;
    }



    /*
     * TODO:
     * HMAC verification should be done before this function,
     * or at the beginning of this function.
     */

    create_aes_256_obj(&aes, session->kenc);
    read_and_update_iv_aes(&aes, rsp_sec_msg->iv);

    ret = aes_cbc_decrypt_pkcs7(aes.key,
                                aes.keybits,
                                aes.iv,
                                rsp_sec_msg->ciphertext,
                                (size_t)rsp_sec_msg->ciphertext_len,
                                &temp_buf,
                                &temp_buf_size);

    if (ret != 0) {
        ESP_LOGE(TAG_SEC_CHAN, "AES-CBC decrypt failed: %d", ret);
        return false;
    }

    /*
     * Plaintext format:
     * version      : 1 byte
     * payload_type : 1 byte
     * reserved     : 2 bytes
     * payload_len  : 4 bytes
     * payload      : variable
     */
    if (temp_buf_size < 8) {
        ESP_LOGE(TAG_SEC_CHAN, "Plain data too short");
        free(temp_buf);
        return false;
    }

    rsp_plain_data->version = temp_buf[offset++];
    rsp_plain_data->payload_type = temp_buf[offset++];

    rsp_plain_data->reserved =
        ((uint16_t)temp_buf[offset] << 8) |
        ((uint16_t)temp_buf[offset + 1]);
    offset += 2;

    rsp_plain_data->payload_len =
        ((uint32_t)temp_buf[offset] << 24) |
        ((uint32_t)temp_buf[offset + 1] << 16) |
        ((uint32_t)temp_buf[offset + 2] << 8) |
        ((uint32_t)temp_buf[offset + 3]);
    offset += 4;

    if (rsp_plain_data->payload_len == 0 ||
        offset + rsp_plain_data->payload_len > temp_buf_size) {
        ESP_LOGE(TAG_SEC_CHAN, "Invalid payload length");
        free(temp_buf);
        return false;
    }

    if (rsp_plain_data->payload_type != PAYLOAD_TYPE_JSON) {
        ESP_LOGE(TAG_SEC_CHAN, "Unexpected payload type: %u",
                 rsp_plain_data->payload_type);
        free(temp_buf);
        return false;
    }

    rsp_plain_data->payload = malloc((size_t)rsp_plain_data->payload_len + 1);
    if (rsp_plain_data->payload == NULL) {
        ESP_LOGE(TAG_SEC_CHAN, "Failed to allocate payload");
        free(temp_buf);
        return false;
    }

    memcpy(rsp_plain_data->payload,
           temp_buf + offset,
           (size_t)rsp_plain_data->payload_len);

    /*
     * Optional null terminator for JSON string parsing.
     */
    rsp_plain_data->payload[rsp_plain_data->payload_len] = '\0';

    free(temp_buf);
    return true;
}