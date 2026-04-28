#include <stdlib.h>
#include <string.h>

#include "esp_log.h"
#include "esp_system.h"
#include "mbedtls/md.h"

#include "secure_channel.h"
#include "aes_cbc.h"

bool start_secure_channel_session(struct secure_session *self,
                                  const uint8_t *sid,
                                  size_t sid_len,
                                  const uint8_t *kenc,
                                  const uint8_t *kmac)
{
    if (self == NULL || sid == NULL || sid_len == 0 ||
        kenc == NULL || kmac == NULL) {
        ESP_LOGE(TAG_SEC_CHAN, "Invalid input parameters");
        return false;
    }

    memset(self, 0, sizeof(*self));

    self->sid = malloc(sid_len);
    if (self->sid == NULL) {
        ESP_LOGE(TAG_SEC_CHAN, "Failed to allocate SID buffer");
        return false;
    }

    memcpy(self->sid, sid, sid_len);
    self->sid_len = sid_len;

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

    memset(self, 0, sizeof(*self));

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
}

struct secure_message {
    int step;

    size_t sid_len;
    uint8_t *sid;

    uint32_t seq;

    size_t iv_len;
    uint8_t iv[AES_CBC_IV_SIZE];

    size_t ciphertext_len;
    uint8_t *ciphertext;

    size_t tag_sc_len;
    uint8_t tag_sc[HMAC_SHA512_SIZE];
};

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

    if (!hmac_update_u32_be(&ctx, (uint32_t)self->step)) {
        ESP_LOGE(TAG_SEC_CHAN, "HMAC update STEP failed");
        mbedtls_md_free(&ctx);
        return false;
    }

    if (!hmac_update_u32_be(&ctx, (uint32_t)self->sid_len)) {
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

    if (!hmac_update_u32_be(&ctx, (uint32_t)self->iv_len)) {
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

    if (!hmac_update_u32_be(&ctx, (uint32_t)self->ciphertext_len)) {
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

bool build_secure_message(struct secure_message *self, struct secure_session *session,
    struct secure_plain_data *plain_data)
{
    self->step = STEP_SEC_CHAN;
    self->sid_len = session->sid_len;
    self->sid = malloc(self->sid_len);
    memcpy(self->sid, session->sid, self->sid_len);
    self->seq = session->tx_seq; // remember to increse the tx_seq;
    self->iv_len = AES_CBC_IV_SIZE;
    esp_fill_random(self->iv, self->iv_len);

    struct aes_256_obj *aes = malloc(sizeof(struct aes_256_obj));
    create_aes_256_obj(aes, session->kenc);
    read_and_update_iv_aes(aes, self->iv); //use the current IV

    size_t temp_buff_size = sizeof(struct secure_plain_data) + plain_data->payload_len;
    uint8_t *temp_buff = malloc(temp_buff_size);
    int offset = 0;
    // add version
    memcpy(temp_buff + offset, plain_data->version, sizeof(plain_data->version));
    offset += sizeof(plain_data->version);
    //add payload_tyoe
    memcpy(temp_buff + offset, plain_data->payload_type, sizeof(plain_data->payload_type));
    offset += sizeof(plain_data->payload_type);
    // add reserved
    memcpy(temp_buff + offset, plain_data->reserved, sizeof(plain_data->reserved));
    offset += sizeof(plain_data->reserved);
    // add payload len
    memcpy(temp_buff + offset, plain_data->payload_len, sizeof(plain_data->payload_len));
    offset += sizeof(plain_data->reserved);
    // add the payload
    memcpy(temp_buff + offset, plain_data->payload, plain_data->payload_len);

    aes_cbc_encrypt_pkcs7(aes->key, aes->keybits, aes->iv, temp_buff, temp_buff_size,
    &self->ciphertext, self->ciphertext_len);

    self->tag_sc_len = HMAC_SHA512_SIZE;
    

    // calculate tagS

    free(temp_buff);
    free(aes);

}