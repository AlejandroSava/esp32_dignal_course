#ifndef SECURE_CHANNEL_H
#define SECURE_CHANNEL_H

#include <stddef.h>
#include <stdint.h>
#include "secure_channel.h"

#define TAG_SEC_CHAN "[SECURE CHANNEL]"

#define AES_CBC_IV_SIZE      16
#define HMAC_SHA512_SIZE     64
#define SEC_CHAN_VERSION      1
#define KEY_SEC_CHAN_SIZE    32
#define STEP_SEC_CHAN 3
#define MAX_SEQ 70
#define MIN_SEQ 0

struct secure_message {
    uint32_t step;

    uint32_t sid_len;
    uint8_t *sid;

    uint32_t seq; // define maximun and minimun. 
    // start in 0 each session. 

    uint32_t iv_len;
    uint8_t iv[AES_CBC_IV_SIZE];

    uint32_t ciphertext_len;
    uint8_t *ciphertext;

    uint32_t tag_sc_len;
    uint8_t tag_sc[HMAC_SHA512_SIZE];
};

enum secure_payload_type {
    PAYLOAD_TYPE_JSON      = 1,
    PAYLOAD_TYPE_STRING    = 2,
    PAYLOAD_TYPE_BOOL      = 3,
    PAYLOAD_TYPE_FLOAT     = 4,
    PAYLOAD_TYPE_UINT8     = 5,
    PAYLOAD_TYPE_UINT16    = 6,
    PAYLOAD_TYPE_UINT32    = 7,
    PAYLOAD_TYPE_INT32     = 8,
    PAYLOAD_TYPE_BINARY    = 9,
};

struct secure_plain_data {
    uint8_t version;
    uint8_t payload_type;
    uint16_t reserved;

    uint32_t payload_len;
    uint8_t *payload;
};

struct secure_session {
    size_t sid_len;
    uint8_t *sid;

    uint32_t tx_seq;
    uint32_t rx_seq;

    uint8_t kenc[KEY_SEC_CHAN_SIZE];
    uint8_t kmac[KEY_SEC_CHAN_SIZE];
};

bool start_secure_channel_session(struct secure_session *self,
                                  const uint8_t *sid,
                                  size_t sid_len,
                                  const uint8_t *kenc,
                                  const uint8_t *kmac);

void free_secure_channel_session(struct secure_session *self);

bool build_secure_plain_data_float(struct secure_plain_data *self,
                                   const uint8_t *payload,
                                   uint32_t payload_len);

void free_secure_plain_data(struct secure_plain_data *self);

bool build_secure_message(struct secure_message *self,
                          struct secure_session *session,
                          const struct secure_plain_data *plain_data);

void free_secure_message(struct secure_message *self);
bool send_secure_channel_message(const struct secure_message *message,
                                 char **json_response_output,
                                 size_t *response_length,
                                 const char *http_address);

bool get_secure_channel_response(struct secure_message *response,
                                 const char *json_response_output);
#endif