#ifndef SECURE_CHANNEL_H
#define SECURE_CHANNEL_H

#include <stddef.h>
#include <stdint.h>

#define TAG_SEC_CHAN "[SECURE CHANNEL]"

#define AES_CBC_IV_SIZE      16
#define HMAC_SHA512_SIZE     64
#define SEC_CHAN_VERSION      1
#define KEY_SEC_CHAN_SIZE    32
#define STEP_SEC_CHAN 3

struct secure_message {
    uint32_t step;

    size_t sid_len;
    uint8_t *sid;

    uint32_t seq; // define maximun and minimun. 
    // start in 0 each session. 

    size_t iv_len;
    uint8_t iv[AES_CBC_IV_SIZE];

    size_t ciphertext_len;
    uint8_t *ciphertext;

    size_t tag_sc_len;
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

#endif