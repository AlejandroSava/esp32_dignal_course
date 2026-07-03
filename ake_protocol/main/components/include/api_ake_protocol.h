#ifndef API_AKE_PROTOCOL_H
#define API_AKE_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "secure_storage_nvs.h"
#include "api_secure_storage.h"
#include "secure_channel.h"
#include "ake_protocol.h"

#define TAG_API_AKE "[API AKE PROTOCOL]"

bool root_of_trust_process(const char *http_post, struct device_info *device_info,
                           struct aes_256_obj *aes_key_ss, struct aes_256_obj *hmac_key_ss );

bool ake_flow(const char *http_post,
              struct device_info *device_info,
              struct aes_256_obj *aes_key_ss,
              struct aes_256_obj *hmac_key_ss,
              struct secure_session *session);

bool send_float_secure_channel(const char *http_post,
                               struct secure_session *session,
                               struct secure_plain_data *rsp_plain_data,
                               float data);
#endif
