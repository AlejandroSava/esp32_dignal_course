#ifndef AKE_PROTOCOL_H
#define AKE_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "api_secure_storage.h"

#define TAG_AKE "[AKE PROTOCOL]"
#define SHA512_DIGEST_SIZE 64 //bytes 
#define KEY_SIZE 32 //bytes
#define NONCE_SIZE 32 //bytes

struct request_step_0{
    int step;
    const char *device_name; 
    size_t device_mac_size;
    uint8_t *device_mac;
    size_t puf_hash_size;
    uint8_t *puf_hash;

    /* base 64 params*/
    char *device_mac_b64;
    char *puf_hash_b64;

};

struct response_step_0{
    int step;
    char *server_name; // TODO: where is used it? 
    size_t kyber_pk_len;
    uint8_t *kyber_pk;  
};

struct request_step_1{
    int step;
    const char *device_name;
    size_t device_mac_size; 
    uint8_t *device_mac;

    /* base 64 params*/
    char *device_mac_b64;
};

struct response_step_1{
    int step;
    char *server_name; 
    size_t sid_len;
    uint8_t *sid;
    size_t nonce_s_len;
    uint8_t *nonce_s;
};

struct request_step_2{
    int step;
    size_t sid_len;
    uint8_t *sid;
    size_t nonce_d_len;
    uint8_t *nonce_d;
    size_t ct_kyber_len;
    uint8_t *ct_kyber;
    size_t tag_d_len;
    uint8_t *tag_d;
    
    // base 64
    char *sid_b64;
    char *nonce_d_b64;
    char *ct_kyber_b64;
    char *tag_d_b64;
};

struct response_step_2{
    int step;
    size_t sid_len;
    uint8_t *sid;
    size_t tag_s_len;
    uint8_t *tag_s;
    
};

struct kyber_object_node {
    uint8_t *pk;
    size_t pk_len;
    uint8_t *ct;
    size_t ct_len;
    uint8_t *ss;
    size_t ss_len;
};

struct ake_key{
    uint8_t *key;
    size_t key_size;
    bool ready; 
    char *key_info;
    size_t key_info_len;
};

struct master_key{
    /*context = SID || nonce_s || nonce_d
    Kmaster = HKDF-SHA512( PUF_hash || SS, salt = context, info = "AKE master")*/
    size_t key_len;
    uint8_t *key;
    size_t context_len;
    uint8_t *context;

};

bool build_request_0(struct request_step_0 *self, const char *device_name, struct puf_object *puf);
void free_request_step_0(struct request_step_0 *self);
bool send_http_request_0(struct request_step_0 *self, char **json_response_output,
                         size_t *response_length, const char *http_address);
bool get_response_0(struct response_step_0 *self, char *json_response_output);
void free_response_step_0(struct response_step_0 *self);

bool build_request_1(struct request_step_1 *self, const char *device_name);
void free_request_step_1(struct request_step_1 *self);
bool send_http_request_1(struct request_step_1 *self, char **json_response_output,
                         size_t *json_response_length, const char *http_address);
bool get_response_1(struct response_step_1 *self, char *json_response_output);
void free_response_step_1(struct response_step_1 *self);

void free_kyber_object_node(struct kyber_object_node *self);
bool get_kyber_object_node(struct kyber_object_node *self,
                           struct aes_256_obj *aes_key_ss);

bool build_request_2(struct request_step_2 *self,
                     const struct response_step_1 *res_step_1,
                     const struct kyber_object_node *kyber_obj,
                     struct master_key *master_key,
                     struct ake_key *key_sess,
                     struct ake_key *key_auth,
                     const struct puf_object *puf_obj,
                     const char *device_name);
void free_request_2(struct request_step_2 *self);
void free_ake_key(struct ake_key *key);
bool send_http_request_2(struct request_step_2 *self,
                         char **json_response_output,
                         size_t *json_response_length,
                         const char *http_address);
void free_response_step_2(struct response_step_2 *self);
bool get_response_2(struct response_step_2 *self, char *json_response_output);
bool verify_tag_s(const uint8_t *expected_tag_s,
                  size_t expected_tag_s_size,
                  const struct ake_key *ksess,
                  const uint8_t *sid,
                  size_t sid_len,
                  const uint8_t *nonce_s,
                  size_t nonce_s_len,
                  const uint8_t *nonce_d,
                  size_t nonce_d_len);
bool get_context_master_key(struct master_key *self, // opaque this function
                 size_t sid_len, const uint8_t *sid,
                 size_t nonce_s_len, const uint8_t *nonce_s,
                 size_t nonce_d_len, const uint8_t *nonce_d);
bool derive_master_key(struct master_key *self, // opaque this function
                       const uint8_t *puf_hash, size_t puf_hash_size,
                       const uint8_t *ss, size_t ss_len);
void free_master_key(struct master_key *self);

#endif