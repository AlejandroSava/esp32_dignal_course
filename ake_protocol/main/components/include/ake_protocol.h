#ifndef AKE_PROTOCOL_H
#define AKE_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "api_secure_storage.h"

#define TAG_AKE "[AKE PROTOCOL]"

struct request_step_0{
    int step;
    const char *device_name; 
    size_t mac_address_size;
    uint8_t *mac_address;
    size_t puf_hash_size;
    uint8_t *puf_hash;

    /* base 64 params*/
    char *mac_address_b64;
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
};

struct response_step_1{
    int step;
    char *server_name; 
    size_t sid_len;
    uint8_t *sid;
    size_t nonce_s_len;
    uint8_t * nonce_s;
};

struct kyber_object_node {
    uint8_t *pk;
    size_t pk_len;
    uint8_t *ct;
    size_t ct_len;
    uint8_t *ss;
    size_t ss_len;
};

bool build_request_0(struct request_step_0 *self, const char *device_name, struct puf_object *puf);
void free_request_step_0(struct request_step_0 *self);
bool send_http_request_0(struct request_step_0 *self, char **json_response_output,
                         size_t *response_length, const char *http_address);
bool get_response_0(struct response_step_0 *self, char *json_response_output);
void free_response_step_0(struct response_step_0 *self);
bool build_request_1(struct request_step_1 *self, const char *device_name);
bool send_http_request_1(struct request_step_1 *self, char **json_response_output,
                         size_t *json_response_length, const char *http_address);
bool get_response_1(struct response_step_1 *self, char *json_response_output);
void free_response_step_1(struct response_step_1 *self);
#endif