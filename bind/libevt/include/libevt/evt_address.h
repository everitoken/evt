/**
 *  @file
 *  @copyright defined in evt/LICENSE.txt
 */
#pragma once
#include "evt.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef evt_data_t evt_public_key_t;
typedef evt_data_t evt_address_t;
typedef evt_data_t evt_name_t;
typedef evt_data_t evt_name128_t;

int evt_address_from_string(const char* str, evt_address_t** addr /* out */);
int evt_address_to_string(evt_address_t* addr, char** str /* out */);
int evt_address_public_key(evt_public_key_t *pub_key, evt_address_t** addr/* out */);
int evt_address_reserved(evt_address_t** addr/* out */);
int evt_address_generated(evt_name_t* prefix, evt_name128_t key, uint32_t nonce, evt_address_t** addr/* out */);

#ifdef __cplusplus
} // extern "C"
#endif
