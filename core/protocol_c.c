#include "protocol_c.h"
#include <string.h>

void encode_header_c(uint16_t main_type, uint16_t sub_type, uint32_t len, uint8_t* out) {
    // Little endian
    out[0] = (uint8_t)(len & 0xFF);
    out[1] = (uint8_t)((len >> 8) & 0xFF);
    out[2] = (uint8_t)((len >> 16) & 0xFF);
    out[3] = (uint8_t)((len >> 24) & 0xFF);
    
    out[4] = (uint8_t)(main_type & 0xFF);
    out[5] = (uint8_t)((main_type >> 8) & 0xFF);
    
    out[6] = (uint8_t)(sub_type & 0xFF);
    out[7] = (uint8_t)((sub_type >> 8) & 0xFF);
}

void decode_header_c(const uint8_t* in, openp2p_header_t* head) {
    head->data_len = (uint32_t)in[0] | ((uint32_t)in[1] << 8) | ((uint32_t)in[2] << 16) | ((uint32_t)in[3] << 24);
    head->main_type = (uint16_t)in[4] | ((uint16_t)in[5] << 8);
    head->sub_type = (uint16_t)in[6] | ((uint16_t)in[7] << 8);
}

void encode_push_header_c(uint64_t from, uint64_t to, uint8_t* out) {
    memcpy(out, &from, 8);
    memcpy(out + 8, &to, 8);
}

void decode_push_header_c(const uint8_t* in, push_header_t* head) {
    memcpy(&head->from, in, 8);
    memcpy(&head->to, in + 8, 8);
}

void encode_overlay_header_c(uint64_t id, uint8_t* out) {
    memcpy(out, &id, 8);
}

void decode_overlay_header_c(const uint8_t* in, overlay_header_t* head) {
    memcpy(&head->id, in, 8);
}
