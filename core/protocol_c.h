#ifndef PROTOCOL_C_H
#define PROTOCOL_C_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t data_len;
    uint16_t main_type;
    uint16_t sub_type;
} openp2p_header_t;

void encode_header_c(uint16_t main_type, uint16_t sub_type, uint32_t len, uint8_t* out);
void decode_header_c(const uint8_t* in, openp2p_header_t* head);

#ifdef __cplusplus
}
#endif

#endif
