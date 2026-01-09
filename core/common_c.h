#ifndef COMMON_C_H
#define COMMON_C_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int pkcs7_padding_c(uint8_t* data, int data_len, int block_size);
int pkcs7_unpadding_c(const uint8_t* data, int data_len);
uint16_t calculate_checksum_c(const uint8_t* data, int len);
int compare_version_c(const char* v1, const char* v2);
uint64_t crc64_iso_c(const uint8_t* data, size_t len);
int aes_cbc_encrypt_c(const uint8_t* key, const uint8_t* iv, uint8_t* out, const uint8_t* in, int len);
int aes_cbc_decrypt_c(const uint8_t* key, const uint8_t* iv, uint8_t* out, const uint8_t* in, int len, int* outLen);

#ifdef __cplusplus
}
#endif

#endif
