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
double calc_retry_time_relay_c(double x);
double calc_retry_time_direct_c(double x);
void rand_str_c(char* out, int n);
void sanitize_file_name_c(char* out, const char* in);
int32_t min_c(const int32_t* nums, int count);
uint64_t app_config_id_c(int src_port, const char* protocol, const char* peer_node);
void app_config_log_peer_node_c(char* out, const char* relay_mode, const char* peer_node);
uint32_t inet_aton_c(const char* ipstr);
int32_t calc_rtt_c(int32_t pre_rtt, int32_t current_rtt);
int64_t moving_average_c(int64_t pre_val, int64_t current_val, double factor);
#ifdef __cplusplus
}
#endif

#endif
