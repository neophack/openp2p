#ifndef NAT_C_H
#define NAT_C_H

#ifdef __cplusplus
extern "C" {
#endif

// Returns 0 on success, non-zero on error.
// public_ip_out should be at least 64 bytes.
// msg_data: content to send.
// response_buf: buffer to receive response.
int nat_detect_udp_c(const char* server_host, int server_port, int local_port, 
                     const void* msg_data, int msg_len, 
                     void* response_buf, int response_buf_len, int* bytes_read);

int nat_detect_tcp_c(const char* server_host, int server_port, int local_port,
                     void* response_buf, int response_buf_len, int* bytes_read);

#ifdef __cplusplus
}
#endif

#endif
