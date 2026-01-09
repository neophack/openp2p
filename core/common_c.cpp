#include "common_c.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <math.h>
#include <time.h>

int pkcs7_padding_c(uint8_t* data, int data_len, int block_size) {
    int pad_len = block_size - (data_len % block_size);
    for (int i = 0; i < pad_len; i++) {
        data[data_len + i] = (uint8_t)pad_len;
    }
    return pad_len;
}

int pkcs7_unpadding_c(const uint8_t* data, int data_len) {
    if (data_len == 0) return 0;
    uint8_t pad_len = data[data_len - 1];
    if (pad_len <= 0 || pad_len > 16) return -1;
    return (int)pad_len;
}

uint16_t calculate_checksum_c(const uint8_t* data, int len) {
    uint32_t sum = 0;
    for (int i = 0; i < len - 1; i += 2) {
        sum += (uint32_t)((data[i] << 8) | data[i + 1]);
    }
    if (len % 2 != 0) {
        sum += (uint32_t)data[len - 1];
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (uint16_t)(~sum);
}

int compare_version_c(const char* v1, const char* v2) {
    if (strcmp(v1, v2) == 0) return 0;
    
    char buf1[64], buf2[64];
    strncpy(buf1, v1, 63); buf1[63] = 0;
    strncpy(buf2, v2, 63); buf2[63] = 0;
    
    char* s1 = buf1;
    char* s2 = buf2;
    
    while (s1 || s2) {
        int n1 = 0, n2 = 0;
        if (s1) {
            char* dot = strchr(s1, '.');
            if (dot) *dot = 0;
            n1 = atoi(s1);
            s1 = dot ? dot + 1 : NULL;
        }
        if (s2) {
            char* dot = strchr(s2, '.');
            if (dot) *dot = 0;
            n2 = atoi(s2);
            s2 = dot ? dot + 1 : NULL;
        }
        if (n1 > n2) return 1;
        if (n1 < n2) return -1;
    }
    return 0;
}

double calc_retry_time_relay_c(double x) {
    return 10 + exp(0.8 * (x - 3.6));
}

double calc_retry_time_direct_c(double x) {
    return 10 + exp(2.8 * (x - 4));
}

void rand_str_c(char* out, int n) {
    const char* letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890-";
    int len = strlen(letters);
    for (int i = 0; i < n; i++) {
        out[i] = letters[rand() % len];
    }
    out[n] = '\0';
}

void sanitize_file_name_c(char* out, const char* in) {
    const char* invalid_chars = "\\/:*?\"<>|";
    int len = strlen(in);
    for (int i = 0; i < len; i++) {
        if (strchr(invalid_chars, in[i])) {
            out[i] = ' ';
        } else {
            out[i] = in[i];
        }
    }
    out[len] = '\0';
}

int32_t min_c(const int32_t* nums, int count) {
    if (count <= 0) return 0;
    int32_t min_val = nums[0];
    for (int i = 1; i < count; i++) {
        if (nums[i] < min_val) {
            min_val = nums[i];
        }
    }
    return min_val;
}

uint64_t app_config_id_c(int src_port, const char* protocol, const char* peer_node) {
    if (src_port == 0) {
        return crc64_iso_c((const uint8_t*)peer_node, strlen(peer_node));
    }
    if (strcmp(protocol, "tcp") == 0) {
        return (uint64_t)src_port * 10;
    }
    return (uint64_t)src_port * 10 + 1;
}

void app_config_log_peer_node_c(char* out, const char* relay_mode, const char* peer_node) {
    if (strcmp(relay_mode, "public") == 0) {
        sprintf(out, "%llu", (unsigned long long)crc64_iso_c((const uint8_t*)peer_node, strlen(peer_node)));
    } else {
        strcpy(out, peer_node);
    }
}

uint32_t inet_aton_c(const char* ipstr) {
    // simple implementation for IPv4
    int a, b, c, d;
    if (sscanf(ipstr, "%d.%d.%d.%d", &a, &b, &c, &d) == 4) {
        return (uint32_t)((a << 24) | (b << 16) | (c << 8) | d);
    }
    return 0;
}

int32_t calc_rtt_c(int32_t pre_rtt, int32_t current_rtt) {
    if (pre_rtt == 1000) { // DefaultRtt
        return current_rtt;
    }
    return (int32_t)(pre_rtt * (1.0 - 1.0 / 20.0) + current_rtt * (1.0 / 20.0));
}

int64_t moving_average_c(int64_t pre_val, int64_t current_val, double factor) {
    return (int64_t)(pre_val * (1.0 - factor) + current_val * factor);
}

int is_ipv6_c(const char* ipstr) {
    if (!ipstr) return 0;
    return (strchr(ipstr, ':') != NULL && strchr(ipstr, '.') == NULL) ? 1 : 0;
}

int is_localhost_c(const char* ipstr) {
    if (!ipstr) return 0;
    if (strcmp(ipstr, "localhost") == 0 || strcmp(ipstr, "127.0.0.1") == 0 || strcmp(ipstr, "::1") == 0) {
        return 1;
    }
    return 0;
}

int parse_major_ver_c(const char* ver) {
    if (!ver) return 0;
    int major = 0;
    if (sscanf(ver, "%d", &major) == 1) {
        return major;
    }
    return 0;
}

uint64_t crc64_iso_c(const uint8_t* data, size_t len) {
    if (!data || len == 0) return 0;

    static uint64_t table[256];
    static int initialized = 0;

    if (!initialized) {
        const uint64_t poly = 0xD800000000000000ULL;  // Go crc64.ISO (reflected)
        for (int i = 0; i < 256; i++) {
            uint64_t crc = (uint64_t)i;
            for (int j = 0; j < 8; j++) {
                if (crc & 1ULL) {
                    crc = (crc >> 1) ^ poly;
                } else {
                    crc >>= 1;
                }
            }
            table[i] = crc;
        }
        initialized = 1;
    }

    uint64_t crc = 0xFFFFFFFFFFFFFFFFULL;

    for (size_t i = 0; i < len; i++) {
        uint8_t idx = (uint8_t)(crc ^ data[i]);
        crc = table[idx] ^ (crc >> 8);
    }

    return crc ^ 0xFFFFFFFFFFFFFFFFULL;
}


// AES-128 constants
#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE 16
#define AES_ROUNDS 10

// AES S-box
static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// AES inverse S-box
static const uint8_t inv_sbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

// Rcon values for key expansion
static const uint8_t Rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

class AES128 {
private:
    uint8_t round_key[176]; // 11 round keys * 16 bytes

    void KeyExpansion(const uint8_t* key) {
        memcpy(round_key, key, AES_KEY_SIZE);
        
        for (int i = AES_KEY_SIZE; i < 176; i += 4) {
            uint8_t temp[4];
            memcpy(temp, &round_key[i - 4], 4);
            
            if (i % AES_KEY_SIZE == 0) {
                // RotWord
                uint8_t k = temp[0];
                temp[0] = temp[1];
                temp[1] = temp[2];
                temp[2] = temp[3];
                temp[3] = k;
                
                // SubWord
                temp[0] = sbox[temp[0]];
                temp[1] = sbox[temp[1]];
                temp[2] = sbox[temp[2]];
                temp[3] = sbox[temp[3]];
                
                temp[0] ^= Rcon[i / AES_KEY_SIZE];
            }
            
            round_key[i] = round_key[i - AES_KEY_SIZE] ^ temp[0];
            round_key[i + 1] = round_key[i + 1 - AES_KEY_SIZE] ^ temp[1];
            round_key[i + 2] = round_key[i + 2 - AES_KEY_SIZE] ^ temp[2];
            round_key[i + 3] = round_key[i + 3 - AES_KEY_SIZE] ^ temp[3];
        }
    }

    void AddRoundKey(uint8_t* state, int round) {
        for (int i = 0; i < 16; i++) {
            state[i] ^= round_key[round * 16 + i];
        }
    }

    void SubBytes(uint8_t* state) {
        for (int i = 0; i < 16; i++) {
            state[i] = sbox[state[i]];
        }
    }

    void InvSubBytes(uint8_t* state) {
        for (int i = 0; i < 16; i++) {
            state[i] = inv_sbox[state[i]];
        }
    }

    void ShiftRows(uint8_t* state) {
        uint8_t temp;
        
        // Row 1: shift left by 1
        temp = state[1];
        state[1] = state[5];
        state[5] = state[9];
        state[9] = state[13];
        state[13] = temp;
        
        // Row 2: shift left by 2
        temp = state[2];
        state[2] = state[10];
        state[10] = temp;
        temp = state[6];
        state[6] = state[14];
        state[14] = temp;
        
        // Row 3: shift left by 3
        temp = state[15];
        state[15] = state[11];
        state[11] = state[7];
        state[7] = state[3];
        state[3] = temp;
    }

    void InvShiftRows(uint8_t* state) {
        uint8_t temp;
        
        // Row 1: shift right by 1
        temp = state[13];
        state[13] = state[9];
        state[9] = state[5];
        state[5] = state[1];
        state[1] = temp;
        
        // Row 2: shift right by 2
        temp = state[2];
        state[2] = state[10];
        state[10] = temp;
        temp = state[6];
        state[6] = state[14];
        state[14] = temp;
        
        // Row 3: shift right by 3
        temp = state[3];
        state[3] = state[7];
        state[7] = state[11];
        state[11] = state[15];
        state[15] = temp;
    }

    uint8_t xtime(uint8_t x) {
        return ((x << 1) ^ (((x >> 7) & 1) * 0x1b));
    }

    void MixColumns(uint8_t* state) {
        uint8_t temp[4];
        for (int i = 0; i < 4; i++) {
            temp[0] = state[i * 4];
            temp[1] = state[i * 4 + 1];
            temp[2] = state[i * 4 + 2];
            temp[3] = state[i * 4 + 3];
            
            state[i * 4] = xtime(temp[0]) ^ xtime(temp[1]) ^ temp[1] ^ temp[2] ^ temp[3];
            state[i * 4 + 1] = temp[0] ^ xtime(temp[1]) ^ xtime(temp[2]) ^ temp[2] ^ temp[3];
            state[i * 4 + 2] = temp[0] ^ temp[1] ^ xtime(temp[2]) ^ xtime(temp[3]) ^ temp[3];
            state[i * 4 + 3] = xtime(temp[0]) ^ temp[0] ^ temp[1] ^ temp[2] ^ xtime(temp[3]);
        }
    }

    uint8_t Multiply(uint8_t x, uint8_t y) {
        return (((y & 1) * x) ^
                ((y >> 1 & 1) * xtime(x)) ^
                ((y >> 2 & 1) * xtime(xtime(x))) ^
                ((y >> 3 & 1) * xtime(xtime(xtime(x)))) ^
                ((y >> 4 & 1) * xtime(xtime(xtime(xtime(x))))));
    }

    void InvMixColumns(uint8_t* state) {
        uint8_t temp[4];
        for (int i = 0; i < 4; i++) {
            temp[0] = state[i * 4];
            temp[1] = state[i * 4 + 1];
            temp[2] = state[i * 4 + 2];
            temp[3] = state[i * 4 + 3];
            
            state[i * 4] = Multiply(temp[0], 0x0e) ^ Multiply(temp[1], 0x0b) ^ 
                          Multiply(temp[2], 0x0d) ^ Multiply(temp[3], 0x09);
            state[i * 4 + 1] = Multiply(temp[0], 0x09) ^ Multiply(temp[1], 0x0e) ^ 
                              Multiply(temp[2], 0x0b) ^ Multiply(temp[3], 0x0d);
            state[i * 4 + 2] = Multiply(temp[0], 0x0d) ^ Multiply(temp[1], 0x09) ^ 
                              Multiply(temp[2], 0x0e) ^ Multiply(temp[3], 0x0b);
            state[i * 4 + 3] = Multiply(temp[0], 0x0b) ^ Multiply(temp[1], 0x0d) ^ 
                              Multiply(temp[2], 0x09) ^ Multiply(temp[3], 0x0e);
        }
    }

public:
    AES128(const uint8_t* key) {
        KeyExpansion(key);
    }

    void EncryptBlock(uint8_t* output, const uint8_t* input) {
        memcpy(output, input, AES_BLOCK_SIZE);
        
        AddRoundKey(output, 0);
        
        for (int round = 1; round < AES_ROUNDS; round++) {
            SubBytes(output);
            ShiftRows(output);
            MixColumns(output);
            AddRoundKey(output, round);
        }
        
        SubBytes(output);
        ShiftRows(output);
        AddRoundKey(output, AES_ROUNDS);
    }

    void DecryptBlock(uint8_t* output, const uint8_t* input) {
        memcpy(output, input, AES_BLOCK_SIZE);
        
        AddRoundKey(output, AES_ROUNDS);
        
        for (int round = AES_ROUNDS - 1; round > 0; round--) {
            InvShiftRows(output);
            InvSubBytes(output);
            AddRoundKey(output, round);
            InvMixColumns(output);
        }
        
        InvShiftRows(output);
        InvSubBytes(output);
        AddRoundKey(output, 0);
    }
};

// AES-CBC Encrypt
int aes_cbc_encrypt_c(const uint8_t* key, const uint8_t* iv, uint8_t* out, const uint8_t* in, int len) {
    if (key == nullptr || key[0] == 0) {
        memcpy(out, in, len);
        return len;
    }
    
    AES128 aes(key);
    
    uint8_t current_iv[AES_BLOCK_SIZE];
    memcpy(current_iv, iv, AES_BLOCK_SIZE);
    
    for (int i = 0; i < len; i += AES_BLOCK_SIZE) {
        uint8_t block[AES_BLOCK_SIZE];
        memcpy(block, in + i, AES_BLOCK_SIZE);
        
        // XOR with IV
        for (int j = 0; j < AES_BLOCK_SIZE; j++) {
            block[j] ^= current_iv[j];
        }
        
        // Encrypt block
        aes.EncryptBlock(out + i, block);
        
        // Update IV to current ciphertext
        memcpy(current_iv, out + i, AES_BLOCK_SIZE);
    }
    
    return len;
}

// AES-CBC Decrypt
int aes_cbc_decrypt_c(const uint8_t* key, const uint8_t* iv, uint8_t* out, const uint8_t* in, int len, int* outLen) {
    if (key == nullptr || key[0] == 0) {
        memcpy(out, in, len);
        if (outLen) *outLen = len;
        return 0;
    }
    
    AES128 aes(key);
    
    uint8_t current_iv[AES_BLOCK_SIZE];
    memcpy(current_iv, iv, AES_BLOCK_SIZE);
    
    for (int i = 0; i < len; i += AES_BLOCK_SIZE) {
        uint8_t next_iv[AES_BLOCK_SIZE];
        memcpy(next_iv, in + i, AES_BLOCK_SIZE);
        
        // Decrypt block
        aes.DecryptBlock(out + i, in + i);
        
        // XOR with IV
        for (int j = 0; j < AES_BLOCK_SIZE; j++) {
            out[i + j] ^= current_iv[j];
        }
        
        // Update IV
        memcpy(current_iv, next_iv, AES_BLOCK_SIZE);
    }
    
    int pad_len = pkcs7_unpadding_c(out, len);
    if (pad_len < 0) {
        if (outLen) *outLen = 0;
        return -1;
    }
    if (outLen) *outLen = len - pad_len;
    
    return 0;
}