#ifndef PROTOCOL_C_H
#define PROTOCOL_C_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OPENP2P_HEADER_SIZE 8

// Message main type
#define MSG_LOGIN     0
#define MSG_HEARTBEAT 1
#define MSG_NAT_DETECT 2
#define MSG_PUSH      3
#define MSG_P2P       4
#define MSG_RELAY     5
#define MSG_REPORT    6
#define MSG_QUERY     7
#define MSG_SDWAN     8

// MsgPush sub type message
#define MSG_PUSH_RSP                  0
#define MSG_PUSH_CONNECT_REQ           1
#define MSG_PUSH_CONNECT_RSP           2
#define MSG_PUSH_HANDSHAKE_START       3
#define MSG_PUSH_ADD_RELAY_TUNNEL_REQ    4
#define MSG_PUSH_ADD_RELAY_TUNNEL_RSP    5
#define MSG_PUSH_UPDATE               6
#define MSG_PUSH_REPORT_APPS           7
#define MSG_PUSH_UNDERLAY_CONNECT      8
#define MSG_PUSH_EDIT_APP              9
#define MSG_PUSH_SWITCH_APP            10
#define MSG_PUSH_RESTART              11
#define MSG_PUSH_EDIT_NODE             12
#define MSG_PUSH_APP_KEY               13
#define MSG_PUSH_REPORT_LOG            14
#define MSG_PUSH_DST_NODE_ONLINE        15
#define MSG_PUSH_REPORT_GOROUTINE      16
#define MSG_PUSH_REPORT_MEM_APPS        17
#define MSG_PUSH_SERVER_SIDE_SAVE_MEM_APP 18
#define MSG_PUSH_CHECK_REMOTE_SERVICE   19
#define MSG_PUSH_SPEC_TUNNEL           20
#define MSG_PUSH_REPORT_HEAP           21
#define MSG_PUSH_SDWAN_REFRESH         22
#define MSG_PUSH_NAT4_DETECT           23

// MsgP2P sub type message
#define MSG_PUNCH_HANDSHAKE 0
#define MSG_PUNCH_HANDSHAKE_ACK 1
#define MSG_TUNNEL_HANDSHAKE 2
#define MSG_TUNNEL_HANDSHAKE_ACK 3
#define MSG_TUNNEL_HEARTBEAT 4
#define MSG_TUNNEL_HEARTBEAT_ACK 5
#define MSG_OVERLAY_CONNECT_REQ 6
#define MSG_OVERLAY_CONNECT_RSP 7
#define MSG_OVERLAY_DISCONNECT_REQ 8
#define MSG_OVERLAY_DATA 9
#define MSG_RELAY_DATA 10
#define MSG_RELAY_HEARTBEAT 11
#define MSG_RELAY_HEARTBEAT_ACK 12
#define MSG_NODE_DATA 13
#define MSG_RELAY_NODE_DATA 14
#define MSG_NODE_DATA_MP 15
#define MSG_NODE_DATA_MP_ACK 16
#define MSG_RELAY_HEARTBEAT_ACK2 17

// MsgRelay sub type message
#define MSG_RELAY_NODE_REQ 0
#define MSG_RELAY_NODE_RSP 1

// MsgReport sub type message
#define MSG_REPORT_BASIC 0
#define MSG_REPORT_QUERY 1
#define MSG_REPORT_CONNECT 2
#define MSG_REPORT_APPS 3
#define MSG_REPORT_LOG 4
#define MSG_REPORT_MEM_APPS 5
#define MSG_REPORT_RESPONSE 6

// NAT type
#define NAT_NONE      0
#define NAT_CONE      1
#define NAT_SYMMETRIC 2
#define NAT_UNKNOWN   314

// MsgQuery sub type message
#define MSG_QUERY_PEER_INFO_REQ 0
#define MSG_QUERY_PEER_INFO_RSP 1

// MsgSDWAN sub type message
#define MSG_SDWAN_INFO_REQ 0
#define MSG_SDWAN_INFO_RSP 1

// MsgNATDetect sub type message
#define MSG_NAT 0
#define MSG_PUBLIC_IP 1

typedef struct {
    uint32_t data_len;
    uint16_t main_type;
    uint16_t sub_type;
} openp2p_header_t;

typedef struct {
    uint64_t from;
    uint64_t to;
} push_header_t;

typedef struct {
    uint64_t id;
} overlay_header_t;

void encode_header_c(uint16_t main_type, uint16_t sub_type, uint32_t len, uint8_t* out);
void decode_header_c(const uint8_t* in, openp2p_header_t* head);
void encode_push_header_c(uint64_t from, uint64_t to, uint8_t* out);
void decode_push_header_c(const uint8_t* in, push_header_t* head);
void encode_overlay_header_c(uint64_t id, uint8_t* out);
void decode_overlay_header_c(const uint8_t* in, overlay_header_t* head);

#ifdef __cplusplus
}
#endif

#endif
