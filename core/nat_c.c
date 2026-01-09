#include "nat_c.h"
#include "protocol_c.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
//#pragma comment(lib, "ws2_32.lib") // Handled by CGO LDFLAGS
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/select.h>
#define SOCKET int
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#define closesocket close
#endif

int nat_detect_udp_c(const char* server_host, int server_port, int local_port, 
                     const void* msg_data, int msg_len, 
                     void* response_buf, int response_buf_len, int* bytes_read) {
    
    #ifdef _WIN32
    WSADATA wsaData;
    int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        return 1; // WSAStartup failed
    }
    #endif

    SOCKET sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sockfd == INVALID_SOCKET) {
        #ifdef _WIN32
        WSACleanup();
        #endif
        return 2; // socket failed
    }

    // Bind to local port
    struct sockaddr_in cli_addr;
    memset(&cli_addr, 0, sizeof(cli_addr));
    cli_addr.sin_family = AF_INET;
    cli_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    cli_addr.sin_port = htons((unsigned short)local_port);

    if (bind(sockfd, (struct sockaddr*)&cli_addr, sizeof(cli_addr)) == SOCKET_ERROR) {
        closesocket(sockfd);
        #ifdef _WIN32
        WSACleanup();
        #endif
        return 3; // bind failed
    }

    // Resolve server host
    char port_str[6];
#ifdef _WIN32
    snprintf(port_str, sizeof(port_str), "%d", server_port);
#else
    sprintf(port_str, "%d", server_port);
#endif
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    if (getaddrinfo(server_host, port_str, &hints, &res) != 0) {
        closesocket(sockfd);
        #ifdef _WIN32
        WSACleanup();
        #endif
        return 4; // resolve failed
    }

    // Send
    if (sendto(sockfd, (const char*)msg_data, msg_len, 0, res->ai_addr, (int)res->ai_addrlen) == SOCKET_ERROR) {
        freeaddrinfo(res);
        closesocket(sockfd);
        #ifdef _WIN32
        WSACleanup();
        #endif
        return 5; // send failed
    }
    freeaddrinfo(res);

    // Set timeout (5 seconds)
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(sockfd, &readfds);
    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;

    int ret = select((int)(sockfd + 1), &readfds, NULL, NULL, &tv);
    if (ret <= 0) { // Timeout or error
        closesocket(sockfd);
        #ifdef _WIN32
        WSACleanup();
        #endif
        return 6; // timeout
    }

    // Read
    struct sockaddr_in from_addr;
    int from_len = sizeof(from_addr);
    
#ifdef _WIN32
    int n = recvfrom(sockfd, (char*)response_buf, response_buf_len, 0, (struct sockaddr*)&from_addr, &from_len);
#else
    socklen_t flen = sizeof(from_addr);
    int n = recvfrom(sockfd, (char*)response_buf, response_buf_len, 0, (struct sockaddr*)&from_addr, &flen);
#endif

    if (n == SOCKET_ERROR) {
        closesocket(sockfd);
        #ifdef _WIN32
        WSACleanup();
        #endif
        return 7; // recv failed
    }

    *bytes_read = n;

    closesocket(sockfd);
    #ifdef _WIN32
    WSACleanup();
    #endif

    return 0; // success
}

int nat_detect_tcp_c(const char* server_host, int server_port, int local_port,
                     void* response_buf, int response_buf_len, int* bytes_read) {
    #ifdef _WIN32
    WSADATA wsaData;
    int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        return 1;
    }
    #endif

    SOCKET sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sockfd == INVALID_SOCKET) {
        #ifdef _WIN32
        WSACleanup();
        #endif
        return 2;
    }

    int opt = 1;
#ifdef _WIN32
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
#else
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const void*)&opt, sizeof(opt));
#ifdef SO_REUSEPORT
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, (const void*)&opt, sizeof(opt));
#endif
#endif

    struct sockaddr_in cli_addr;
    memset(&cli_addr, 0, sizeof(cli_addr));
    cli_addr.sin_family = AF_INET;
    cli_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    cli_addr.sin_port = htons((unsigned short)local_port);

    if (bind(sockfd, (struct sockaddr*)&cli_addr, sizeof(cli_addr)) == SOCKET_ERROR) {
        closesocket(sockfd);
        #ifdef _WIN32
        WSACleanup();
        #endif
        return 3;
    }

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    char port_str[6];
    sprintf(port_str, "%d", server_port);

    if (getaddrinfo(server_host, port_str, &hints, &res) != 0) {
        closesocket(sockfd);
        #ifdef _WIN32
        WSACleanup();
        #endif
        return 4;
    }

    if (connect(sockfd, res->ai_addr, (int)res->ai_addrlen) == SOCKET_ERROR) {
        freeaddrinfo(res);
        closesocket(sockfd);
        #ifdef _WIN32
        WSACleanup();
        #endif
        return 5;
    }
    freeaddrinfo(res);

    const char* ping = "1";
    if (send(sockfd, ping, 1, 0) == SOCKET_ERROR) {
        closesocket(sockfd);
        #ifdef _WIN32
        WSACleanup();
        #endif
        return 6;
    }

    // Set timeout (5 seconds)
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(sockfd, &readfds);
    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;

    int ret = select((int)(sockfd + 1), &readfds, NULL, NULL, &tv);
    if (ret <= 0) {
        closesocket(sockfd);
        #ifdef _WIN32
        WSACleanup();
        #endif
        return 7;
    }

    int n = recv(sockfd, (char*)response_buf, response_buf_len, 0);
    if (n == SOCKET_ERROR) {
        closesocket(sockfd);
        #ifdef _WIN32
        WSACleanup();
        #endif
        return 8;
    }

    *bytes_read = n;
    closesocket(sockfd);
    #ifdef _WIN32
    WSACleanup();
    #endif
    return 0;
}

// Helper to parse simple JSON {"ip":"...","port":...}
int parse_nat_rsp_c(const char* buf, int len, char* ip, int* port) {
    const char* ip_ptr = strstr(buf, "\"ip\":\"");
    if (!ip_ptr) {
        ip_ptr = strstr(buf, "\"IP\":\"");
    }
    if (!ip_ptr) return -1;
    ip_ptr += 6;
    const char* ip_end = strchr(ip_ptr, '\"');
    if (!ip_end) return -1;
    int ip_len = ip_end - ip_ptr;
    strncpy(ip, ip_ptr, ip_len);
    ip[ip_len] = '\0';

    const char* port_ptr = strstr(buf, "\"port\":");
    if (!port_ptr) return -1;
    port_ptr += 7;
    *port = atoi(port_ptr);
    return 0;
}

int get_nat_type_c(const char* server_host, int detect_port1, int detect_port2, int local_port,
                   char* public_ip_out, int* nat_type_out) {
    uint8_t msg[OPENP2P_HEADER_SIZE + 2]; // +2 for empty json {}
    encode_header_c(MSG_NAT_DETECT, MSG_NAT, 2, msg);
    msg[OPENP2P_HEADER_SIZE] = '{';
    msg[OPENP2P_HEADER_SIZE+1] = '}';

    char buf[2048];
    int bytes_read;
    char ip1[64];
    int port1, port2;

    // First detection
    if (nat_detect_udp_c(server_host, detect_port1, local_port, msg, sizeof(msg), buf, sizeof(buf), &bytes_read) != 0) {
        // Try TCP if UDP fails
        if (nat_detect_tcp_c(server_host, detect_port1, local_port, buf, sizeof(buf), &bytes_read) != 0) {
            return -1;
        }
        // TCP response is just ip:port string
        if (sscanf(buf, "%63[^:]:%d", ip1, &port1) != 2) return -2;
    } else {
        if (parse_nat_rsp_c(buf + OPENP2P_HEADER_SIZE, bytes_read - OPENP2P_HEADER_SIZE, ip1, &port1) != 0) return -3;
    }

    strcpy(public_ip_out, ip1);

    // Second detection
    if (nat_detect_udp_c(server_host, detect_port2, local_port, msg, sizeof(msg), buf, sizeof(buf), &bytes_read) != 0) {
        if (nat_detect_tcp_c(server_host, detect_port2, local_port, buf, sizeof(buf), &bytes_read) != 0) {
            return -4;
        }
        char ip2[64];
        if (sscanf(buf, "%63[^:]:%d", ip2, &port2) != 2) return -5;
    } else {
        char ip2[64];
        if (parse_nat_rsp_c(buf + OPENP2P_HEADER_SIZE, bytes_read - OPENP2P_HEADER_SIZE, ip2, &port2) != 0) return -6;
    }

    if (port1 == port2) {
        *nat_type_out = NAT_CONE;
    } else {
        *nat_type_out = NAT_SYMMETRIC;
    }

    return 0;
}
