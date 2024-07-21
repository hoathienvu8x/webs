#ifndef __WS_H
#define __WS_H

#include <stdint.h>

#define WS_FR_OP_CONT 0
#define WS_FR_OP_TXT  1
#define WS_FR_OP_BIN  2
#define WS_FR_OP_CLSE 8
#define WS_FR_OP_PING 0x9
#define WS_FR_OP_PONG 0xA
#define WS_FR_OP_UNSUPPORTED 0xF

#define WS_STATE_CONNECTING 0
#define WS_STATE_OPEN       1
#define WS_STATE_CLOSING    2
#define WS_STATE_CLOSED     3

#define WS_CLSE_NORMAL                1000
#define WS_CLSE_GOING_AWAY            1001
#define WS_CLSE_PROTOCOL_ERROR        1002
#define WS_CLSE_UNSUPPORTED_DATA_TYPE 1003
#define WS_CLSE_STATUS_NOT_AVAILABLE  1005
#define WS_CLSE_ABNORMAL_CLOSED       1006
#define WS_CLSE_INVALID_PAYLOAD       1007
#define WS_CLSE_POLICY_VIOLATION      1008
#define WS_CLSE_MESSAGE_TOO_BIG       1009
#define WS_CLSE_INVALID_EXTENSION     1010
#define WS_CLSE_UNEXPECTED_CONDITION  1011
#define WS_CLSE_TLS_HANDSHAKE_ERROR   1015

typedef struct tcp_server tcp_server;
typedef struct tcp_conn tcp_conn;

tcp_server * create_tcp_server(short port, void * data);
void tcp_server_start(tcp_server * srv, int thread_loop);
void tcp_server_stop(tcp_server * srv);
void tcp_server_destroy(tcp_server * srv);

size_t tcp_server_get_id(const tcp_server * srv);
void * tcp_server_get_context(const tcp_server * srv);

void tcp_server_onopen(tcp_server * srv, void (*onopen)(tcp_conn *));
void tcp_server_ondata(tcp_server * srv, void (*ondata)(tcp_conn *, const unsigned char *, size_t, int));
void tcp_server_onclose(tcp_server * srv, void (*onclose)(tcp_conn *));
void tcp_server_dispatch(tcp_server * srv, int (*dispatch)(tcp_conn *, const char *));

void tcp_server_close(tcp_conn * conn, int code, const char * reason);
void tcp_server_send(tcp_conn * conn, const unsigned char * data, int opcode);
void tcp_server_boadcast(tcp_conn * conn, const unsigned char * data, int opcode);
void tcp_server_sendall(tcp_server * srv, const unsigned char * data, int opcode);

int tcp_conn_get_state(const tcp_conn * conn);
size_t tcp_conn_get_id(const tcp_conn * conn);
void * tcp_conn_get_context(const tcp_conn * conn);

#endif
