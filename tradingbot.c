#ifndef _GNU_SOURCE
  #define _GNU_SOURCE
#endif

#include <stdio.h>

#include "ws.h"


#define TRADINGBOT_PORT 8900

void tradingbot_onopen(tcp_conn * conn);
void tradingbot_ondata(tcp_conn * conn, const unsigned char * data, size_t length, int opcode);
void tradingbot_onclose(tcp_conn * conn);
int tradingbot_dispatch(tcp_conn * conn, const char * path);

int main(void) {
  tcp_server * srv = create_tcp_server(TRADINGBOT_PORT, NULL);

  if (!srv) return -1;

  tcp_server_onopen(srv, tradingbot_onopen);
  tcp_server_ondata(srv, tradingbot_ondata);
  tcp_server_onclose(srv, tradingbot_onclose);
  tcp_server_dispatch(srv, tradingbot_dispatch);

  tcp_server_start(srv, 0);

  tcp_server_destroy(srv);
  return 0;
}

void tradingbot_onopen(tcp_conn * conn) {
  printf("Client #%ld connected\n", tcp_conn_get_id(conn));
}
void tradingbot_ondata(tcp_conn * conn, const unsigned char * data, size_t length, int opcode) {
  if (opcode != WS_FR_OP_TXT && opcode != WS_FR_OP_BIN) return;
  if (opcode == WS_FR_OP_TXT) {
    printf("Client #%ld send\n -> %s\n", tcp_conn_get_id(conn), data);
  } else {
    printf("Client #%ld send %ld bytes\n", tcp_conn_get_id(conn), length);
  }
}
void tradingbot_onclose(tcp_conn * conn) {
  printf("Client #%ld disconnected\n", tcp_conn_get_id(conn));
}
int tradingbot_dispatch(tcp_conn * conn, const char * path) {
  return 1;
}
