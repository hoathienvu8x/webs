#ifndef __WEBS_H__
#define __WEBS_H__

#ifndef _GNU_SOURCE
  #define _GNU_SOURCE
#endif

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include <pthread.h>
#include <unistd.h>
#include <errno.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define WEBS_MAX_PACKET 1024

typedef struct webs_server webs_server;
typedef struct webs_client webs_client;

/* 
 * list of errors passed to `on_error`
 */
enum webs_error {
  WEBS_ERR_NONE = 0,
  WEBS_ERR_READ_FAILED,
  WEBS_ERR_UNEXPECTED_CONTINUTATION,
  WEBS_ERR_NO_SUPPORT,
  WEBS_ERR_OVERFLOW
};

/* 
 * stores header data from a websocket frame.
 */
struct webs_frame {
  ssize_t length; /* length of the frame's payload in bytes */
  uint32_t key;   /* a 32-bit key used to decrypt the frame's
                   *   payload (provided per frame) */
  uint16_t info;  /* the 16-bit frame header */
  short off;      /* offset from star of frame to payload*/
};

/* 
 * stores data parsed from an HTTP websocket request.
 */
struct webs_info {
  char webs_key[24 + 1]; /* websocket key (base-64 encoded string) */
  uint16_t webs_vrs;     /* websocket version (integer) */
  uint16_t http_vrs;     /* HTTP version (concatonated chars) */
  char req_type[8];
  char path[256];
};

/* 
 * used for sending / receiving data.
 */
struct webs_buffer {
  char data[WEBS_MAX_PACKET];
  ssize_t len;
};

/* 
 * user-implemented event handlers.
 */
struct webs_event_list {
  void (*on_error)(struct webs_client*, enum webs_error);
  void (*on_data )(struct webs_client*, int, char*, ssize_t);
  void (*on_open )(struct webs_client*);
  void (*on_close)(struct webs_client*);
  void (*on_pong)(struct webs_client*);
  void (*on_ping)(struct webs_client*);
  int (*is_route)(struct webs_client*, const char *);
  void (*on_periodic)(struct webs_server *);
};

struct webs_socket {
  char data[WEBS_MAX_PACKET];
  ssize_t len;
  ssize_t pos;
};

/* 
 * holds information relevant to a client.
 */
struct webs_client {
  struct webs_server* srv; /* a pointer to the server the the
                            *   clinet is connected to */
  struct sockaddr_in addr; /* client address */
  pthread_t thread;        /* client's posix thread id */
  size_t id;               /* client's internal id */
  int fd;                  /* client's descriptor */
  struct webs_socket buf;
  struct webs_client * next;
  struct webs_client * prev;
  int state;
  pthread_mutex_t mtx_snd;
  pthread_mutex_t mtx_sta;
};

/* 
 * holds information relevant to a server.
 */
struct webs_server {
  struct webs_event_list events;
  struct webs_client* head;
  struct webs_client* tail;
  size_t num_clients;
  pthread_t thread;
  size_t id;
  int soc;
  void * data;
  pthread_t periodic;
  pthread_mutex_t mtx;
  int interval;
};

/**
 * checks a client out of the server to which it is connected.
 * @param _self: the client to be ejected.
 * @note for user functions, passing self (a webs_client pointer) is suffice.
 */
void webs_eject(webs_client* _self);

/**
 * closes a websocket server.
 * @param _srv: the server that is to be shut down.
 */
void webs_close(webs_server* _srv);

/**
 * user function used to send null-terminated data over a
 * websocket.
 * @param _self: the client who is sending the data.
 * @param _data: a pointer to the null-terminated data
 * that is to be sent.
 * @return the result of the write.
 */
int webs_send(webs_client* _self, char* _data);
int webs_broadcast(webs_client* _self, char* _data);

/**
 * user function used to send binary data over a websocket.
 * @param _self: the client who is sending the data.
 * @param _data: a pointer to the data to is to be sent.
 * @param _n: the number of bytes that are to be sent.
 * @return the result of the write.
 */
void * webs_get_context(webs_client* _self);
int webs_sendn(webs_client* _self, char* _data, ssize_t _n);
int webs_nbroadcast(webs_client* _self, char* _data, ssize_t _n);

int webs_sendall(webs_server* _srv, char* _data);
int webs_nsendall(webs_server* _srv, char* _data, ssize_t _n);
/**
 * sends a pong frame to a client over a websocket.
 * @param _self: the client that the pong is to be sent to.
 */
void webs_pong(webs_client* _self);

/**
 * blocks until a server's thread closes (likely the
 * server has been closed with a call to "webs_close()").
 * @param _srv: the server that is to be waited for.
 * @return the result of pthread_join(), or -1 if NULL
 * was provided.
 */
int webs_hold(webs_server* _srv);
void webs_set_interval(webs_server* _srv, int interval);

/**
 * initialises a websocket sever and starts listening for
 * connections.
 * @param _port: the port to listen on.
 * @return 0 if the server could not be created, or a pointer
 * to the newly created server otherwise.
 */
webs_server* webs_create(int _port, void * data);
void webs_start(webs_server* _srv, int as_thread);

#endif /* __WEBS_H__ */
