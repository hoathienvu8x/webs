#ifndef _GNU_SOURCE
  #define _GNU_SOURCE
#endif

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <pthread.h>
#include <unistd.h>
#include <errno.h>

#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "ws.h"

#define MAX_CLIENTS    8
#define MESSAGE_LENGTH 2048
#define MAGIC_STRING   "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

#ifndef SSIZE_MAX
  #define SSIZE_MAX ((~((size_t) 0)) >> 1)
#endif

#define __tcp_get_length(h) (((uint8_t *)&h)[1] & 0x7f)
#define __tcp_get_opcode(h) (((uint8_t *)&h)[0] & 0x0f)
#define __tcp_get_masked(h) (((uint8_t *)&h)[1] & 0x80)
#define __tcp_get_finish(h) (((uint8_t *)&h)[0] & 0x80)
#define __tcp_get_resvrd(h) (((uint8_t *)&h)[0] & 0x70)

#define __tcp_panic(s) do { perror(s); exit(-1); } while (0)
#ifndef NDEBUG
  #define __tcp_debug(...) fprintf(stderr, __VA_ARGS__)
  #define __tcp_debug_info(s) perror(s)
#else
  #define __tcp_debug(...)
  #define __tcp_debug_info(s)
#endif

struct tcp_buffer {
  char data[MESSAGE_LENGTH];
  size_t pos;
  size_t length;
};

struct tcp_conn {
  int fd;
  size_t id;
  tcp_server * srv;
  struct sockaddr_in addr;
  int state;
  struct tcp_buffer buf;
  pthread_t run_thread;
  tcp_conn * next;
  tcp_conn * prev;
  pthread_mutex_t mtx_state;
  pthread_mutex_t mtx_snd;
  pthread_mutex_t mtx_ping;
  uint32_t last_pong_id;
	uint32_t current_ping_id;
};

struct tcp_server {
  int fd;
  size_t id;
  int stop;
  pthread_t run_thread;
  tcp_conn * conns;
  tcp_conn * tail;
  void * ctx;
  size_t num_clients;
  void (*onopen)(tcp_conn *);
  void (*ondata)(tcp_conn *, const unsigned char *, size_t, int);
  void (*onclose)(tcp_conn *);
  int (*dispatch)(tcp_conn *, const char *);
};

struct http_header {
  char name[256];
  char value[256];
  struct http_header * next;
};

struct http_request {
  char method[10];
  char path[255];
  float version;
  char query[255];
  struct http_header * hdrs;
  struct http_header * tail;
  char * payload;
  size_t payload_length;
  int is_update;
};

struct tcp_frame {
  uint64_t length;
  uint32_t key;
  uint16_t info;
};

static int __tcp_close_socket(int fd) {
  shutdown(fd, SHUT_RDWR);
  return close(fd);
}

static int __tcp_base64_encode(const char * _s, char * _d, size_t _n) {
  size_t i = 0, n_max;
  int rem = _n % 3;
  _n -= rem;
  n_max = (_n * 4) / 3;
  #define TO_B64(X) ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[X])
  while (i < n_max) {
    _d[i + 0] = TO_B64(( _s[0] & 0xFC) >> 2);
    _d[i + 1] = TO_B64(((_s[0] & 0x03) << 4) | ((_s[1] & 0xF0) >> 4));
    _d[i + 2] = TO_B64(((_s[1] & 0x0F) << 2) | ((_s[2] & 0xC0) >> 6));
    _d[i + 3] = TO_B64(  _s[2] & 0x3F);
    _s += 3, i += 4;
  }

  if (rem == 1) {
    _d[i + 0] = TO_B64((_s[0] & 0xFC) >> 2);
    _d[i + 1] = TO_B64((_s[0] & 0x03) << 4);
    _d[i + 2] = '=';
    _d[i + 3] = '=';
  } else if (rem == 2) {
    _d[i + 0] = TO_B64(( _s[0] & 0xFC) >> 2);
    _d[i + 1] = TO_B64(((_s[0] & 0x03) << 4) | ((_s[1] & 0xF0) >> 4));
    _d[i + 2] = TO_B64(( _s[1] & 0x0F) << 2);
    _d[i + 3] = '=';
  }
  #undef TO_B64
  _d[i + 4] = '\0';

  return i + 4;
}

static int __tcp_sha1(const uint8_t *data, uint8_t *digest, size_t databytes)
{
  #define SHA1ROTATELEFT(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

  uint32_t W[80];
  uint32_t H[] = {
    0x67452301, 0xEFCDAB89, 0x98BADCFE,
    0x10325476, 0xC3D2E1F0
  };
  uint32_t a;
  uint32_t b;
  uint32_t c;
  uint32_t d;
  uint32_t e;
  uint32_t f = 0;
  uint32_t k = 0;

  uint32_t idx;
  uint32_t lidx;
  uint32_t widx;
  uint32_t didx = 0;

  int32_t wcount;
  uint32_t temp;
  uint64_t databits = ((uint64_t)databytes) * 8;
  uint32_t loopcount = (databytes + 8) / 64 + 1;
  uint32_t tailbytes = 64 * loopcount - databytes;
  uint8_t datatail[128] = {0};

  if (!digest || !data) {
    __tcp_debug("digest or data is null\n");
    return -1;
  }

  datatail[0] = 0x80;
  datatail[tailbytes - 8] = (uint8_t) (databits >> 56 & 0xFF);
  datatail[tailbytes - 7] = (uint8_t) (databits >> 48 & 0xFF);
  datatail[tailbytes - 6] = (uint8_t) (databits >> 40 & 0xFF);
  datatail[tailbytes - 5] = (uint8_t) (databits >> 32 & 0xFF);
  datatail[tailbytes - 4] = (uint8_t) (databits >> 24 & 0xFF);
  datatail[tailbytes - 3] = (uint8_t) (databits >> 16 & 0xFF);
  datatail[tailbytes - 2] = (uint8_t) (databits >> 8 & 0xFF);
  datatail[tailbytes - 1] = (uint8_t) (databits >> 0 & 0xFF);

  for (lidx = 0; lidx < loopcount; lidx++) {
    memset (W, 0, 80 * sizeof (uint32_t));

    for (widx = 0; widx <= 15; widx++) {
      wcount = 24;

      while (didx < databytes && wcount >= 0) {
        W[widx] += (((uint32_t)data[didx]) << wcount);
        didx++;
        wcount -= 8;
      }
      while (wcount >= 0) {
        W[widx] += (((uint32_t)datatail[didx - databytes]) << wcount);
        didx++;
        wcount -= 8;
      }
    }

    for (widx = 16; widx <= 31; widx++) {
      W[widx] = SHA1ROTATELEFT ((W[widx - 3] ^ W[widx - 8] ^ W[widx - 14] ^ W[widx - 16]), 1);
    }
    for (widx = 32; widx <= 79; widx++) {
      W[widx] = SHA1ROTATELEFT ((W[widx - 6] ^ W[widx - 16] ^ W[widx - 28] ^ W[widx - 32]), 2);
    }

    a = H[0];
    b = H[1];
    c = H[2];
    d = H[3];
    e = H[4];

    for (idx = 0; idx <= 79; idx++) {
      if (idx <= 19) {
        f = (b & c) | ((~b) & d);
        k = 0x5A827999;
      } else if (idx >= 20 && idx <= 39) {
        f = b ^ c ^ d;
        k = 0x6ED9EBA1;
      } else if (idx >= 40 && idx <= 59) {
        f = (b & c) | (b & d) | (c & d);
        k = 0x8F1BBCDC;
      } else if (idx >= 60 && idx <= 79) {
        f = b ^ c ^ d;
        k = 0xCA62C1D6;
      }
      temp = SHA1ROTATELEFT (a, 5) + f + e + k + W[idx];
      e = d;
      d = c;
      c = SHA1ROTATELEFT (b, 30);
      b = a;
      a = temp;
    }

    H[0] += a;
    H[1] += b;
    H[2] += c;
    H[3] += d;
    H[4] += e;
  }

  for (idx = 0; idx < 5; idx++) {
    digest[idx * 4 + 0] = (uint8_t) (H[idx] >> 24);
    digest[idx * 4 + 1] = (uint8_t) (H[idx] >> 16);
    digest[idx * 4 + 2] = (uint8_t) (H[idx] >> 8);
    digest[idx * 4 + 3] = (uint8_t) (H[idx]);
  }

  return 0;
}

static uint32_t __tcp_parse_uint32(uint8_t * msg) {
  return (msg[3] << 0) | (msg[2] << 8) | (msg[1] << 16) | (msg[0] << 24);
}

static int __tcp_create_socket(
  const char * host, short port,
  int (*boc)(int, const struct sockaddr *, socklen_t)
) {
  const int yes = 1;
  int ret = 0, sockfd = -1;
  struct addrinfo hints, *results, *p;
  char sport[8] = {0};

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_flags = AI_PASSIVE;
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  ret = snprintf(sport, sizeof(sport) - 1, "%d", port);
  if (ret <= 0) {
    __tcp_debug_info("snprintf(port) ");
    return -1;
  }

  if (getaddrinfo(host, sport, &hints, &results) != 0) {
    __tcp_debug_info("getaddrinfo(port) ");
    return -1;
  }

  for (p = results; p != NULL; p = p->ai_next) {
    sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (sockfd < 0) continue;
    ret = setsockopt(
      sockfd, SOL_SOCKET, SO_REUSEADDR, (const char *)&yes, sizeof(yes)
    );
    if (ret == 0 && boc(sockfd, p->ai_addr, p->ai_addrlen) == 0) break;
    close(sockfd);
  }

  freeaddrinfo(results);
  if (p == NULL) {
    __tcp_debug("No port to bind\n");
    return -1;
  }
  return sockfd;
}

static int __tcp_get_line(const char * s, char * line) {
  if (!s || strlen(s) == 0) return -1;
  const char * p = s;
  int i = 0;
  while (*p) {
    if (*p == '\n') break;
    line[i++] = *(p++);
  }
  line[i] = '\0';
  if (line[i - 1] == '\r') {
    i--;
    line[i] = '\0';
  }
  return i;
}

static int __tcp_parse_header(const char * s, struct http_header * hr) {
  const char * p = strstr(s, ": ");
  if (!p) return -1;
  size_t len = (size_t)(p - s);
  memcpy(hr->name, s, len);
  hr->name[len] = '\0';
  p += 2;
  len = strlen(p);
  if (len > 0) {
    memcpy(hr->value, p, len);
    hr->value[len] = '\0';
  }
  return 0;
}

static int __tcp_parse_request(const char * s, struct http_request * req) {
  if (!s || strlen(s) == 0) return -1;
  char line[255] = {0};
  req->is_update = 0;
  if (__tcp_get_line(s, line) <= 0) return -1;

  if (sscanf(line, "%s %s HTTP/%f", req->method, req->path, &req->version) != 3) {
    return -1;
  }
  size_t pos = strcspn(req->path, "?#");
  if (pos != strlen(req->path)) {
    memcpy(&req->query[0], &req->path[pos + 1], strlen(req->path) - pos);
    req->path[pos] = '\0';
  }
  const char * p = s + strlen(line);
  if (!*p) return 0;
  while (*(p++) != '\n');
  memset(&line, 0, sizeof(line));
  int socket_ver = 0, socket_key = 0, socket_update = 0;
  while(*p && __tcp_get_line(p, line) > 0) {
    struct http_header * hr = malloc(sizeof(struct http_header));
    if (!hr) __tcp_panic("Failed to allocated memory!\n");
    if (__tcp_parse_header(line, hr) == 0) {
      hr->next = NULL;
      if(req->hdrs == NULL) {
        req->hdrs = req->tail = hr;
      } else {
        req->tail->next = hr;
        req->tail = hr;
      }
      if (strcasecmp(hr->name, "Sec-WebSocket-Version") == 0 && strcmp(hr->value, "13") == 0) {
        socket_ver = 1;
      } else if (strcasecmp(hr->name, "Sec-WebSocket-Key") == 0) {
        socket_key = 1;
      } else if (strcasecmp(hr->name, "Connection") == 0 && strcasecmp(hr->value, "Upgrade") == 0) {
        socket_update = 1;
      }
    }
    p = p + strlen(line);
    memset(&line, 0, sizeof(line));
    while (*(p++) != '\n');
  }

  req->is_update = (socket_ver && socket_key && socket_update);
  if (req->is_update && strcasecmp(req->method,"GET") != 0) {
    req->is_update = 0;
  }
  return 0;
}

static ssize_t __tcp_conn_recv(tcp_conn * conn, char * buf, size_t len) {
  size_t i = 0;
  char * p = buf;
  for (; i < len; i++) {
    if (conn->buf.pos == 0 || conn->buf.pos == conn->buf.length) {
      ssize_t n = recv(conn->fd, conn->buf.data, sizeof(conn->buf.data), 0);
      if (n <= 0) return -1;
      conn->buf.pos = 0;
      conn->buf.length = (size_t)n;
    }
    p[i] = conn->buf.data[conn->buf.pos++];
  }
  return (size_t)i;
}

static ssize_t __tcp_conn_send(tcp_conn * conn, const char * buf, size_t len) {
  const char * p = buf;
  ssize_t ret = 0, r;
  pthread_mutex_lock(&conn->mtx_snd);
  while (len) {
    r = send(conn->fd, p, len, 0);
    if (r == -1) {
      pthread_mutex_unlock(&conn->mtx_snd);
      return -1;
    }
    p += r;
    len -= r;
    ret += r;
  }
  pthread_mutex_unlock(&conn->mtx_snd);
  return ret;
}

static int __tcp_is_control_frame(int opcode) {
  if (
    opcode == WS_FR_OP_CONT || opcode == WS_FR_OP_TXT ||
    opcode == WS_FR_OP_BIN || opcode == WS_FR_OP_CLSE ||
    opcode == WS_FR_OP_PING || opcode == WS_FR_OP_PONG
  ) {
    return 1;
  }
  return 0;
}

static int __tcp_conn_handshake(tcp_conn * conn, const char * key) {
  char buf[80] = {0}, hash[21] = {0}, s[1024] = {0};
  strcat(buf, key);
  strcat(buf, MAGIC_STRING);
  if (__tcp_sha1((const uint8_t *)&buf[0], (uint8_t *)&hash[0], strlen(&buf[0])) < 0) {
    return -1;
  }

  memset(&buf, 0, sizeof(buf));
  (void)__tcp_base64_encode(hash, buf, 20);
  int rc = snprintf(
    s, sizeof(s) - 1, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
    "Connection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", buf
  );

  if (rc <= 0) {
    __tcp_debug("snprintf(handshake) ");
    return -1;
  }
  s[rc] = '\0';
  rc = __tcp_conn_send(conn, s, strlen(s));
  if (rc < 0) return -1;
  return 0;
}

static void __tcp_mask_data(char * s, uint32_t key, size_t len) {
  ssize_t i;
  for (i = 0; i < len; i++) s[i] ^= ((char*) &key)[i % 4];
}

static char * __tcp_make_frame(
  const char * s, ssize_t n, uint8_t op, uint32_t key
) {
  size_t payload_length = n + 2;
  if (n > 125) {
    payload_length += 2;
  } else if (n > 65536) {
    payload_length += 8;
  }
  if (key != 0 && s) {
    payload_length += 4;
  }
  unsigned char * payload = malloc((payload_length + 1) * sizeof(unsigned char));
  if(!payload) {
    __tcp_debug("Failed to allocated memory!\n");
    return NULL;
  }
  short data_start = 2;
  uint64_t length = (uint64_t)n;
  payload[0] = (0x80 | op);
  if (length <= 125) {
    payload[1] = length & 0x7f;
  } else if (n >= 126 && n <= 65535) {
    payload[1] = 0x7e;
    payload[2] = (length >> 8) & 0xff;
    payload[3] = length & 0xff;
    data_start += 2;
  } else {
    payload[1] = 0x7f;
    payload[2] = (unsigned char)((length >> 56) & 0xff);
    payload[3] = (unsigned char)((length >> 48) & 0xff);
    payload[4] = (unsigned char)((length >> 40) & 0xff);
    payload[5] = (unsigned char)((length >> 32) & 0xff);
    payload[6] = (unsigned char)((length >> 24) & 0xff);
    payload[7] = (unsigned char)((length >> 16) & 0xff);
    payload[8] = (unsigned char)((length >> 8) & 0xff);
    payload[9] = (unsigned char)(length & 0xff);
    data_start += 8;
  }
  if (!s) {
    payload[payload_length] = '\0';
    return (char *)payload;
  }
  if (key != 0) {
    payload[1] |= 0x80;
    memcpy(payload + data_start, (char *)&key, 4);
    data_start += 4;
  }
  memcpy(payload + data_start, s, n);
  if (key != 0) {
    __tcp_mask_data((char *)(payload + data_start), key, n);
  }
  payload[payload_length] = '\0';
  return (char *)payload;
}

static void __tcp_conn_set_state(tcp_conn * conn, int state) {
  if (state < 0 || state > 3) return;
  pthread_mutex_lock(&conn->mtx_state);
  conn->state = state;
  pthread_mutex_unlock(&conn->mtx_state);
}

static tcp_conn * __tcp_server_add_node(tcp_server * srv, tcp_conn * node) {
  if (!srv) return NULL;

  if (srv->tail == NULL) {
    srv->tail = srv->conns = node;
    srv->conns->prev = NULL;
  } else {
    srv->tail->next = node;
    srv->tail->next->prev = srv->tail;
    srv->tail = srv->tail->next;
  }

  srv->tail->next = NULL;
  srv->num_clients++;

  return node;
}

static void __tcp_server_remove_node(tcp_conn * conn) {
  if (!conn) return;
  if (conn->prev) {
    conn->prev->next = conn->next;
  }
  if (conn->next) {
    conn->next->prev = conn->prev;
  }
  if (conn->srv) conn->srv->num_clients--;
  free(conn);
}

static int __tcp_accept_connection(int fd, tcp_conn * c) {
  static size_t tcp_conn_counter = 0;
  socklen_t len = sizeof(c->addr);
  c->fd = accept(fd, (struct sockaddr *)&c->addr, &len);
  if (c->fd < 0) {
    __tcp_panic("Error on accepting connections...");
  }

  c->last_pong_id = -1;
  c->current_ping_id = -1;

  if (pthread_mutex_init(&c->mtx_state, NULL)) {
    __tcp_close_socket(c->fd);
    __tcp_debug_info("pthread_mutex_init(mtx_state)");
    return -1;
  }

  if (pthread_mutex_init(&c->mtx_snd, NULL)) {
    __tcp_close_socket(c->fd);
    __tcp_debug_info("pthread_mutex_init(mtx_snd)");
    return -1;
  }

  if (pthread_mutex_init(&c->mtx_ping, NULL)) {
    __tcp_close_socket(c->fd);
    __tcp_debug_info("pthread_mutex_init(mtx_ping)");
    return -1;
  }

  c->id = tcp_conn_counter++;
  return c->fd;
}

static int __tcp_conn_parse_frame(tcp_conn * conn, struct tcp_frame * frm) {
  ssize_t ret;
  char buf[10] = {0};
  ret = __tcp_conn_recv(conn, (char *)&frm->info, 2);
  if (ret < 2) return -1;
  uint64_t frame_length = __tcp_get_length(frm->info);
  if (frame_length == 126) {
    ret = __tcp_conn_recv(conn, buf, 2);
    if (ret < 2) return -1;
    frm->length = ((uint64_t)buf[0] << 8) | buf[1];
  } else if (frame_length == 127) {
    ret = __tcp_conn_recv(conn, buf, 8);
    if (ret < 8) return -1;
    frm->length = (
      ((uint64_t)buf[0] << 56) | ((uint64_t)buf[1] << 48) |
      ((uint64_t)buf[2] << 40) | ((uint64_t)buf[3] << 32) |
      ((uint64_t)buf[4] << 24) | ((uint64_t)buf[5] << 16) |
      ((uint64_t)buf[6] << 8) | buf[7]
    );
  } else {
    frm->length = frame_length;
  }
  if (__tcp_get_masked(frm->info)) {
    ret = __tcp_conn_recv(conn, (char *)&frm->key, 4);
    if (ret < 4) return -1;
  }
  if (__tcp_get_resvrd(frm->info)) return -1;
  return 0;
}

static void * __tcp_conn_main(void * self) {
  tcp_conn * conn = (tcp_conn *)self;

  char buf[4096] = {0};
  ssize_t n = 0, len = 0;
  uint64_t total = 0;
  int cont = 0;
  struct http_request req;
  struct http_header * hdr;
  struct tcp_frame frm;
  char * data = NULL;
  do {
    n = __tcp_conn_recv(conn, buf + len, 1);
    len += n;
    if (strstr(buf, "\r\n\r\n") != NULL) break;
  } while (n > 0);

  memset(&req, 0, sizeof(struct http_request));
  req.hdrs = req.tail = NULL;

  if (__tcp_parse_request(buf, &req) < 0) goto ABORT;

  if (conn->srv && *conn->srv->dispatch) {
    if (!(*conn->srv->dispatch)(conn, req.path)) goto ABORT;
  }

  if (!req.is_update) goto ABORT;

  hdr = req.hdrs;
  while (hdr) {
    if (strcasecmp(hdr->name, "Sec-WebSocket-Key") == 0) {
      if (__tcp_conn_handshake(conn, hdr->value) < 0) goto ABORT;
      break;
    }
    hdr = hdr->next;
  }
  
  if (hdr == NULL) goto ABORT;

  __tcp_conn_set_state(conn, WS_STATE_OPEN);

  if (conn->srv && *conn->srv->onopen) {
    (*conn->srv->onopen)(conn);
  }

  for (;;) {
    if (conn->srv && conn->srv->stop) break;

    if (__tcp_conn_parse_frame(conn, &frm) < 0) {
      break;
    }
    
    int opcode = __tcp_get_opcode(frm.info);
    if (!__tcp_is_control_frame(opcode)) {
      continue;
    }

    if (opcode == WS_FR_OP_PING || opcode == WS_FR_OP_PONG || opcode == WS_FR_OP_CLSE) {
      if (frm.length > 125) break;
    }

    if ((size_t)frm.length > SSIZE_MAX) {
      continue;
    }

    if (opcode != WS_FR_OP_CONT) {
      if (data) free(data);
      data = malloc(frm.length + 1);
      if (!data) {
        __tcp_panic("Failed to allocate memory!\n");
      }

      ssize_t z = 0;
      do {
        n = __tcp_conn_recv(conn, data + z, frm.length - z);
        if (n < 0) {
          free(data);
          goto CLOSING;
        }
        if (n > 0) z += n;
      } while (n > 0 || z < (ssize_t)frm.length);
      total = frm.length;

      if (__tcp_get_masked(frm.info)) {
        __tcp_mask_data(data, frm.key, frm.length);
      }

      if (!__tcp_get_finish(frm.info)) {
        cont = 1;
        continue;
      }
    } else if (cont == 1) {
      data = realloc(data, total + frm.length + 1);
      if (!data) {
        __tcp_panic("Failed to reallocate memory!\n");
      }

      ssize_t z = 0;
      do {
        n = __tcp_conn_recv(conn, data + total + z, frm.length - z);
        if (n < 0) {
          free(data);
          goto CLOSING;
        }
        if (n > 0) z += n;
      } while (n > 0 || z < (ssize_t)frm.length);

      if (__tcp_get_masked(frm.info)) {
        __tcp_mask_data(data + total, frm.key, frm.length);
      }

      total += frm.length;

      if (!__tcp_get_finish(frm.info)) {
        continue;
      }

      cont = 0;
    } else {
      continue;
    }

    if (opcode == WS_FR_OP_CLSE) {
      if (tcp_conn_get_state(conn) != WS_STATE_CLOSING) {
        __tcp_conn_set_state(conn, WS_STATE_CLOSING);
      }
      int cc = -1;
      if (frm.length == 1) {
        cc = data[0];
      } else if (frm.length == 2) {
        cc = ((int)data[0] << 8) | data[1];
      }
      char * payload = NULL;
      if (cc < 0) {
        payload = __tcp_make_frame(data, frm.length, WS_FR_OP_CLSE, 0);
      } else {
        char m[2] = { (cc >> 8), (cc & 0xff) };
        payload = __tcp_make_frame(m, sizeof(m), WS_FR_OP_CLSE, 0);
      }
      free(data);
      if (!payload) {        
        (void)__tcp_conn_send(conn, payload, strlen(payload));
        free(payload);
      }
      break;
    }

    data[total] = '\0';

    if (opcode == WS_FR_OP_PING) {
      char * payload = __tcp_make_frame(data, frm.length, WS_FR_OP_PONG, 0);
      if (!payload) {
        free(data);
        goto CLOSING;
      }
      if (__tcp_conn_send(conn, payload, strlen(payload)) < 0) {
        free(data);
        free(payload);
        goto CLOSING;
      }
      free(payload);
    } else if (opcode == WS_FR_OP_PONG) {
      if (frm.length == sizeof(conn->last_pong_id)) {
        pthread_mutex_lock(&conn->mtx_ping);
        uint32_t pong_id = __tcp_parse_uint32((uint8_t *)data);
        if (pong_id > 0 && pong_id < conn->current_ping_id) {
          conn->last_pong_id = pong_id;
        }
        pthread_mutex_unlock(&conn->mtx_ping);
      }
    } else {
      if (conn->srv && *conn->srv->ondata) {
        (*conn->srv->ondata)(conn, (const unsigned char *)data, total, opcode);
      }
    }

    free(data);
    data = NULL;
  }

CLOSING:
  if (conn->srv && *conn->srv->onclose) {
    (*conn->srv->onclose)(conn);
  }
  __tcp_conn_set_state(conn, WS_STATE_CLOSED);

ABORT:
  __tcp_close_socket(conn->fd);

  pthread_mutex_destroy(&conn->mtx_state);
  pthread_mutex_destroy(&conn->mtx_snd);
  pthread_mutex_destroy(&conn->mtx_ping);

  __tcp_server_remove_node(conn);

  return self;
}

static void * __tcp_server_main(void * self) {
  tcp_server * srv = (tcp_server *)self;
  if (!srv) return self;

  for (;;) {
    if (srv->stop) break;
    tcp_conn * c = malloc(sizeof(struct tcp_conn));
    if (c) {
      c->fd = __tcp_accept_connection(srv->fd, c);

      if (c->fd > 0) {
        c->srv = srv;
        __tcp_server_add_node(srv, c);
        if (pthread_create(&c->run_thread, NULL, __tcp_conn_main, c)) {
          __tcp_panic("Could not create client thread!");
        }
      }
    }
  }

  return self;
}

tcp_server * create_tcp_server(short port, void * data) {
  static size_t tcp_server_counter = 0;
  tcp_server * srv = malloc(sizeof(struct tcp_server));
  if (!srv) {
    __tcp_debug("Failed to allocate memory\n");
    return NULL;
  }

  srv->fd = __tcp_create_socket(NULL, port, bind);
  if (srv->fd <= 0) {
    free(srv);
    return NULL;
  }

  if (listen(srv->fd, MAX_CLIENTS) < 0) {
    free(srv);
    return NULL;
  }

  srv->stop = 1;
  srv->onopen = NULL;
  srv->ondata = NULL;
  srv->onclose = NULL;
  srv->dispatch = NULL;

  srv->conns = srv->tail = NULL;
  srv->ctx = data;
  srv->id = tcp_server_counter++;

  return srv;
}
void tcp_server_start(tcp_server * srv, int thread_loop) {
  if (!srv) return;

  srv->stop = 0;

  if (thread_loop) {
    if (pthread_create(&srv->run_thread, NULL, __tcp_server_main, srv)) {
      __tcp_panic("Could not create server thread!");
    }
  } else {
    (void)__tcp_server_main(srv);
  }
}
void tcp_server_stop(tcp_server * srv) {
  if (!srv) return;

  srv->stop = 1;

  if (srv->run_thread) {
    pthread_cancel(srv->run_thread);
  }
}
void tcp_server_destroy(tcp_server * srv) {
  if (!srv) return;

  if (srv->run_thread) {
    pthread_join(srv->run_thread, NULL);
  }

  tcp_conn * node = srv->conns;
  tcp_conn * temp = NULL;

  while (node) {
    temp = node->next;
    tcp_server_close(node, WS_CLSE_ABNORMAL_CLOSED, NULL);
    __tcp_server_remove_node(node);
    node = temp;
  }

  free(srv);
}

size_t tcp_server_get_id(const tcp_server * srv) {
  if (!srv) return 0;
  return srv->id;
}
void * tcp_server_get_context(const tcp_server * srv) {
  if (!srv) return NULL;
  return srv->ctx;
}

void tcp_server_onopen(tcp_server * srv, void (*onopen)(tcp_conn *)) {
  if (!srv) return;
  srv->onopen = onopen;
}
void tcp_server_ondata(
  tcp_server * srv, void (*ondata)(
    tcp_conn *, const unsigned char *, size_t, int
  )
) {
  if (!srv) return;
  srv->ondata = ondata;
}
void tcp_server_onclose(tcp_server * srv, void (*onclose)(tcp_conn *)) {
  if (!srv) return;
  srv->onclose = onclose;
}
void tcp_server_dispatch(
  tcp_server * srv, int (*dispatch)(tcp_conn *, const char *)
) {
  if (!srv) return;
  srv->dispatch = dispatch;
}

void tcp_server_close(tcp_conn * conn, int code, const char * reason) {
  if (!conn) return;
  if (tcp_conn_get_state(conn) != WS_STATE_CLOSING) {
    __tcp_conn_set_state(conn, WS_STATE_CLOSING);
  }
  char * frm = NULL;
  if (!reason) {
    uint8_t cc[2] = { ((uint64_t)WS_CLSE_NORMAL >> 8), ((uint64_t)WS_CLSE_NORMAL & 0xff) };
    frm = __tcp_make_frame((const char *)cc, sizeof(cc), code, 0);
  } else {
    frm = __tcp_make_frame(reason, strlen(reason), code, 0);
  }
  if (!frm) goto done;
  (void)__tcp_conn_send(conn, frm, strlen(frm));
  free(frm);

done:
  if (*conn->srv->onclose) {
    (*conn->srv->onclose)(conn);
  }
  __tcp_close_socket(conn->fd);
  if (conn->run_thread) {
    pthread_cancel(conn->run_thread);
  }
  __tcp_conn_set_state(conn, WS_STATE_CLOSED);

  pthread_mutex_destroy(&conn->mtx_state);
  pthread_mutex_destroy(&conn->mtx_snd);
  pthread_mutex_destroy(&conn->mtx_ping);

  __tcp_server_remove_node(conn);
}
void tcp_server_send(tcp_conn * conn, const unsigned char * data, int opcode) {
  if (tcp_conn_get_state(conn) != WS_STATE_OPEN) return;
  char * frm = __tcp_make_frame(
    (const char *)data, data ? strlen((char *)data) : 0, opcode, 0
  );
  if (!frm) return;
  (void)__tcp_conn_send(conn, frm, strlen(frm));
  free(frm);
}
void tcp_server_boadcast(tcp_conn * conn, const unsigned char * data, int opcode) {
  if (!conn || !conn->srv) return;
  char * frm = __tcp_make_frame(
    (const char *)data, data ? strlen((char *)data) : 0, opcode, 0
  );
  if (!frm) return;
  size_t len = strlen(frm);
  tcp_conn * node = conn->srv->conns;
  while (node) {
    if (node->fd != conn->fd && tcp_conn_get_state(node) == WS_STATE_OPEN) {
      (void)__tcp_conn_send(node, frm, len);
    }
    node = node->next;
  }
  free(frm);
}
void tcp_server_sendall(
  tcp_server * srv, const unsigned char * data, int opcode
) {
  if (srv) return;
  char * frm = __tcp_make_frame(
    (const char *)data, data ? strlen((char *)data) : 0, opcode, 0
  );
  if (!frm) return;
  size_t len = strlen(frm);
  tcp_conn * node = srv->conns;
  while (node) {
    if (tcp_conn_get_state(node) == WS_STATE_OPEN) {
      (void)__tcp_conn_send(node, frm, len);
    }
    node = node->next;
  }
  free(frm);
}

int tcp_conn_get_state(tcp_conn * conn) {
  if (!conn) return WS_STATE_CLOSED;
  pthread_mutex_lock(&conn->mtx_state);
  int state = conn->state;
  pthread_mutex_unlock(&conn->mtx_state);
  return state;
}
size_t tcp_conn_get_id(const tcp_conn * conn) {
  if (!conn) return 0;
  return conn->id;
}
void * tcp_conn_get_context(const tcp_conn * conn) {
  if (!conn || !conn->srv) return NULL;
  return conn->srv->ctx;
}
