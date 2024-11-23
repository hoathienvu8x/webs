#include "webs.h"
#include <math.h>
#include <netdb.h>

#define WS_STATE_CONNECTING 0
#define WS_STATE_OPEN       1
#define WS_STATE_CLOSING    2
#define WS_STATE_CLOSED     3
/* 
 * macros to report runtime errors...
 */
#define __WEBS_XE_PASTE_WRAPPER(x) __WEBS_XE_PASTE_RAW(x)
#define __WEBS_XE_PASTE_RAW(x) #x
#define __WEBS_XE_PASTE(V) __WEBS_XE_PASTE_WRAPPER(V)

#if __STDC_VERSION__ > 199409L
  #ifdef NOESCAPE
    #define WEBS_XERR(MESG, ERR) { \
      printf( \
        "Runtime Error: (in "__WEBS_XE_PASTE(__FILE__)", func: %s [line " \
        __WEBS_XE_PASTE(__LINE__)"]) : "MESG"\n", __func__); exit(ERR); \
      }
  #else
    #define WEBS_XERR(MESG, ERR) { \
      printf( \
        "\x1b[31m\x1b[1mRuntime Error: \x1b[0m(in "__WEBS_XE_PASTE(__FILE__) \
        ", func: \x1b[1m%s\x1b[0m [line \x1b[1m"__WEBS_XE_PASTE(__LINE__) \
        "\x1b[0m]) : "MESG"\n", __func__); exit(ERR); \
      }
  #endif
#else
  #ifdef NOESCAPE
    #define WEBS_XERR(MESG, ERR) { \
      printf( \
        "Runtime Error: (in "__WEBS_XE_PASTE(__FILE__)", line " \
        __WEBS_XE_PASTE(__LINE__)") : "MESG"\n"); exit(ERR); \
      }
  #else
    #define WEBS_XERR(MESG, ERR) { \
      printf( \
        "\x1b[31m\x1b[1mRuntime Error: \x1b[0m(in "__WEBS_XE_PASTE(__FILE__) \
        ", line \x1b[1m"__WEBS_XE_PASTE(__LINE__) \
        "\x1b[0m) : "MESG"\n"); exit(ERR); \
      }
  #endif
#endif
#ifdef VALIDATE_UTF8
#define IS_CONT(b) (((unsigned char)(b) & 0xC0) == 0x80)
#define WS_CLSE_INVUTF8 1007
#endif
/* 
 * declare endian-independant macros
 * http://www.yolinux.com/TUTORIALS/Endian-Byte-Order.html
 */
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  #define WEBS_BIG_ENDIAN_WORD(X) X
  #define WEBS_BIG_ENDIAN_DWORD(X) X
  #define WEBS_BIG_ENDIAN_QWORD(X) X
#else
  #if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
    #warning could not determine system endianness (assumng little endian).
  #endif
  #define WEBS_BIG_ENDIAN_WORD(x) ( (((x) >> 8) & 0x00FF) | (((x) << 8) & 0xFF00) )
  #define WEBS_BIG_ENDIAN_DWORD(x) ( (((x) >> 24) & 0x000000FF) | (((x) >>  8) & 0x0000FF00) | \
    (((x) <<  8) & 0x00FF0000) | (((x) << 24) & 0xFF000000) )
  #define WEBS_BIG_ENDIAN_QWORD(x) ( (((x) >> 56) & 0x00000000000000FF) | \
    (((x) >> 40) & 0x000000000000FF00) | (((x) >> 24) & 0x0000000000FF0000) | \
    (((x) >>  8) & 0x00000000FF000000) | (((x) <<  8) & 0x000000FF00000000) | \
    (((x) << 24) & 0x0000FF0000000000) | (((x) << 40) & 0x00FF000000000000) | \
    (((x) << 56) & 0xFF00000000000000) )

#endif

/* 
 * make sure SSIZE_MAX is defined.
 */
#ifndef SSIZE_MAX
  #define SSIZE_MAX ( (~((size_t) 0)) >> 1 )
#endif

/* 
 * buffer sizes...
 */
#define WEBS_MAX_BACKLOG 8

/* 
 * maximum packet recieve size is SSIZE_MAX.
 */
#define WEBS_MAX_RECIEVE SSIZE_MAX

/* 
 * macros for extracting bitwise data from a websocket frame's 16-bit
 * header.
 */
#define WEBSFR_GET_LENGTH(H) ( ((uint8_t*) &H)[1] & WEBSFR_LENGTH_MASK[1] )
#define WEBSFR_GET_OPCODE(H) ( ((uint8_t*) &H)[0] & WEBSFR_OPCODE_MASK[0] )
#define WEBSFR_GET_MASKED(H) ( ((uint8_t*) &H)[1] & WEBSFR_MASKED_MASK[1] )
#define WEBSFR_GET_FINISH(H) ( ((uint8_t*) &H)[0] & WEBSFR_FINISH_MASK[0] )
#define WEBSFR_GET_RESVRD(H) ( ((uint8_t*) &H)[0] & WEBSFR_RESVRD_MASK[0] )

#define WEBSFR_SET_LENGTH(H, V) ( ((uint8_t*) &H)[1] |= V & 0x7F )
#define WEBSFR_SET_OPCODE(H, V) ( ((uint8_t*) &H)[0] |= V & 0x0F )
#define WEBSFR_SET_MASKED(H, V) ( ((uint8_t*) &H)[1] |= (V << 7) & 0x80 )
#define WEBSFR_SET_FINISH(H, V) ( ((uint8_t*) &H)[0] |= (V << 7) & 0x80 )
#define WEBSFR_SET_RESVRD(H, V) ( ((uint8_t*) &H)[0] |= (V << 4) & 0x70 )

/* 
 * HTTP response format for confirming a websocket connection.
 */
#define WEBS_RESPONSE_FMT "HTTP/1.1 101 Switching Protocols\r\n" \
                          "Upgrade: websocket\r\nConnection: Upgrade\r\n" \
                          "Sec-WebSocket-Accept: %s\r\n\r\n"

/* 
 * macro to convert an integer to its base-64 representation.
 */
#define TO_B64(X) ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[X])

/* 
 * cast macro (can be otherwise pretty ugly)
 */
#define CASTP(X, T) (*((T*) (X)))

/* 
 * bitwise rotate left
 */
#define ROL(X, N) ((X << N) | (X >> ((sizeof(X) * 8) - N)))

/* headers for ping and pong frames */
uint8_t WEBS_PING[2] = {0x89, 0x00};
uint8_t WEBS_PONG[2] = {0x8A, 0x00};

/* masks... */
uint8_t WEBSFR_LENGTH_MASK[2] = {0x00, 0x7F};
uint8_t WEBSFR_OPCODE_MASK[2] = {0x0F, 0x00};
uint8_t WEBSFR_MASKED_MASK[2] = {0x00, 0x80};
uint8_t WEBSFR_FINISH_MASK[2] = {0x80, 0x00};
uint8_t WEBSFR_RESVRD_MASK[2] = {0x70, 0x00};


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
 * strcat that write result to a buffer...
 */
static int __webs_strcat(char* _buf, char* _a, char* _b) {
  int len = 0;
  while (*_a) *(_buf++) = *(_a++), len++;
  while (*_b) *(_buf++) = *(_b++), len++;
  *_buf = '\0';
  return len;
}

/* 
 * takes the SHA-1 hash of `_n` bytes of data (pointed to by `_s`),
 * storing the 160-bit (20-byte) result in the buffer pointed to by `_d`.
 */
static int __webs_sha1(char* _s, char* _d, uint64_t _n) {
  uint64_t raw_bits = _n * 8, * p = NULL;       /* length of message in bits */
  uint32_t a, b, c, d, e, f, k, t;  /* internal temporary variables */
  uint64_t C, O, i;                 /* iteration variables */
  short j;                          /* likewise */

  uint8_t* ptr = (uint8_t*) _s;  /* pointer to active chunk data */
  uint32_t wrds[80];             /* used in main loop */

  /* constants */
  uint32_t h0 = 0x67452301;
  uint32_t h1 = 0xEFCDAB89;
  uint32_t h2 = 0x98BADCFE;
  uint32_t h3 = 0x10325476;
  uint32_t h4 = 0xC3D2E1F0;

  /* pad the message length (plus one so that a bit can
   * be appended to the message, as per the specification)
   * so it is congruent to 56 modulo 64, all in bytes,
   * then add 8 bytes for the 64-bit length field */

  /* equivelantly, ((56 - (_n + 1)) MOD 64) + (_n + 1) + 8,
   * where `a MOD b` is the POSITIVE remainder after a is
   * divided by b */
  uint64_t pad_n = _n + ((55 - _n) & 63) + 9;

  uint64_t num_chks = pad_n / 64;  /* number of chunks to be processed */
  uint16_t rem_chks_begin = 0;     /* the first chunk with extended data */
  uint16_t offset = pad_n - 128;   /* start index for extended data */

  /* buffer to store extended chunk data (i.e. data that goes past the
   * smallest multiple of 64 bytes less than `_n`) (to avoid having to
   * make an allocation)*/
  uint8_t ext[128] = {0};

  /* if n is less than 120 bytes, then we can store the expanded data
   * directly in our buffer */
  if (_n < 120) {
    p = (uint64_t*) &ext[pad_n - 8];
    *p = WEBS_BIG_ENDIAN_QWORD(raw_bits);
    ext[_n] = 0x80;

    for (i = 0; i < _n; i++)
      ext[i] = _s[i];
  }

  /* otherwise, we will save our buffer for the last two chunks */
  else {
    rem_chks_begin = num_chks - 2;

    ext[_n - offset] = 0x80;
    p = (uint64_t*) &ext[120];
    *p = WEBS_BIG_ENDIAN_QWORD(raw_bits);

    for (i = 0; i < _n - offset; i++)
      ext[i] = _s[offset + i];
  }

  /* main loop (very similar to example in specification) */
  for (C = O = 0; C < num_chks; C++, O++) {
    if (C == rem_chks_begin) ptr = ext, O = 0;

    for (j = 0; j < 16; j++)
      wrds[j] = WEBS_BIG_ENDIAN_DWORD(((uint32_t*) ptr)[j]);

    for (j = 16; j < 80; j++) 
      wrds[j] = ROL((wrds[j - 3] ^ wrds[j - 8] ^
        wrds[j - 14] ^ wrds[j - 16]), 1);

    a = h0; b = h1; c = h2;
    d = h3; e = h4;

    for (j = 0; j < 80; j++) {
      if (j < 20) {
        f = ((b & c) | ((~b) & d));
        k = 0x5A827999;
      } else if (j < 40) {
        f = (b ^ c ^ d);
        k = 0x6ED9EBA1;
      } else if (j < 60) {
        f = ((b & c) | (b & d) | (c & d));
        k = 0x8F1BBCDC;
      } else {
        f = (b ^ c ^ d);
        k = 0xCA62C1D6;
      }

      t = ROL(a, 5) + f + e + k + wrds[j];

      e = d; d = c;
      c = ROL(b, 30);
      b = a; a = t;
    }

    h0 = h0 + a; h1 = h1 + b;
    h2 = h2 + c; h3 = h3 + d;
    h4 = h4 + e;

    ptr += 64;
  }

  /* copy data into destination */
  ((uint32_t*) _d)[0] = WEBS_BIG_ENDIAN_DWORD(h0);
  ((uint32_t*) _d)[1] = WEBS_BIG_ENDIAN_DWORD(h1);
  ((uint32_t*) _d)[2] = WEBS_BIG_ENDIAN_DWORD(h2);
  ((uint32_t*) _d)[3] = WEBS_BIG_ENDIAN_DWORD(h3);
  ((uint32_t*) _d)[4] = WEBS_BIG_ENDIAN_DWORD(h4);

  return 0;
}

/* 
 * Encodes `_n` bytes of data (pointed to by `_s`) into
 * base-64, storing the result as a null terminating string
 * in `_d`. The number of successfully written bytes is
 * returned.
 */
static int __webs_b64_encode(char* _s, char* _d, size_t _n) {
  size_t i = 0; /* iteration variable */

  /* `n_max` is the number of base-64 chars we
   * expect to output in the main loop */
  size_t n_max;

  /* belay data past a multiple of 3 bytes - so
   * we end on a whole number of encoded chars in
   * the main loop. */
  int rem = _n % 3;
  _n -= rem;

  n_max = (_n * 4) / 3;

  /* process bulk of data */
  while (i < n_max) {
    _d[i + 0] = TO_B64(( _s[0] & 0xFC) >> 2);
    _d[i + 1] = TO_B64(((_s[0] & 0x03) << 4) | ((_s[1] & 0xF0) >> 4));
    _d[i + 2] = TO_B64(((_s[1] & 0x0F) << 2) | ((_s[2] & 0xC0) >> 6));
    _d[i + 3] = TO_B64(  _s[2] & 0x3F);
    _s += 3, i += 4;
  }

  /* deal with remaining bytes (some may need to
   * be 0-padded if the data is not a multiple of
   * 6-bits - the length of a base-64 digit) */
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

  _d[i + 4] = '\0';

  return i + 4;
}
static void nsleep(long msec) {
  struct timespec ts, rs;
  int rc = -1;
  if (msec <= 0) {
    errno = EINVAL;
    return;
  }
  memset(&ts, 0, sizeof(ts));
  memset(&rs, 0, sizeof(rs));
  /* https://stackoverflow.com/a/26064185 */
  /* https://stackoverflow.com/a/33412806 */
  if (msec > 999) {
    ts.tv_sec = (int)(msec / 1000);
    ts.tv_nsec = (msec % 1000) * 1000000;
  } else {
    ts.tv_sec = 0;
    ts.tv_nsec = msec * 1000000;
  }
  do {
    rs = ts;
    rc = nanosleep(&rs, &ts);
  } while (rc == -1 && errno == EINTR);
}
static int __webs_close_socket(int fd) {
  shutdown(fd, SHUT_RDWR);
  return close(fd);
}
#ifdef VALIDATE_UTF8
static int num_bytes_in_utf8_sequence(unsigned char c) {
  if (c == 0xC0 || c == 0xC1 || c > 0xF4 || IS_CONT(c)) return 0;
  if ((c & 0x80) == 0) return 1;
  if ((c & 0xE0) == 0xC0) return 2;
  if ((c & 0xF0) == 0xE0) return 3;
  if ((c & 0xF8) == 0xF0) return 4;
  return 0;
}

static int verify_utf8_sequence(const unsigned char * str, int * len) {
  unsigned int cp = 0;
  *len = num_bytes_in_utf8_sequence(str[0]);
  if (*len == 1) {
    cp = str[0];
  } else if (*len == 2 && IS_CONT(str[1])) {
    cp = str[0] & 0x1f;
    cp = (cp << 6) | (str[1] & 0x3f);
  } else if (*len == 3 && IS_CONT(str[1]) && IS_CONT(str[2])) {
    cp = ((unsigned char)str[0]) & 0xf;
    cp = (cp << 6) | (str[1] & 0x3f);
    cp = (cp << 6) | (str[2] & 0x3f);
  } else if (*len == 4 && IS_CONT(str[1]) && IS_CONT(str[2]) && IS_CONT(str[3])) {
    cp = str[0] & 0x7;
    cp = (cp << 6) | (str[1] & 0x3f);
    cp = (cp << 6) | (str[2] & 0x3f);
    cp = (cp << 6) | (str[3] & 0x3f);
  } else {
    return -1;
  }
  if ((cp < 0x80 && *len > 1) || (cp < 0x800 && *len > 2) || (cp < 0x10000 && *len > 3)) {
    return -1;
  }
  if (cp > 0x10FFFF) return -1;
  if (cp >= 0xD800 && cp <= 0xDFFF) return -1;
  return 0;
}

static int is_valid_utf8(const char * str, size_t len) {
  int bytes = 0;
  const char * end = str + len;
  while (str < end) {
    if (verify_utf8_sequence((const unsigned char *)str, &bytes) != 0) {
      return -1;
    }
    str += bytes;
  }
  return 0;
}
#endif
/* 
 * wraper functon that deals with reading lage amounts
 * of data, as well as attemts to complete partial reads.
 * @param _fd: the file desciptor to be read from.
 * @param _dst: a buffer to store the resulting data.
 * @param _n: the number of bytes to be read.
 */
static ssize_t __webs_asserted_read(webs_client* cli, void* _dst, size_t _n) {
  size_t i = 0;
  ssize_t n = -1;
  char * p = _dst;

  for (; i < _n; i++) {
    if (cli->buf.pos == 0|| cli->buf.pos == cli->buf.len) {
      memset(&cli->buf, 0, sizeof(cli->buf));
      n = recv(cli->fd, cli->buf.data, sizeof(cli->buf.data), 0);
      if (n <= 0) return -1;
      cli->buf.pos = 0;
      cli->buf.len = (size_t)n;
    }
    *(p++) = cli->buf.data[cli->buf.pos++];
  }

  return (ssize_t)i;
}
static int __webs_asserted_write(int _fd, const void * _buf, size_t _len) {
  size_t left = _len;
  const char * buf = (const char *)_buf;
  do {
    ssize_t sent = send(_fd, buf, left, MSG_NOSIGNAL);
    if (sent == -1) return -1;
    left -= sent;
    if (sent > 0) buf += sent;
  } while (left > 0);
  return (left == 0 ? (int)_len : -1);
}
/* 
 * decodes XOR encrypted data from a websocket frame.
 * @param _dta: a pointer to the data that is to be decrypted.
 * @param _key: a 32-bit key used to decrypt the data.
 * @param _n: the number of bytes of data to be decrypted.
 */
static int __webs_decode_data(char* _dta, uint32_t _key, ssize_t _n) {
  ssize_t i;

  for (i = 0; i < _n; i++)
    _dta[i] ^= ((char*) &_key)[i % 4];

  return 0;
}

/* 
 * empties bytes from a descriptor's internal buffer.
 * (this is used to skip frames that cannot be processed)
 * @param _fd: the descritor whos buffer is to be emptied.
 * @return the number of bytes successfully processed.
 */
static size_t __webs_flush(webs_client* cli, size_t _n) {
  size_t i = 0;
  ssize_t n = -1;
  for (; i < _n; i++) {
    if (cli->buf.pos == 0|| cli->buf.pos == cli->buf.len) {
      memset(&cli->buf, 0, sizeof(cli->buf));
      n = recv(cli->fd, cli->buf.data, sizeof(cli->buf.data), 0);
      if (n <= 0) return -1;
      cli->buf.pos = 0;
      cli->buf.len = (size_t)n;
    }
    cli->buf.pos++;
  }
  return i;
}

/* 
 * parses a websocket frame by reading data sequentially from
 * a socket, storing the result in `_frm`.
 * @param _self: a pointer to the client who sent the frame.
 * @param _frm: a poiter to store the resulting frame data.
 * @return -1 if the frame could not be parsed, or 0 otherwise.
 */
static int __webs_parse_frame(webs_client* _self, struct webs_frame* _frm) {
  ssize_t error;

  /* read the 2-byte header field */
  error = __webs_asserted_read(_self, &_frm->info, 2);
  if (error < 0) return -1; /* read(2) error, maybe broken pipe */

  /* read the length field (may offset payload) */
  _frm->off = 2;

  /* a value of 126 here says to interpret the next two bytes */
  if (WEBSFR_GET_LENGTH(_frm->info) == 126) {
    error = __webs_asserted_read(_self, &_frm->length, 2);
    if (error < 0) return -1; /* read(2) error, maybe broken pipe */

    _frm->off = 4;
    _frm->length = WEBS_BIG_ENDIAN_WORD(_frm->length);
  }

  /* a value of 127 says to interpret the next eight bytes */
  else if (WEBSFR_GET_LENGTH(_frm->info) == 127) {
    error = __webs_asserted_read(_self, &_frm->length, 8);
    if (error < 0) return -1; /* read(2) error, maybe broken pipe */

    _frm->off = 10;
    _frm->length = WEBS_BIG_ENDIAN_QWORD(_frm->length);
  }

  /* otherwise, the raw value is used */
  else _frm->length = WEBSFR_GET_LENGTH(_frm->info);

  /* if the data is masked, the payload is further offset
   * to fit a four byte key */
  if (WEBSFR_GET_MASKED(_frm->info)) {
    error = __webs_asserted_read(_self, &_frm->key, 4);
    if (error < 1) return -1; /* read(2) error, maybe broken pipe */
  }

  /* if it is not masked, then by the specification (RFC-6455), the
   * connection should be closed */
  else return -1;

  /* by the specification (RFC-6455), since no extensions are yet
   * supported, if we recieve non-zero reserved bits the connection
   * should be closed */
  if (WEBSFR_GET_RESVRD(_frm->info) != 0)
    return -1;

  return 0;
}

/* 
 * generates a websocket frame from the provided data.
 * @param _src: a pointer to the frame's payload data.
 * @param _dst: a buffer that will hold the resulting frame.
 * @note the caller ensures this buffer is of adequate
 * length (it shouldn't need more than _n + 10 bytes).
 * @param _n: the size of the frame's payload data.
 * @param _op: the frame's opcode.
 * @return the total number of resulting bytes copied.
 */
static int __webs_make_frame(const char* _src, char* _dst, ssize_t _n,
    uint8_t _op, uint8_t _fin) {
  short data_start = 2;  /* offset to the start of the frame's payload */
  uint16_t hdr = 0;      /* the frame's header */

  WEBSFR_SET_FINISH(hdr, _fin);  /* this is not a cont. frame */
  WEBSFR_SET_OPCODE(hdr, _op);  /* opcode */

  /* set frame length field */

  /* if we have more than 125 bytes, store the length in the
   * next two bytes */
  if (_n > 125) {
    WEBSFR_SET_LENGTH(hdr, 126);
    CASTP(_dst + 2, uint16_t) = WEBS_BIG_ENDIAN_WORD((uint16_t) _n);
    data_start = 4;
  }

  /* if we have more than 2^16 bytes, store the length in
   * the next eight bytes */
  else if (_n > 65536) {
    WEBSFR_SET_LENGTH(hdr, 127);
    CASTP(_dst + 2, uint64_t) = WEBS_BIG_ENDIAN_QWORD((uint64_t) _n);
    data_start = 10;
  }

  /* otherwise place the value right in the field */
  else WEBSFR_SET_LENGTH(hdr, _n);

  /* write header to buffer */
  CASTP(_dst, uint16_t) = hdr;

  /* copy data */
  memcpy(_dst + data_start, _src, _n);

  return _n + data_start;
}

/* 
 * parses an HTTP header for web-socket related data.
 * @note this function is a bit of a mess...
 * @param _src: a pointer to the raw header data.
 * @param _rtn: a pointer to store the resulting data.
 * @return -1 on error (bad vers., ill-formed, etc.), or 0
 * otherwise.
 */
static int __webs_process_handshake(char* _src, struct webs_info* _rtn) {
  char http_vrs_low = 0;

  char param_str[256];
  int nbytes = 0;

  _rtn->webs_key[0] = 0;
  _rtn->webs_vrs = 0;
  _rtn->http_vrs = 0;

  if (sscanf(_src, "%s %s HTTP/%c.%c%*[^\r]\r%n", _rtn->req_type, _rtn->path,
    (char*) &_rtn->http_vrs, &http_vrs_low, &nbytes) <= 0)
    return -1;

  _src += nbytes;

  if (strcasecmp(_rtn->req_type, "GET"))
    return -1;

  _rtn->http_vrs <<= 8;
  _rtn->http_vrs += http_vrs_low;

  while (sscanf(_src, "%s%n", param_str, &nbytes) > 0) {
    _src += nbytes;

    if (!strcasecmp(param_str, "Sec-WebSocket-Version:")) {
      if (sscanf(_src, "%hu%*[^\r]\r%n", &_rtn->webs_vrs, &nbytes) <= 0)
        return -1;
      _src += nbytes;
    }

    else
    if (!strcasecmp(param_str, "Sec-WebSocket-Key:")) {
      if (sscanf(_src, "%s%*[^\r]\r%n", _rtn->webs_key, &nbytes) <= 0)
        return -1;
      _src += nbytes;
    }

    else {
      if (sscanf(_src, "%*[^\r]\r%n", &nbytes) < 0)
        return -1;
      _src += nbytes;
    }
  }

  if (!(_rtn->webs_key[0] || _rtn->webs_vrs || _rtn->http_vrs))
    return -1;

  return 0;
}

/* 
 * generates an HTTP websocket handshake response. by the
 * specification (RFC-6455), this is done by concatonating the
 * client provided key with a magic string, and returning the
 * base-64 encoded, SHA-1 hash of the result in the "Sec-WebSocket-
 * Accept" field of an HTTP response header.
 * @param _dst: a buffer that will hold the resulting HTTP
 * response data.
 * @param _key: a pointer to the websocket key provided by the
 * client in it's HTTP websocket request header.
 * @return the total number of resulting bytes copied.
 */
static int __webs_generate_handshake(char* _dst, char* _key) {
  char buf[61];   /* size of result is 60 bytes */
  char hash[21];  /* SHA-1 hash is 20 bytes */
  int len = 0;

  len = __webs_strcat(buf, _key, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
  __webs_sha1(buf, hash, len);
  len = __webs_b64_encode(hash, buf, 20);
  buf[len] = '\0';

  return sprintf(_dst, WEBS_RESPONSE_FMT, buf);
}

static int __webs_get_client_state(webs_client* _self) {
  int state;
  if (!_self) return -1;
  pthread_mutex_lock(&_self->mtx_sta);
  state = _self->state;
  pthread_mutex_unlock(&_self->mtx_sta);
  return state;
}

static int __webs_set_client_state(webs_client* _self, int state) {
  if (!_self) return -1;
  if (state < 0 || state > 3)
    return -1;
  pthread_mutex_lock(&_self->mtx_sta);
  if (_self->state != state)
    _self->state = state;
  pthread_mutex_unlock(&_self->mtx_sta);
  return 0;
}

/* 
 * removes a client from a server's internal listing.
 * @param _node: a pointer to the client in the server's listing.
 */
static void __webs_remove_client(webs_client* _node) {
  if (_node == NULL) return;

  if (_node->prev)
    _node->prev->next = _node->next;

  if (_node->next)
    _node->next->prev = _node->prev;

  _node->srv->num_clients--;

  pthread_mutex_destroy(&_node->mtx_sta);
  pthread_mutex_destroy(&_node->mtx_snd);

  free(_node);

  return;
}

/* 
 * adds a client to a server's internal listing.
 * @param _srv: the server that the client should be added to.
 * @param _cli: the client to be added.
 * @return a pointer to the added client in the server's listing.
 * (or NULL if NULL was provided)
 */
static void __webs_add_client(webs_server* _srv, webs_client * node) {
  if (_srv == NULL) return;

  /* if this is first client, set head = tail = new element */
  if (_srv->tail == NULL) {
    _srv->tail = _srv->head = node;

    _srv->head->prev = NULL;
  }

  /* otherwise, just add after the current tail */
  else {
    _srv->tail->next = node;

    _srv->tail->next->prev = _srv->tail;
    _srv->tail = _srv->tail->next;
  }

  _srv->tail->next = NULL;

  _srv->num_clients++;
}

/* 
 * accepts a connection from a client and provides it with
 * relevant data.
 * @param _soc: the socket that the connection is being requested on.
 * @param _cli: the client that is to be connected.
 * @return -1 on error, or 0 otherwise.
 */
static int __webs_accept_connection(int _soc, webs_client* _c) {
  /* static id counter variable */
  static size_t client_id_counter = 0;

  socklen_t addr_size = sizeof(_c->addr);

  _c->fd = accept(_soc, (struct sockaddr*) &_c->addr, &addr_size);
  if (_c->fd < 0) {
    WEBS_XERR("Error on accepting connections..", errno);
    return -1;
  }

  _c->id = client_id_counter;
  client_id_counter++;

  return _c->fd;
}

/* 
 * main client function, called on a thread for each
 * connected client.
 * @param _self: the client who is calling.
 */
static void* __webs_client_main(void* _self) {
  webs_client* self = (webs_client*) _self;
  ssize_t total = 0, _n = -1;
  ssize_t error;

  /* flag set if frame is a continuation one */
  int cont = 0;

  /* general-purpose recv/send buffer */
  struct webs_buffer soc_buffer;

  /* temporary variables */
  struct webs_info ws_info;
  struct webs_frame frm;
  char* data = 0;

  #ifdef VALIDATE_UTF8
  uint8_t ctrl[3] = {
    (WS_CLSE_INVUTF8 >> 8), (WS_CLSE_INVUTF8 & 0xff), '\0'
  };
  #endif

  memset(&soc_buffer, 0, sizeof(soc_buffer));
  memset(&ws_info, 0, sizeof(ws_info));
  memset(&frm, 0, sizeof(frm));

  /* wait for HTTP websocket request header */
  do {
    _n = __webs_asserted_read(self, soc_buffer.data + soc_buffer.len, 1);
    if (_n < 0) goto ABORT;
    soc_buffer.len += _n;
    if (strstr(soc_buffer.data, "\r\n\r\n")) {
      soc_buffer.len -= 4;
      break;
    }
    if (soc_buffer.len >= WEBS_MAX_PACKET) break;
  } while (_n > 0);

  /* if we did not recieve one, abort */
  if (soc_buffer.len == 0 || strstr(soc_buffer.data, "\r\n\r\n") == NULL)
    goto ABORT;

  /* process handshake */
  soc_buffer.data[soc_buffer.len] = '\0';

  /* if we failed, abort */
  if (__webs_process_handshake(soc_buffer.data, &ws_info) < 0)
    goto ABORT;

  if (*self->srv->events.is_route) {
    char path[256] = {0};
    size_t p = strcspn(ws_info.path, "?# ");
    if (p != strlen(ws_info.path)) {
      memcpy(path, ws_info.path, p);
      path[p] = '\0';
    } else {
      memcpy(path, ws_info.path, strlen(ws_info.path));
    }
    if (!(*self->srv->events.is_route)(self, path)) {
      goto ABORT;
    }
  }

  /* if we succeeded, generate + tansmit response */
  soc_buffer.len = __webs_generate_handshake(soc_buffer.data,
    ws_info.webs_key);

  if (__webs_asserted_write(self->fd, soc_buffer.data, soc_buffer.len) < 0)
    goto ABORT;

  __webs_set_client_state(self, WS_STATE_OPEN);

  /* call client on_open function */
  if (*self->srv->events.on_open)
    (*self->srv->events.on_open)(self);

  /* main loop */
  for (;;) {
    if (__webs_parse_frame(self, &frm) < 0) {
      error = WEBS_ERR_READ_FAILED;
      break;
    }

    /* only accept supported frames */
    if (WEBSFR_GET_OPCODE(frm.info) != WS_FR_OP_CONT
     && WEBSFR_GET_OPCODE(frm.info) != WS_FR_OP_TXT
     && WEBSFR_GET_OPCODE(frm.info) != WS_FR_OP_BIN
     && WEBSFR_GET_OPCODE(frm.info) != WS_FR_OP_CLSE
     && WEBSFR_GET_OPCODE(frm.info) != WS_FR_OP_PING
     && WEBSFR_GET_OPCODE(frm.info) != WS_FR_OP_PONG) {
      if (*self->srv->events.on_error)
        (*self->srv->events.on_error)(self, WEBS_ERR_NO_SUPPORT);

      __webs_flush(self, frm.off + frm.length - 2);
      continue;
    }

    /* check if packet is too big */
    if ((size_t) frm.length > SSIZE_MAX) {
      if (*self->srv->events.on_error)
        (*self->srv->events.on_error)(self, WEBS_ERR_OVERFLOW);

      __webs_flush(self, frm.off + frm.length - 2);
      continue;
    }

    /* respond to ping */
    if (WEBSFR_GET_OPCODE(frm.info) == WS_FR_OP_PING) {
      __webs_flush(self, frm.off + frm.length - 2);

      if (*self->srv->events.on_ping)
        (*self->srv->events.on_ping)(self);

      else
        webs_pong(self);

      continue;
    }

    /* handle pong */
    if (WEBSFR_GET_OPCODE(frm.info) == WS_FR_OP_PONG) {
      __webs_flush(self, frm.off + frm.length - 2);

      if (*self->srv->events.on_pong)
        (*self->srv->events.on_pong)(self);

      continue;
    }

    /* deal with normal frames (non-fragmented) */
    if (WEBSFR_GET_OPCODE(frm.info) != WS_FR_OP_CONT) {
      /* read data */
      if (data) free(data);
      data = malloc(frm.length + 1);

      if (data == NULL)
        WEBS_XERR("Failed to allocate memory!", ENOMEM);

      if (__webs_asserted_read(self, data, frm.length) < 0) {
        error = WEBS_ERR_READ_FAILED;
        free(data);
        break;
      }

      total = frm.length;
      __webs_decode_data(data, frm.key, frm.length);

      if (!WEBSFR_GET_FINISH(frm.info)) {
        cont = 1;
        continue;
      }
    }

    /* otherwise deal with fragmentation */
    else if (cont == 1) {
      data = realloc(data, total + frm.length);

      if (data == NULL)
        WEBS_XERR("Failed to allocate memory!", ENOMEM);

      if (__webs_asserted_read(self, data + total, frm.length) < 0) {
        error = WEBS_ERR_READ_FAILED;
        free(data);
        break;
      }

      __webs_decode_data(data + total, frm.key, frm.length);

      #ifdef VALIDATE_UTF8
      if (is_valid_utf8(data + total, frm.length) < 0) {
        free(data);
        webs_send(self, (const char *)ctrl, WS_FR_OP_CLSE);
        goto ABORT;
      }
      #endif

      total += frm.length;

      if (!WEBSFR_GET_FINISH(frm.info))
        continue;

      cont = 0;
    }

    /* or if we aren't expecting a continuation frame,
     * set error and skip the frame */
    else {
      if (*self->srv->events.on_error)
        (*self->srv->events.on_error)(self, WEBS_ERR_UNEXPECTED_CONTINUTATION);

      __webs_flush(self, frm.off + frm.length - 2);
      continue;
    }

    /* respond to close */
    if (WEBSFR_GET_OPCODE(frm.info) == WS_FR_OP_CLSE) {
      pthread_mutex_lock(&self->mtx_snd);
      soc_buffer.len = __webs_make_frame(data, soc_buffer.data,
        frm.length, WS_FR_OP_CLSE, 0x1);

      (void)__webs_asserted_write(self->fd, soc_buffer.data, soc_buffer.len);
      pthread_mutex_unlock(&self->mtx_snd);
      error = 0;
      break;
    }

    /* call clinet on_data function */
    data[total] = '\0';

    if (data) {
      #ifdef VALIDATE_UTF8
      if (
        WEBSFR_GET_OPCODE(frm.info) == WS_FR_OP_TXT &&
        is_valid_utf8(data, total) < 0
      ) {
        free(data);
        webs_send(self, (const char *)ctrl, WS_FR_OP_CLSE);
        goto ABORT;
      }
      #endif
      if (*self->srv->events.on_data)
        (*self->srv->events.on_data)(
          self, WEBSFR_GET_OPCODE(frm.info), data, total
        );
    }

    free(data);

    data = 0;
    continue;
  }

  /* call client on_error if there was an error */
  if (error > 0) {
    if (*self->srv->events.on_error)
      (*self->srv->events.on_error)(self, error);
  }

  __webs_set_client_state(self, WS_STATE_CLOSING);

  if (*self->srv->events.on_close)
    (*self->srv->events.on_close)(self);

  __webs_set_client_state(self, WS_STATE_CLOSED);

  ABORT:

  __webs_close_socket(self->fd);
  __webs_remove_client(self);

  return NULL;
}

static void * __webs_periodic(void * _srv) {
  webs_server * srv = (webs_server*) _srv;
  for (;;) {
    nsleep((long)srv->interval);
    (*srv->events.on_periodic)(srv);
  }
  return NULL;
}

/* 
 * main loop for a server, listens for connections and forks
 * them off for further initialisation.
 * @param _srv: the server that is calling.
 */
static void* __webs_main(void* _srv) {
  webs_server* srv = (webs_server*) _srv;
  webs_client* user_ptr;

  if (*srv->events.on_periodic && srv->interval > 0)
    pthread_create(&srv->periodic, 0, __webs_periodic, srv);

  for (;;) {
    user_ptr = malloc(sizeof(webs_client));
    if (!user_ptr)
      WEBS_XERR("Failed to allocate memory!", ENOMEM);

    if (pthread_mutex_init(&user_ptr->mtx_sta, NULL))
      WEBS_XERR("Failed to allocate state mutex!", ENOMEM);

    if (pthread_mutex_init(&user_ptr->mtx_snd, NULL))
      WEBS_XERR("Failed to allocate send mutex!", ENOMEM);

    user_ptr->fd = __webs_accept_connection(srv->soc, user_ptr);
    user_ptr->srv = srv;
    memset(&user_ptr->buf, 0, sizeof(user_ptr->buf));

    user_ptr->next = user_ptr->prev = NULL;

    if (user_ptr->fd >= 0) {
      __webs_add_client(srv, user_ptr);
      __webs_set_client_state(user_ptr, WS_STATE_CONNECTING);
      if (pthread_create(&user_ptr->thread, 0, __webs_client_main, user_ptr))
        WEBS_XERR("Could not create the client thread!", ENOMEM);
    }
  }

  return NULL;
}

void webs_eject(webs_client* _self) {
  __webs_set_client_state(_self, WS_STATE_CLOSING);
  if (*_self->srv->events.on_close)
    (*_self->srv->events.on_close)(_self);

  __webs_set_client_state(_self, WS_STATE_CLOSED);

  __webs_close_socket(_self->fd);
  pthread_cancel(_self->thread);
  __webs_remove_client(_self);
}

void webs_close(webs_server* _srv) {
  webs_client* node = _srv->head;
  webs_client* temp;

  if (_srv->periodic)
    pthread_cancel(_srv->periodic);

  if (_srv->thread)
    pthread_cancel(_srv->thread);

  __webs_close_socket(_srv->soc);

  pthread_mutex_destroy(&_srv->mtx);

  while (node) {
    temp = node->next;
    webs_eject(node);
    node = temp;
  }

  free(_srv);
}
int webs_send_close(webs_client* _self, const char * reason) {
  return webs_send(_self, reason, WS_FR_OP_CLSE);
}
int webs_send(webs_client* _self, const char* _data, int opcode) {
  /* general-purpose recv/send buffer */
  struct webs_buffer soc_buffer;
  int len = 0, i = 0, frame_count, rc;
  char buf[WEBS_MAX_PACKET];
  size_t _len;

  memset(&soc_buffer, 0, sizeof(soc_buffer));

  if (__webs_get_client_state(_self) != WS_STATE_OPEN) return 0;
  /* check for nullptr or empty string */
  if (!_data || !*_data) return 0;

  /* get length of data */
  while (_data[++len]);
  if (len < WEBS_MAX_PACKET - 4) {
    /* write data */
    pthread_mutex_lock(&_self->mtx_snd);
    _len = __webs_make_frame(_data, soc_buffer.data, len, opcode, 0x1);
    rc = __webs_asserted_write(_self->fd, soc_buffer.data, _len);
    pthread_mutex_unlock(&_self->mtx_snd);
    return rc;
  }
  pthread_mutex_lock(&_self->mtx_snd);
  frame_count = ceil((float)len / (float)(WEBS_MAX_PACKET - 4));
  if (frame_count == 0) frame_count = 1;
  for (; i < frame_count; i++) {
    int size = i != frame_count - 1 ? WEBS_MAX_PACKET - 4 : len % (WEBS_MAX_PACKET - 4);
    uint8_t _op = i != 0 ? 0x0 : opcode;
    uint8_t _fin = i != frame_count - 1 ? 0x0 : 0x1;
    memset(&buf, 0, sizeof(buf));
    memcpy(buf, &_data[i * (WEBS_MAX_PACKET - 4)], size);
    buf[size] = '\0';
    _len = __webs_make_frame(buf, soc_buffer.data, size, _op, _fin);
    if (__webs_asserted_write(_self->fd, soc_buffer.data, _len) < 0) {
      pthread_mutex_unlock(&_self->mtx_snd);
      return -1;
    }
  }
  pthread_mutex_unlock(&_self->mtx_snd);
  return 0;
}
int webs_broadcast(webs_client* _self, const char* _data, int opcode) {
  webs_client* node;
  if (!_self || !_self->srv) return -1;
  pthread_mutex_lock(&_self->srv->mtx);
  node = _self->srv->head;
  while (node) {
    if (node->id == _self->id) continue;
    (void)webs_send(node, _data, opcode);
    node = node->next;
  }
  pthread_mutex_unlock(&_self->srv->mtx);
  return 0;
}
void * webs_get_context(webs_client* _self) {
  if (!_self || !_self->srv) return NULL;
  return _self->srv->data;
}
int webs_sendn(webs_client* _self, const char* _data, ssize_t _n, int opcode) {
  /* general-purpose recv/send buffer */
  struct webs_buffer soc_buffer;
  int i = 0, frame_count = 0, rc;
  char buf[WEBS_MAX_PACKET];
  size_t _len;

  memset(&soc_buffer, 0, sizeof(soc_buffer));

  if (__webs_get_client_state(_self) != WS_STATE_OPEN) return 0;
  /* check for NULL or empty string */
  if (!_data || !*_data) return 0;
  if (_n < WEBS_MAX_PACKET - 4) {
    pthread_mutex_lock(&_self->mtx_snd);
    _len = __webs_make_frame(_data, soc_buffer.data, _n, opcode, 0x1);
    rc = __webs_asserted_write(_self->fd, soc_buffer.data, _len);
    pthread_mutex_unlock(&_self->mtx_snd);
    return rc;
  }
  pthread_mutex_lock(&_self->mtx_snd);
  frame_count = ceil((float)_n / (float)(WEBS_MAX_PACKET - 4));
  if (frame_count == 0) frame_count = 1;
  for (; i < frame_count; i++) {
    int size = i != frame_count - 1 ? WEBS_MAX_PACKET - 4 : _n % (WEBS_MAX_PACKET - 4);
    uint8_t _op = i != 0 ? 0x0 : opcode;
    uint8_t _fin = i != frame_count - 1 ? 0x0 : 0x1;
    memset(&buf, 0, sizeof(buf));
    memcpy(buf, &_data[i * (WEBS_MAX_PACKET - 4)], size);
    buf[size] = '\0';
    _len = __webs_make_frame(buf, soc_buffer.data, size, _op, _fin);
    if (__webs_asserted_write(_self->fd, soc_buffer.data, _len) < 0) {
      pthread_mutex_unlock(&_self->mtx_snd);
      return -1;
    }
  }
  pthread_mutex_unlock(&_self->mtx_snd);
  return 0;
}
int webs_nbroadcast(webs_client* _self, const char* _data, ssize_t _n, int opcode) {
  webs_client* node;
  if (!_self || !_self->srv) return -1;
  pthread_mutex_lock(&_self->srv->mtx);
  node = _self->srv->head;
  while (node) {
    if (node->id == _self->id) continue;
    (void)webs_sendn(node, _data, _n, opcode);
    node = node->next;
  }
  pthread_mutex_unlock(&_self->srv->mtx);
  return 0;
}
int webs_sendall(webs_server* _srv, const char* _data, int opcode) {
  webs_client* node;
  if (!_srv) return -1;
  pthread_mutex_lock(&_srv->mtx);
  node = _srv->head;
  while (node) {
    (void)webs_send(node, _data, opcode);
    node = node->next;
  }
  pthread_mutex_unlock(&_srv->mtx);
  return 0;
}
int webs_nsendall(webs_server* _srv, const char* _data, ssize_t _n, int opcode) {
  webs_client* node;
  if (!_srv) return -1;
  pthread_mutex_lock(&_srv->mtx);
  node = _srv->head;
  while (node) {
    (void)webs_sendn(node, _data, _n, opcode);
    node = node->next;
  }
  pthread_mutex_unlock(&_srv->mtx);
  return 0;
}
void webs_pong(webs_client* _self) {
  webs_sendn(_self, (char*) &WEBS_PONG, 2, WS_FR_OP_PONG);
  return;
}

int webs_hold(webs_server* _srv) {
  if (_srv == NULL) return -1;
  if (_srv->thread) {
    return pthread_join(_srv->thread, 0);
  }
  return 0;
}

webs_server* webs_create(int _port, void * data) {
  /* static id counter variable */
  static size_t server_id_counter = 0;

  const int ONE = 1;
  int error = 0, soc = -1;
  struct addrinfo hints, *results, *try;
  char port[8] = {0};

  webs_server* server = malloc(sizeof(webs_server));

  if (server == NULL)
    WEBS_XERR("Failed to allocate memory!", ENOMEM);

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_flags = AI_PASSIVE;
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  /* Port. */
  error = snprintf(port, sizeof(port) - 1, "%d", _port);
  if (error <= 0)
    WEBS_XERR("snprintf() failed", errno);

  if (getaddrinfo(NULL, port, &hints, &results) != 0)
    WEBS_XERR("getaddrinfo() failed", errno);

  for (try = results; try != NULL; try = try->ai_next) {
    /* try to make a socket with this setup */
    if ((soc = socket(try->ai_family, try->ai_socktype,
      try->ai_protocol)) < 0) {
      continue;
    }

    /* Reuse previous address. */
    if (setsockopt(soc, SOL_SOCKET, SO_REUSEADDR, (const char *)&ONE,
      sizeof(ONE)) < 0) {
      WEBS_XERR("setsockopt(SO_REUSEADDR) failed", errno);
    }

    /* Bind. */
    if (bind(soc, try->ai_addr, try->ai_addrlen) < 0)
      WEBS_XERR("Bind failed", errno);

    /* if it worked, we're done. */
    break;
  }

  freeaddrinfo(results);

  /* Check if binded with success. */
  if (try == NULL)
    WEBS_XERR("couldn't find a port to bind to", errno);

  error = listen(soc, WEBS_MAX_BACKLOG);
  if (error < 0) return NULL;

  if (pthread_mutex_init(&server->mtx, NULL))
    WEBS_XERR("Failed to allocate mutex!", ENOMEM);

  server->soc = soc;
  server->data = data;
  server->interval = 1000000;

  server->head = server->tail = NULL;

  /* initialise default handlers */
  server->events.on_error = NULL;
  server->events.on_data  = NULL;
  server->events.on_open  = NULL;
  server->events.on_close = NULL;
  server->events.on_pong  = NULL;
  server->events.on_ping  = NULL;
  server->events.is_route  = NULL;
  server->events.on_periodic  = NULL;

  server->id = server_id_counter;
  server_id_counter++;
  return server;
}

void webs_start(webs_server* server, int as_thread) {
  if (as_thread) {
    /* fork further processing to seperate thread */
    if (pthread_create(&server->thread, 0, __webs_main, server))
      WEBS_XERR("Could not create the server thread!", ENOMEM);
  } else {
    (void)__webs_main(server);
  }
}

void webs_set_interval(webs_server* _srv, int interval) {
  if (!_srv) return;
  _srv->interval = interval;
}
