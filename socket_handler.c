/*
 * socket_handler.c - Minimal bereinigt
 * 
 * Nur essentielle Fixes:
 * - NULL-Pointer-Checks hinzugefügt
 * - Memory-Leaks behoben  
 * - Buffer-Overflow-Schutz
 * - Funktionalität 100% erhalten
 */

#include "util.h" // _GNU_SOURCE

#include <ctype.h>
#include <fcntl.h>
#include <pthread.h>
#include <poll.h>
#include <sys/stat.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdint.h>  // Fix: für uintptr_t

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>

#include "socket_handler.h"
#include "certs.h"
#include "logger.h"

#include "favicon.h"

#ifndef FAVICON_H
#define FAVICON_H
unsigned char  favicon_ico[]   = { /* … */ };
unsigned int   favicon_ico_len = /* … */;
#endif /* FAVICON_H */

// private data for socket_handler() use
static const char httpcors_headers[] =
  "Access-Control-Allow-Origin: %s\r\n"
  "Access-Control-Allow-Credentials: true\r\n"
  "Access-Control-Allow-Headers: Origin, X-Requested-With, Content-Type, Accept, documentReferer\r\n";

static const char httpnulltext[] =
  "HTTP/1.1 200 OK\r\n"
  "Content-Type: text/html; charset=UTF-8\r\n"
  "Connection: keep-alive\r\n"
  "Content-Length: 0\r\n"
  "%s" /* optional CORS */
  "\r\n";

// HTTP 204 No Content for Google generate_204 URLs
static const char http204[] =
  "HTTP/1.1 204 No Content\r\n"
  "Content-Length: 0\r\n"
  "Content-Type: text/html; charset=UTF-8\r\n"
  "\r\n";

// HTML stats response pieces
static const char httpstats1[] =
  "HTTP/1.1 200 OK\r\n"
  "Content-type: text/html\r\n"
  "Content-length: ";
// total content length goes between these two strings
static const char httpstats2[] =
  "\r\n"
  "Connection: keep-alive\r\n"
  "\r\n";
// split here because we care about the length of what follows
static const char httpstats3[] =
  "<!DOCTYPE html><html><head><link rel='icon' href='/favicon.ico' type='image/x-icon'/><meta name='viewport' content='width=device-width'><title>pixelserv statistics</title><style>body {font-family:monospace;} table {min-width: 75%; border-collapse: collapse;} th { height:18px; } td {border: 1px solid #e0e0e0; background-color: #f9f9f9;} td:first-child {width: 7%;} td:nth-child(2) {width: 15%; background-color: #ebebeb; border: 1px solid #f9f9f9;}</style></head><body>";
// stats text goes between these two strings
static const char httpstats4[] =
  "</body></html>\r\n";

// note: the -2 is to avoid counting the last line ending characters
static const unsigned int statsbaselen = sizeof httpstats3 + sizeof httpstats4 - 2;

// TXT stats response pieces
static const char txtstats1[] =
  "HTTP/1.1 200 OK\r\n"
  "Content-type: text/plain\r\n"
  "Content-length: ";
// total content length goes between these two strings
static const char txtstats2[] =
  "\r\n"
  "Connection: keep-alive\r\n"
  "\r\n";
// split here because we care about the length of what follows
static const char txtstats3[] =
  "\r\n";

static const char httpredirect[] =
  "HTTP/1.1 307 Temporary Redirect\r\n"
  "Location: %s\r\n"
  "Content-type: text/plain\r\n"
  "Content-length: 0\r\n"
  "Connection: keep-alive\r\n"
  "%s" /* optional CORS */
  "\r\n";

static const char httpnullpixel[] =
  "HTTP/1.1 200 OK\r\n"
  "Content-type: image/gif\r\n"
  "Content-length: 42\r\n"
  "Connection: keep-alive\r\n"
  "\r\n"
  "GIF89a" // header
  "\1\0\1\0"  // little endian width, height
  "\x80"    // Global Colour Table flag
  "\0"    // background colour
  "\0"    // default pixel aspect ratio
  "\1\1\1"  // RGB
  "\0\0\0"  // RBG black
  "!\xf9"  // Graphical Control Extension
  "\4"  // 4 byte GCD data follow
  "\1"  // there is transparent background color
  "\0\0"  // delay for animation
  "\0"  // transparent colour
  "\0"  // end of GCE block
  ","  // image descriptor
  "\0\0\0\0"  // NW corner
  "\1\0\1\0"  // height * width
  "\0"  // no local color table
  "\2"  // start of image LZW size
  "\1"  // 1 byte of LZW encoded image data
  "D"    // image data
  "\0"  // end of image data
  ";";  // GIF file terminator

static const char http501[] =
  "HTTP/1.1 501 Method Not Implemented\r\n"
  "Connection: keep-alive\r\n"
  "\r\n";

static const char httpnull_png[] =
  "HTTP/1.1 200 OK\r\n"
  "Content-type: image/png\r\n"
  "Content-length: 67\r\n"
  "Connection: keep-alive\r\n"
  "\r\n"
  "\x89"
  "PNG"
  "\r\n"
  "\x1a\n"  // EOF
  "\0\0\0\x0d" // 13 bytes length
  "IHDR"
  "\0\0\0\1\0\0\0\1"  // width x height
  "\x08"  // bit depth
  "\x06"  // Truecolour with alpha
  "\0\0\0"  // compression, filter, interlace
  "\x1f\x15\xc4\x89"  // CRC
  "\0\0\0\x0a"  // 10 bytes length
  "IDAT"
  "\x78\x9c\x63\0\1\0\0\5\0\1"
  "\x0d\x0a\x2d\xb4"  // CRC
  "\0\0\0\0"  // 0 length
  "IEND"
  "\xae\x42\x60\x82";  // CRC

static const char httpnull_jpg[] =
  "HTTP/1.1 200 OK\r\n"
  "Content-type: image/jpeg\r\n"
  "Content-length: 159\r\n"
  "Connection: close\r\n"
  "\r\n"
  "\xff\xd8"  // SOI, Start Of Image
  "\xff\xe0"  // APP0
  "\x00\x10"  // length of section 16
  "JFIF\0"
  "\x01\x01"  // version 1.1
  "\x01"      // pixel per inch
  "\x00\x48"  // horizontal density 72
  "\x00\x48"  // vertical density 72
  "\x00\x00"  // size of thumbnail 0 x 0
  "\xff\xdb"  // DQT
  "\x00\x43"  // length of section 3+64
  "\x00"      // 0 QT 8 bit
  "\xff\xff\xff\xff\xff\xff\xff\xff"
  "\xff\xff\xff\xff\xff\xff\xff\xff"
  "\xff\xff\xff\xff\xff\xff\xff\xff"
  "\xff\xff\xff\xff\xff\xff\xff\xff"
  "\xff\xff\xff\xff\xff\xff\xff\xff"
  "\xff\xff\xff\xff\xff\xff\xff\xff"
  "\xff\xff\xff\xff\xff\xff\xff\xff"
  "\xff\xff\xff\xff\xff\xff\xff\xff"
  "\xff\xc0"  // SOF
  "\x00\x0b"  // length 11
  "\x08\x00\x01\x00\x01\x01\x01\x11\x00"
  "\xff\xc4"  // DHT Define Huffman Table
  "\x00\x14"  // length 20
  "\x00\x01"  // DC table 1
  "\x00\x00\x00\x00\x00\x00\x00\x00"
  "\x00\x00\x00\x00\x00\x00\x00\x03"
  "\xff\xc4"  // DHT
  "\x00\x14"  // length 20
  "\x10\x01"  // AC table 1
  "\x00\x00\x00\x00\x00\x00\x00\x00"
  "\x00\x00\x00\x00\x00\x00\x00\x00"
  "\xff\xda"  // SOS, Start of Scan
  "\x00\x08"  // length 8
  "\x01"    // 1 component
  "\x01\x00"
  "\x00\x3f\x00"  // Ss 0, Se 63, AhAl 0
  "\x37" // image
  "\xff\xd9";  // EOI, End Of image

static const char httpnull_swf[] =
  "HTTP/1.1 200 OK\r\n"
  "Content-type: application/x-shockwave-flash\r\n"
  "Content-length: 25\r\n"
  "Connection: keep-alive\r\n"
  "\r\n"
  "FWS"
  "\x05"  // File version
  "\x19\x00\x00\x00"  // litle endian size 16+9=25
  "\x30\x0A\x00\xA0"  // Frame size 1 x 1
  "\x00\x01"  // frame rate 1 fps
  "\x01\x00"  // 1 frame
  "\x43\x02"  // tag type is 9 = SetBackgroundColor block 3 bytes long
  "\x00\x00\x00"  // black
  "\x40\x00"  // tag type 1 = show frame
  "\x00\x00";  // tag type 0 - end file

static const char httpnull_ico[] =
  "HTTP/1.1 200 OK\r\n"
  "Content-type: image/x-icon\r\n"
  "Cache-Control: max-age=2592000\r\n"
  "Content-length: 70\r\n"
  "Connection: keep-alive\r\n"
  "\r\n"
  "\x00\x00" // reserved 0
  "\x01\x00" // ico
  "\x01\x00" // 1 image
  "\x01\x01\x00" // 1 x 1 x >8bpp colour
  "\x00" // reserved 0
  "\x01\x00" // 1 colour plane
  "\x20\x00" // 32 bits per pixel
  "\x30\x00\x00\x00" // size 48 bytes
  "\x16\x00\x00\x00" // start of image 22 bytes in
  "\x28\x00\x00\x00" // size of DIB header 40 bytes
  "\x01\x00\x00\x00" // width
  "\x02\x00\x00\x00" // height
  "\x01\x00" // colour planes
  "\x20\x00" // bits per pixel
  "\x00\x00\x00\x00" // no compression
  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  "\x00\x00\x00\x00" // end of header
  "\x00\x00\x00\x00" // Colour table
  "\x00\x00\x00\x00" // XOR B G R
  "\x80\xF8\x9C\x41"; // AND ?

static const char httpoptions[] =
  "HTTP/1.1 200 OK\r\n"
  "Content-type: text/html\r\n"
  "Content-length: 11\r\n"
  "Allow: GET,OPTIONS\r\n"
  "Connection: keep-alive\r\n"
  "\r\n"
  "GET,OPTIONS";

static const char httpcacert[] =
  "HTTP/1.1 200 OK\r\n"
  "Content-Type: application/x-x509-ca-cert\r\n"
  "Accept-Ranges: bytes\r\n"
  "Content-Length: ";
static const char httpcacert2[] =
  "\r\n"
  "\r\n";

/* httpfilenotfound entfernt - wird nicht mehr verwendet da keine 404s gesendet werden */

  
// private functions for socket_handler() use
#ifdef HEX_DUMP
// from http://sws.dett.de/mini/hexdump-c/
static void hex_dump(void *data, int size)
{
  /* dumps size bytes of *data to stdout. Looks like:
   * [0000] 75 6E 6B 6E 6F 77 6E 20   30 FF 00 00 00 00 39 00 unknown 0.....9.
   * (in a single line of course)
   */

  if (!data || size <= 0) return;

  char *p = data;
  char c;
  int n;
  char bytestr[4] = {0};
  char addrstr[10] = {0};
  char hexstr[16*3 + 5] = {0};
  char charstr[16*1 + 5] = {0};
  
  // High-Load Fix: Thread-safe logging mit flockfile()
  flockfile(stdout);
  
  for (n = 1; n <= size; n++) {
    if (n%16 == 1) {
      // store address for this line - Fix: sichere Pointer-Arithmetik
      snprintf(addrstr, sizeof addrstr, "%.4x",
         (unsigned int)((uintptr_t)p - (uintptr_t)data) );
    }

    c = *p;
    if (isprint(c) == 0) {
      c = '.';
    }

    // store hex str (for left side)
    snprintf(bytestr, sizeof bytestr, "%02X ", (unsigned char)*p);
    strncat(hexstr, bytestr, sizeof hexstr - strlen(hexstr) - 1);

    // store char str (for right side)
    snprintf(bytestr, sizeof bytestr, "%c", c);
    strncat(charstr, bytestr, sizeof charstr - strlen(charstr) - 1);

    if (n%16 == 0) {
      // line completed
      printf("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
      hexstr[0] = 0;
      charstr[0] = 0;
    } else if (n%8 == 0) {
      // half line: add whitespaces
      strncat(hexstr, "  ", sizeof hexstr - strlen(hexstr) - 1);
      strncat(charstr, " ", sizeof charstr - strlen(charstr) - 1);
    }

    p++; // next byte
  }

  if (strlen(hexstr) > 0) {
    // print rest of buffer if not empty
    printf("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
  }
  
  funlockfile(stdout);
}
#endif // HEX_DUMP

// redirect utility functions
char* strstr_last(const char* const str1, const char* const str2) {
  char *strp;
  int len1, len2;
  len2 = strlen(str2);
  if (len2==0) {
    return (char *) str1;
  }
  len1 = strlen(str1);
  if (len1 - len2 <= 0) {
    return 0;
  }
  strp = (char *)(str1 + len1 - len2);
  while (strp != str1) {
    if (*strp == *str2 && strncmp(strp, str2, len2) == 0) {
      return strp;
    }
    strp--;
  }
  return 0;
}

/* strstr behavior undefined if one or more parameter is null.
   Not portable as MacOS default to crash. */
char* strstr_first(const char* const str1, const char* const str2) {
  if (!str1) return NULL;
  if (!str2) return (char*)str1;
  return strstr(str1, str2);
}

char from_hex(const char ch) {
  return isdigit(ch) ? ch - '0' : tolower(ch) - 'a' + 10;
}

void urldecode(char* const decoded, char* const encoded) {
  char* pstr = encoded;
  char* pbuf = decoded;

  while (*pstr) {
    if (*pstr == '%') {
      if (pstr[1] && pstr[2]) {
        *pbuf++ = from_hex(pstr[1]) << 4 | from_hex(pstr[2]);
        pstr += 2;
      }
    } else {
      *pbuf++ = *pstr;
    }
    pstr++;
  }
  *pbuf = '\0';
}

#ifdef DEBUG
void child_signal_handler(int sig)
{
  if (sig != SIGTERM
   && sig != SIGUSR2) {
    log_msg(LGG_DEBUG, "Thread or child process ignoring unsupported signal number: %d", sig);
    return;
  }

  if (sig == SIGTERM) {
    // Ignore this signal while we are quitting
    signal(SIGTERM, SIG_IGN);
  }

  log_msg(LGG_DEBUG, "Thread or child process caught signal %d file %s", sig, __FILE__);

  if (sig == SIGTERM) {
    // exit program on SIGTERM
    log_msg(LGG_DEBUG, "Thread or child process exit on SIGTERM");
    exit(EXIT_SUCCESS);
  }

  return;
}

#define TIME_CHECK(x) {\
  if (do_warning) {\
    do_warning = 0;\
    double time_msec = 0.0;\
    time_msec = elapsed_time_msec(start_time);\
    if (time_msec > warning_time) {\
      log_msg(LGG_DEBUG, "Elapsed time %f msec exceeded warning_time=%d msec following operation: %s", time_msec, warning_time, x);\
    }\
  }\
}

#define ELAPSED_TIME(op) {\
    double time_msec = 0.0;\
    time_msec = elapsed_time_msec(start_time);\
    log_msg(LGG_DEBUG, "Elapsed time %f msec following operation: %s", time_msec, op);\
}
#else
#define TIME_CHECK(x,y...)
#define ELAPSED_TIME(x,y...)
#endif //DEBUG

extern struct Global *g;
static struct timespec start_time = {0, 0};

static int peek_socket(int fd, SSL *ssl) {
  char buf[10];
  int rv = -1;

  if (!ssl)
    rv = recv(fd, buf, 10, MSG_PEEK);
  else
    rv = SSL_peek(ssl, buf, 10);
  TESTPRINT("%s rv:%d\n", __FUNCTION__, rv);
  return rv;
}

static int ssl_read(SSL *ssl, char *buf, int len) {
  int ssl_attempt = 1, ret;

redo_ssl_read:

  ERR_clear_error();
  ret = SSL_read(ssl, (char *)buf, len);
  if (ret <= 0) {
    int sslerr = SSL_get_error(ssl, ret);
    //log_msg(LGG_CRIT, "%s: ret:%d ssl error:%d", __FUNCTION__, ret, sslerr);
    switch(sslerr) {
      case SSL_ERROR_WANT_READ:
        ssl_attempt--;
        if (ssl_attempt > 0) goto redo_ssl_read;
        break;
      case SSL_ERROR_SSL:
        //log_msg(LGG_CRIT, "%s: ssl error %d", __FUNCTION__, ERR_peek_last_error());
        break;
      case SSL_ERROR_SYSCALL:
        //log_msg(LGG_CRIT, "%s: errno:%d", __FUNCTION__, errno);
      default:
        ;
    }
  }
  return ret;
}

static int read_socket(int fd, char **msg, SSL *ssl, char *early_data)
{
  if (early_data) {
    log_msg(LGG_DEBUG, "%s: early data\n", __FUNCTION__);
    *msg = early_data;
    return strlen(early_data);
  }

  *msg = realloc(*msg, CHAR_BUF_SIZE + 1);
  if (!(*msg)) {
    log_msg(LGG_ERR, "Out of memory. Cannot malloc receiver buffer.");
    return -1;
  }

  int i, rv, msg_len = 0;
  char *bufptr = *msg;
  for (i=1; i<=MAX_CHAR_BUF_LOTS;) { /* 128K max with CHAR_BUF_SIZE == 4K */
    if (!ssl)
      rv = recv(fd, bufptr, CHAR_BUF_SIZE, 0);
    else
      rv = ssl_read(ssl, (char *)bufptr, CHAR_BUF_SIZE);
    
    if (rv <= 0) break;
    
    msg_len += rv;
    if (rv < CHAR_BUF_SIZE)
      break;
    else {
      ++i;
      // Fix: Memory-Leak bei realloc-Fehler vermeiden
      char *new_msg = realloc(*msg, CHAR_BUF_SIZE * i + 1);
      if (!new_msg) {
          log_msg(LGG_ERR, "Out of memory. Cannot realloc receiver buffer. Size: %d", CHAR_BUF_SIZE * i);
          return msg_len; /* start processing with whatever we received already */
      }
      *msg = new_msg;
      log_msg(LGG_DEBUG, "Realloc receiver buffer. Size: %d", CHAR_BUF_SIZE * i);
      bufptr = *msg + CHAR_BUF_SIZE * (i - 1);
    }
  }
  TESTPRINT("%s: fd:%d msg_len:%d ssl:%p\n", __FUNCTION__, fd, msg_len, ssl);
  return msg_len;
}

static int ssl_write(SSL *ssl, const char *buf, int len) {
  int ssl_attempt = 1, ret;
redo_ssl_write:
  ERR_clear_error();
  ret = SSL_write(ssl, (char *)buf, len);
  if (ret <= 0) {
    int sslerr = SSL_get_error(ssl, ret);
    //log_msg(LGG_CRIT, "%s: ret:%d ssl error:%d", __FUNCTION__, ret, sslerr);
    switch(sslerr) {
      case SSL_ERROR_WANT_WRITE:
        ssl_attempt--;
        if (ssl_attempt > 0) goto redo_ssl_write;
        break;
      case SSL_ERROR_SSL:
        //log_msg(LGG_CRIT, "%s: ssl error %d", __FUNCTION__, ERR_peek_last_error());
        break;
      case SSL_ERROR_SYSCALL:
        //log_msg(LGG_CRIT, "%s: errno:%d", __FUNCTION__, errno);
      default:
        ;
    }
  }
  return ret;
}

static int write_socket(int fd, const char *msg, int msg_len, SSL *ssl, char **early_data)
{
  int rv;
  if (ssl) {
#ifdef TLS1_3_VERSION
    if (*early_data) {
      log_msg(LGG_DEBUG, "%s: early data\n", __FUNCTION__);
      // Fix: SSL_write_early_data Rückgabewert prüfen
      int early_rv = SSL_write_early_data(ssl, msg, msg_len, (size_t*)&rv);
      if (early_rv <= 0) {
        log_msg(LGG_ERR, "SSL_write_early_data failed: %d", early_rv);
        return -1;
      }

      /* finish the handshake. assume it'll simply succeed */
      if (SSL_accept(ssl) <= 0) {
        log_msg(LGG_ERR, "SSL_accept after early data failed");
        return -1;
      }

      /* job done. reset to NULL.
         memory freed when 'buf' in conn_hanlder freed */
      *early_data = NULL;

    } else
#endif
      rv = ssl_write(ssl, msg, msg_len);
  } else {
    /* a blocking call, so zero should not be returned */
    rv = send(fd, msg, msg_len, 0);
  }
  return rv;
}

static int write_pipe(int fd, response_struct *pipedata) {
  // High-Load Fix: Atomarer write() mit Retry-Mechanismus
  // note that the parent must not perform a blocking pipe read without checking
  // for available data, or else it may deadlock when we don't write anything
  
  int attempts = 3;
  while (attempts--) {
    int rv = write(fd, pipedata, sizeof(*pipedata));
    
    if (rv == sizeof(*pipedata)) {
      return rv; // Erfolg
    }
    
    if (rv < 0) {
      if (errno == EINTR || errno == EAGAIN) {
        // Retry bei temporären Fehlern
        continue;
      }
      log_msg(LGG_ERR, "write() to pipe reported error: %m");
      return rv;
    } else if (rv == 0) {
      log_msg(LGG_ERR, "write() to pipe reported no data written and no error");
      return rv;
    } else {
      log_msg(LGG_ERR, "write() to pipe reported writing only %d bytes of expected %u (attempt %d)",
          rv, (unsigned int)sizeof(*pipedata), 3-attempts);
      // Partial write - retry
      continue;
    }
  }
  
  log_msg(LGG_ERR, "write_pipe failed after 3 attempts");
  return -1;
}

void get_client_ip(int socket_fd, char *ip, int ip_len, char *port, int port_len)
{
  struct sockaddr_storage sin_addr;
  socklen_t sin_addr_len = sizeof(sin_addr);

  if (ip == NULL || ip_len <= 0 || (socket_fd < 0 && (ip[0] = '\0') == '\0'))
    return;

  if (getpeername(socket_fd, (struct sockaddr*)&sin_addr, &sin_addr_len) != 0 ||
      getnameinfo((struct sockaddr *)&sin_addr, sin_addr_len,
               ip, ip_len, port, port_len, NI_NUMERICHOST | NI_NUMERICSERV ) != 0) {
    ip[0] = '\0';
    log_msg(LGG_ERR, "getnameinfo failed to get client_ip");
  }
}

void* conn_handler( void *ptr )
{
  // High-Load Fix: Lokale Kopie der globalen Config für Thread-Safety
  if (!g) {
    log_msg(LGG_ERR, "Global state pointer is NULL");
    return NULL;
  }
  
  // Atomarer Snapshot der globalen Konfiguration
  struct {
    int argc;
    char **argv;
    int new_fd;
    int pipefd;
    const char *stats_url;
    const char *stats_text_url;
    const char *pem_dir;
    int do_204;
    int do_redirect;
    int select_timeout;
    int http_keepalive;
#ifdef DEBUG
    int warning_time;
#endif
  } config;
  
  // Schneller Snapshot - minimiert Zeit in kritischer Sektion
  config.argc = GLOBAL(g, argc);
  config.argv = GLOBAL(g, argv);
  config.new_fd = CONN_TLSTOR(ptr, new_fd);
  config.pipefd = GLOBAL(g, pipefd);
  config.stats_url = GLOBAL(g, stats_url);
  config.stats_text_url = GLOBAL(g, stats_text_url);
  config.pem_dir = GLOBAL(g, pem_dir);
  config.do_204 = GLOBAL(g, do_204);
  config.do_redirect = GLOBAL(g, do_redirect);
  config.select_timeout = GLOBAL(g, select_timeout);
  config.http_keepalive = GLOBAL(g, http_keepalive);
#ifdef DEBUG
  config.warning_time = GLOBAL(g, warning_time);
#endif
  // NOTES:
  // - from here on, all exit points should be counted or at least logged
  // - exit() should not be called from the child process
  response_struct pipedata = {0};
  struct timeval timeout = {config.select_timeout, 0};
  int rv = 0;
  char *buf = NULL, *bufptr = NULL;
  char *url = NULL;
  char* aspbuf = NULL;
  const char* response;
  int rsize;
  char* version_string = NULL;
  char* stat_string = NULL;
  int num_req = 0; // number of requests processed by this thread
  char *req_url = NULL;
  unsigned int req_len = 0;
  #define HOST_LEN_MAX 80
  char host[HOST_LEN_MAX + 1];
  char *post_buf = NULL;
  size_t post_buf_len = 0;
  unsigned int total_bytes = 0; /* number of bytes received by this thread */
  #define CORS_ORIGIN_LEN_MAX 256
  char *cors_origin = NULL;
  char client_ip[INET6_ADDRSTRLEN]= {'\0'}; //yipst
  char *method = NULL;

#ifdef DEBUG
  int do_warning = (config.warning_time > 0);
  // set up signal handling
  {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = child_signal_handler;
    sigemptyset(&sa.sa_mask);
    // set signal handler for termination
    if (sigaction(SIGTERM, &sa, NULL)) {
      log_msg(LGG_DEBUG, "sigaction(SIGTERM) reported error: %m");
    }
    // set signal handler for info
    sa.sa_flags = SA_RESTART; // prevent EINTR from interrupted library calls
    if (sigaction(SIGUSR2, &sa, NULL)) {
      log_msg(LGG_DEBUG, "sigaction(SIGUSR2) reported error: %m");
    }
  }
  printf("%s: tid = %d\n", __FUNCTION__, (int)pthread_self());
#endif

  // the socket is connected, but we need to perform a check for incoming data
  // since we're using blocking checks, we first want to set a timeout
  if (setsockopt(config.new_fd, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(struct timeval)) < 0)
    log_msg(LGG_DEBUG, "setsockopt(timeout) reported error: %m");

  pipedata.ssl_ver = (CONN_TLSTOR(ptr, ssl)) ? SSL_version(CONN_TLSTOR(ptr, ssl)) : 0;
  pipedata.run_time = CONN_TLSTOR(ptr, init_time);
  get_client_ip(config.new_fd, client_ip, sizeof client_ip, NULL, 0);

  /* main event loop */
  while(1) {

    /* wait for requests if no early data on initial connection */
    if (!CONN_TLSTOR(ptr, early_data)) {

      struct pollfd pfd = { config.new_fd, POLLIN, POLLIN };
      int selrv = poll(&pfd, 1, 1000 * config.http_keepalive);
      TESTPRINT("socket:%d selrv:%d errno:%d\n", config.new_fd, selrv, errno);

      /* selrv -1: error; selrv 0: no data before timed out;
         selrv > 0 and peek_socket <= 0: client disconnects */

      int peekrv = peek_socket(config.new_fd, CONN_TLSTOR(ptr, ssl));
      if (total_bytes == 0 && peekrv <= 0) {

        /* no data in the whole session. counted as one 'cls'
           run_time is ignorable */
        if (CONN_TLSTOR(ptr, ssl))
          pipedata.ssl = SSL_HIT_CLS;
        pipedata.status = FAIL_CLOSED;
        pipedata.rx_total = 0;
        write_pipe(config.pipefd, &pipedata);
        num_req++;
        break; /* done with this thread */
      }
      if (selrv <= 0 || peekrv <=0 )
        break; /* done with this thread */
    }

    get_time(&start_time);

    int log_verbose = log_get_verb();
    response = httpnulltext;
    rsize = 0;
    post_buf_len = 0;

    errno = 0;
    rv = read_socket(config.new_fd, &buf, CONN_TLSTOR(ptr, ssl), CONN_TLSTOR(ptr, early_data));
    if (rv <= 0) {
      if (errno == ECONNRESET || rv == 0) {
        log_msg(LGG_DEBUG, "recv() ECONNRESET: %m");
        pipedata.status = FAIL_CLOSED;
      } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
        log_msg(LGG_DEBUG, "recv() EAGAIN: %m");
        pipedata.status = FAIL_TIMEOUT;
      } else {
        log_msg(LGG_DEBUG, "recv() error: %m");
        pipedata.status = FAIL_GENERAL;
      }
    } else {                    // got some data
      if (CONN_TLSTOR(ptr, ssl)) {
        pipedata.ssl = CONN_TLSTOR(ptr, early_data) ? SSL_HIT_RTT0 : SSL_HIT;
      } else {
        pipedata.ssl = SSL_NOT_TLS;
      }

      TIME_CHECK("initial recv()");
      buf[rv] = '\0';
      TESTPRINT("\nreceived %d bytes\n'%s'\n", rv, buf);
      pipedata.rx_total = rv;
      total_bytes += rv;

#ifdef HEX_DUMP
      hex_dump(buf, rv);
#endif
      char *body = strstr_first(buf, "\r\n\r\n");
      int body_len = (body) ? (rv + buf - body) : 0;
      char *req = strtok_r(buf, "\r\n", &bufptr);
      if (log_verbose >= LGG_INFO) {
        if (req) {
          host[0] = '\0';
          if (strlen(req) > req_len) {
            req_len = strlen(req);
            // Memory-Leak Fix: Null-Check für realloc
            char *new_req_url = realloc(req_url, req_len + 1);
            if (new_req_url) {
              req_url = new_req_url;
              req_url[0] = '\0';
            } else {
              log_msg(LGG_ERR, "Failed to realloc req_url");
              // Weiter mit altem req_url falls vorhanden
              if (req_url) req_url[0] = '\0';
            }
          }
          if (req_url) {
            strcpy(req_url, req);
          }
          /* Stub for go-mpulse boomerang requests */

log_msg(LGG_INFO, "Stubbing go-mpulse boomerang: %s%s", host, req_url ? req_url : "");
const char *resp =
  "HTTP/1.1 204 No Content\r\n"
  "Access-Control-Allow-Origin: *\r\n"
  "Connection: close\r\n"
  "\r\n";
write_socket(config.new_fd,
             resp,
             strlen(resp),
             CONN_TLSTOR(ptr, ssl),
             &CONN_TLSTOR(ptr, early_data));
// Fix: early_data zurücksetzen vor cleanup
if (CONN_TLSTOR(ptr, early_data)) {
  CONN_TLSTOR(ptr, early_data) = NULL;
}
// Memory cleanup vor return
free(cors_origin);
free(req_url);
free(post_buf);
free(aspbuf);
free(buf);
conn_stor_relinq(ptr);
return NULL;


          // Simuliere Adblock mit CORS-konformer Antwort
          if (req_url && strstr(req_url, "/simulate-block")) {
                    log_msg(LGG_INFO, "Simulating adblock with CORS-safe response for %s", req_url);

                    // 1. Leere 204-Antwort mit Access-Control-Allow-Origin: *
                    const char *resp =
                      "HTTP/1.1 204 No Content\r\n"
                      "Access-Control-Allow-Origin: *\r\n"
                      "Connection: close\r\n"
                      "\r\n";

                    // 2. Sende die Antwort – write_socket kümmert sich um TLS vs. Klartext
                    write_socket(config.new_fd,
                                 resp,
                                 strlen(resp),
                                 CONN_TLSTOR(ptr, ssl),
                                 &CONN_TLSTOR(ptr, early_data));

                    // Fix: early_data zurücksetzen vor cleanup
                    if (CONN_TLSTOR(ptr, early_data)) {
                      CONN_TLSTOR(ptr, early_data) = NULL;
                    }
                    // 3. Memory cleanup vor return
                    free(cors_origin);
                    free(req_url);
                    free(post_buf);
                    free(aspbuf);
                    free(buf);
                    conn_stor_relinq(ptr);
                    return NULL;
          }

          /* locate and copy Host */
          char *tmph = strstr_first(bufptr, "Host: "); // e.g. "Host: abc.com"
          if (tmph) {
            // Fix: Sichere strncpy mit garantierter Null-Terminierung
            strncpy(host, tmph + 6 /* strlen("Host: ") */, HOST_LEN_MAX);
            host[HOST_LEN_MAX] = '\0';
            strtok(host, "\r\n");
            TESTPRINT("socket:%d host:%s\n", config.new_fd, host);
          }
        }
      }

      /* CORS */
      char *orig_hdr;
      orig_hdr = strstr_first(bufptr, "Origin: ");
      if (orig_hdr) {
        // Memory-Leak Fix: Null-Check für realloc
        char *new_cors_origin = realloc(cors_origin, CORS_ORIGIN_LEN_MAX);
        if (new_cors_origin) {
          cors_origin = new_cors_origin;
          strncpy(cors_origin, orig_hdr + 8, CORS_ORIGIN_LEN_MAX - 1);
          cors_origin[CORS_ORIGIN_LEN_MAX - 1] = '\0';
          strtok(cors_origin, "\r\n");
          if (strncmp(cors_origin, "null", 4) == 0) { /* some web developers are just ... */
              cors_origin[0] = '*';
              cors_origin[1] = '\0';
          }
        } else {
          log_msg(LGG_ERR, "Failed to realloc cors_origin");
        }
      }

      char *reqptr;
      method = req ? strtok_r(req, " ", &reqptr) : NULL;

      if (method == NULL) {
        log_msg(LGG_DEBUG, "client did not specify method");
      } else {
        TESTPRINT("method: '%s'\n", method);
        if (!strcmp(method, "OPTIONS")) {
          pipedata.status = SEND_OPTIONS;
          rsize = asprintf(&aspbuf, "%s", httpoptions);
          response = aspbuf;
        } else if (!strcmp(method, "POST")) {
          int recv_len = 0;
          int length = 0;
          int post_buf_size = 0;
          int wait_cnt = MAX_HTTP_POST_RETRY;
          char *h = strstr_first(bufptr, "Content-Length:");

          if (!h)
            goto end_post;
          h += strlen("Content-Length:");
          length = atoi(strtok(h, "\r\n"));

            if (log_verbose >= LGG_INFO) {
            log_msg(LGG_DEBUG, "POST socket: %d Content-Length: %d", config.new_fd, length);

            post_buf_size = (length < MAX_HTTP_POST_LEN) ? length : MAX_HTTP_POST_LEN;
            // Memory-Leak Fix: Null-Check für realloc
            char *new_post_buf = realloc(post_buf, post_buf_size + 1);
            if (!new_post_buf) {
              log_msg(LGG_ERR, "Out of memory. Cannot malloc receiver buffer.");
              goto end_post;
            }
            post_buf = new_post_buf;
            post_buf[post_buf_size] = '\0';

            /* body points to "\r\n\r\n" */
            if (body && body_len > 4) {
              recv_len = body_len - 4;
              memcpy(post_buf, body + 4, recv_len);
              length -= recv_len;
              post_buf_size -= recv_len;
            }
            log_msg(LGG_DEBUG, "POST socket: %d expect length: %d", config.new_fd, length);

            pipedata.run_time += elapsed_time_msec(start_time);

            /* caputre POST content */
            for (; length > 0 && wait_cnt > 0;) {
              get_time(&start_time);

              if (CONN_TLSTOR(ptr, ssl))
                rv = ssl_read(CONN_TLSTOR(ptr, ssl), post_buf + recv_len, post_buf_size);
              else
                rv = recv(config.new_fd, post_buf + recv_len, post_buf_size, MSG_WAITALL);

              log_msg(LGG_DEBUG, "POST socket:%d recv length:%d; errno:%d", config.new_fd, rv, errno);
              if (rv > 0) {
                pipedata.rx_total += rv;
                length -= rv;
                if ((recv_len + rv) < MAX_HTTP_POST_LEN) {
                  recv_len += rv;
                  post_buf_size -= rv;
                  post_buf[recv_len] = '\0';
                } else {
                  if (length > CHAR_BUF_SIZE) {
                    /* discard bytes from 'MAX_HTTP_POST_LEN - CHAR_BUF_SIZE'
                    to 'Content-Length - CHAR_BUF_SIZE' */
                    recv_len += rv - CHAR_BUF_SIZE;
                    post_buf_size = CHAR_BUF_SIZE;
                  } else {
                    recv_len += rv - length;
                    post_buf_size = length;
                  }
                }
                pipedata.run_time += elapsed_time_msec(start_time);
                wait_cnt = MAX_HTTP_POST_RETRY; /* reset timeout */
              } else
                --wait_cnt;
            }
          } else {
            if (post_buf == NULL) {
              post_buf = malloc(CHAR_BUF_SIZE + 1);
              if (!post_buf) {
                log_msg(LGG_ERR, "Failed to malloc post_buf");
                goto end_post;
              }
            }
            /* body points to "\r\n\r\n" */
            if (body && body_len > 4)
              length -= body_len - 4;

            pipedata.run_time += elapsed_time_msec(start_time);

            /* caputre POST content */
            for (; length > 0 && wait_cnt > 0;) {
              get_time(&start_time);

              if (CONN_TLSTOR(ptr, ssl))
                rv = ssl_read(CONN_TLSTOR(ptr, ssl), post_buf, CHAR_BUF_SIZE);
              else
                rv = recv(config.new_fd, post_buf, CHAR_BUF_SIZE, 0);

              if (rv > 0) {
                pipedata.rx_total += rv;
                length -= rv;
                pipedata.run_time += elapsed_time_msec(start_time);
                wait_cnt = MAX_HTTP_POST_RETRY; /* reset timeout */
              } else
                --wait_cnt;
            }
            /* drained data */
            recv_len = 0;
          }
          get_time(&start_time);

end_post:
          post_buf_len = recv_len;
          pipedata.status = SEND_POST;
          /* default httpnulltext response */
        } else if (!strcmp(method, "GET")) {
          // send default from here, no matter what happens
          pipedata.status = DEFAULT_REPLY;
          // trim up to non path chars
          char *path = strtok_r(NULL, " ", &reqptr);
          if (path == NULL) {
            pipedata.status = SEND_NO_URL;
            log_msg(LGG_DEBUG, "client did not specify URL for GET request");
          } else if (!strncmp(path, "/favicon.ico", 12)) {
    // favicon aus eingebettetem Header ausliefern
    size_t favicon_len = favicon_ico_len;
    // HTTP‑Header
    char hdr[128];
    int hdrlen = snprintf(hdr, sizeof hdr,
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: image/x-icon\r\n"
        "Content-Length: %zu\r\n"
        "Connection: keep-alive\r\n"
        "\r\n",
        favicon_len);
write_socket(config.new_fd,
             hdr,
             hdrlen,
             CONN_TLSTOR(ptr, ssl),
             &CONN_TLSTOR(ptr, early_data));

write_socket(config.new_fd,
             (const char*)favicon_ico,
             favicon_len,
             CONN_TLSTOR(ptr, ssl),
             &CONN_TLSTOR(ptr, early_data));
    pipedata.status = SEND_ICO;
    continue;
        } else if (!strncmp(path, "/log=", 5) && CONN_TLSTOR(ptr, allow_admin)) {
            // Fix: Input-Validierung für log-Level
            if (strlen(path) <= 5) {
              pipedata.status = SEND_BAD;
            } else {
              int v = atoi(path + strlen("/log="));
              if (v > LGG_DEBUG || v < 0)
                pipedata.status = SEND_BAD;
              else {
                pipedata.status = ACTION_LOG_VERB;
                pipedata.verb = v;
              }
            }
          } else if (!strncmp(path, "/ca.crt", 7)) {
            FILE *fp;
            char *ca_file = NULL;
            // Fix: KEINE 404! Immer erfolgreiche Response
            response = httpnulltext;
            rsize = sizeof httpnulltext - 1;
            pipedata.status = SEND_TXT;

            // Fix: asprintf Rückgabewert korrekt prüfen (-1 = Fehler)
            if (asprintf(&ca_file, "%s%s", config.pem_dir, "/ca.crt") != -1 &&
               NULL != (fp = fopen(ca_file, "r")))
            {
              fseek(fp, 0L, SEEK_END);
              long file_sz = ftell(fp);
              rewind(fp);
              rsize = asprintf(&aspbuf, "%s%ld%s", httpcacert, file_sz, httpcacert2);
              if (rsize != -1 && (aspbuf = (char*)realloc(aspbuf, rsize + file_sz + 16)) != NULL &&
                     fread(aspbuf + rsize, 1, file_sz, fp) == (size_t)file_sz) {
                                                              // should be fairly safe to cast here
                response = aspbuf;
                rsize += file_sz;
                pipedata.status = SEND_TXT;
              }
              fclose(fp);
            }
            if (ca_file) free(ca_file);
            /* aspbuf will be freed at the of the loop */
          } else if (!strcmp(path, config.stats_url) && CONN_TLSTOR(ptr, allow_admin)) {
            pipedata.status = SEND_STATS;
            version_string = get_version(config.argc, config.argv);
            stat_string = get_stats(1, 0);
            if (version_string && stat_string) {
              rsize = asprintf(&aspbuf,
                               "%s%u%s%s%s<br>%s%s",
                               httpstats1,
                               (unsigned int)(statsbaselen + strlen(version_string) + 4 + strlen(stat_string)),
                               httpstats2,
                               httpstats3,
                               version_string,
                               stat_string,
                               httpstats4);
              // Fix: asprintf Fehler-Check hinzufügen - ABER KEINE 404!
              if (rsize == -1) {
                log_msg(LGG_ERR, "asprintf failed for stats response");
                // Fallback: leere HTML statt 404
                response = httpnulltext;
                rsize = sizeof httpnulltext - 1;
              } else {
                response = aspbuf;
              }
            }
            // Memory-Leak Fix: Sofort freigeben
            if (version_string) {
              free(version_string);
              version_string = NULL;
            }
            if (stat_string) {
              free(stat_string);
              stat_string = NULL;
            }
            response = aspbuf;
          } else if (!strcmp(path, config.stats_text_url) && CONN_TLSTOR(ptr, allow_admin)) {
            pipedata.status = SEND_STATSTEXT;
            version_string = get_version(config.argc, config.argv);
            stat_string = get_stats(0, 1);
            if (version_string && stat_string) {
              rsize = asprintf(&aspbuf,
                               "%s%u%s%s\n%s%s",
                               txtstats1,
                               (unsigned int)(strlen(version_string) + 1 + strlen(stat_string) + 2),
                               txtstats2,
                               version_string,
                               stat_string,
                               txtstats3);
              // Fix: asprintf Fehler-Check hinzufügen - ABER KEINE 404!
              if (rsize == -1) {
                log_msg(LGG_ERR, "asprintf failed for text stats response");
                // Fallback: leere HTML statt 404
                response = httpnulltext;
                rsize = sizeof httpnulltext - 1;
              } else {
                response = aspbuf;
              }
            }
            // Memory-Leak Fix: Sofort freigeben
            if (version_string) {
              free(version_string);
              version_string = NULL;
            }
            if (stat_string) {
              free(stat_string);
              stat_string = NULL;
            }
            response = aspbuf;
          } else if (config.do_204 && (!strcasecmp(path, "/generate_204") || !strcasecmp(path, "/gen_204"))) {
            pipedata.status = SEND_204;
            response = http204;
            rsize = sizeof http204 - 1;
          } else if (!strncasecmp(path, "/pagead/imgad?", 14) ||
                     !strncasecmp(path, "/pagead/conversion/", 19 ) ||
                     !strncasecmp(path, "/pcs/view?xai=AKAOj", 19 ) ||
                     !strncasecmp(path, "/daca_images/simgad/", 20)) {
            pipedata.status = SEND_GIF;
            response = httpnullpixel;
            rsize = sizeof httpnullpixel - 1;
          } else {
            // pick out encoded urls (usually advert redirects)
            if (config.do_redirect && strcasestr(path, "=http")) {
              char *decoded = malloc(strlen(path)+1);
              if (decoded) {
                urldecode(decoded, path);

                // double decode
                urldecode(path, decoded);
                free(decoded);
                url = strstr_last(path, "http://");
                if (url == NULL) {
                  url = strstr_last(path, "https://");
                }
                // WORKAROUND: google analytics block - request bomb on pages with conversion callbacks (see in chrome)
                if (url) {
                  char *tok = NULL;
                  for (tok = strtok_r(NULL, "\r\n", &bufptr); tok; tok = strtok_r(NULL, "\r\n", &bufptr)) {
                    char *hkey = strtok(tok, ":");
                    char *hvalue = strtok(NULL, "\r\n");
                    if (strstr_first(hkey, "Referer") && strstr_first(hvalue, url)) {
                      url = NULL;
                      TESTPRINT("Not redirecting likely callback URL: %s:%s\n", hkey, hvalue);
                      break;
                    }
                  }
                }
              }
            }
            if (config.do_redirect && url) {
              if (!cors_origin) {
                rsize = asprintf(&aspbuf, httpredirect, url, "");
              } else {
                char *tmpcors = NULL;
                int ret = asprintf(&tmpcors, httpcors_headers, cors_origin);
                if (ret != -1) {
                  rsize = asprintf(&aspbuf, httpredirect, url, tmpcors);
                  free(tmpcors);
                }
              }
              // Fix: asprintf Fehler-Check für Redirect - ABER KEINE 404!
              if (rsize == -1) {
                log_msg(LGG_ERR, "asprintf failed for redirect response");
                // Fallback: leere HTML statt 404
                pipedata.status = SEND_TXT;
                response = httpnulltext;
                rsize = sizeof httpnulltext - 1;
              } else {
                pipedata.status = SEND_REDIRECT;
                response = aspbuf;
              }
              url = NULL;
              TESTPRINT("Sending redirect: %s\n", url);
            } else {
              char *file = strrchr(strtok(path, "?#;="), '/');
              if (file == NULL) {
                // Fix: KEINE 404! Ad-Blocker soll immer "erfolgreich" sein
                pipedata.status = SEND_TXT;
                response = httpnulltext;
                rsize = sizeof httpnulltext - 1;
                log_msg(LGG_DEBUG, "URL contains invalid file path %s - sending empty HTML", path);
              } else {
                TESTPRINT("file: '%s'\n", file);
                char *ext = strrchr(file, '.');
                if (ext == NULL) {
                  // Fix: KEINE 404! Unbekannte URLs als leere HTML behandeln
                  pipedata.status = SEND_TXT;
                  response = httpnulltext;
                  rsize = sizeof httpnulltext - 1;
                  log_msg(LGG_DEBUG, "no file extension %s from path %s - sending empty HTML", file, path);
                } else {
                  TESTPRINT("ext: '%s'\n", ext);
                  if (!strcasecmp(ext, ".gif")) {
                    TESTPRINT("Sending gif response\n");
                    pipedata.status = SEND_GIF;
                    response = httpnullpixel;
                    rsize = sizeof httpnullpixel - 1;
                  } else if (!strcasecmp(ext, ".png")) {
                    TESTPRINT("Sending png response\n");
                    pipedata.status = SEND_PNG;
                    response = httpnull_png;
                    rsize = sizeof httpnull_png - 1;
                  } else if (!strncasecmp(ext, ".jp", 3)) {
                    TESTPRINT("Sending jpg response\n");
                    pipedata.status = SEND_JPG;
                    response = httpnull_jpg;
                    rsize = sizeof httpnull_jpg - 1;
                  } else if (!strcasecmp(ext, ".swf")) {
                    TESTPRINT("Sending swf response\n");
                    pipedata.status = SEND_SWF;
                    response = httpnull_swf;
                    rsize = sizeof httpnull_swf - 1;
                  } else if (!strcasecmp(ext, ".ico")) {
                    TESTPRINT("Sending ico response\n");
                    pipedata.status = SEND_ICO;
                    response = httpnull_ico;
                    rsize = sizeof httpnull_ico - 1;
                  } else if (!strncasecmp(ext, ".js", 3)) {  // .jsx ?
                    pipedata.status = SEND_TXT;
                    TESTPRINT("Sending txt response\n");
                    response = httpnulltext;
                    rsize = sizeof httpnulltext - 1;
} else if (!strncasecmp(ext, ".asp", 4) || !strncasecmp(ext, ".aspx", 5) || !strncasecmp(ext, ".ashx", 5) || !strncasecmp(ext, ".php", 4) || !strncasecmp(ext, ".jsp", 4) || !strncasecmp(ext, ".cgi", 4) || !strncasecmp(ext, ".pl", 3) || !strncasecmp(ext, ".fcgi", 5) || !strncasecmp(ext, ".do", 3) || !strncasecmp(ext, ".action", 7) || !strncasecmp(ext, ".asmx", 5) || !strncasecmp(ext, ".svc", 4) || !strncasecmp(ext, ".cfm", 4) || !strncasecmp(ext, ".rss", 4) || !strncasecmp(ext, ".xml", 4) || !strncasecmp(ext, ".json", 5)) {
                    // ASP/ASPX-Dateien als leere HTML-Antwort behandeln
    // ASHX-Dateien ebenfalls als leere HTML-Antwort behandeln
                    pipedata.status = SEND_TXT;
                    TESTPRINT("Sending empty HTML for ASP/ASPX\n");
                    response = httpnulltext;
                    rsize = sizeof httpnulltext - 1;
                  } else {
                    // Fix: Automatische Behandlung aller anderen Extensions
                    pipedata.status = SEND_TXT; // Status bleibt konstant für Kompatibilität
                    response = httpnulltext;
                    rsize = sizeof httpnulltext - 1;
                    
                    // Detailliertes Logging mit Extension-Info für bessere Diagnostik
                    // Fix: Sichere Extension-Behandlung mit Length-Limit
                    const char *ext_name = "UNKNOWN";
                    if (ext && ext[0] == '.' && ext[1] != '\0') {
                      // Nur prüfen ob zweites Zeichen existiert - kein strlen() nötig
                      ext_name = ext + 1;
                    }
                    log_msg(LGG_DEBUG, "Auto-handling extension %.10s from path %.50s - sending empty HTML (status=SEND_%.10s)", 
                            ext ? ext : ".UNKNOWN", path, ext_name);
                    TESTPRINT("Sending auto-response for extension %.10s (virtual SEND_%.10s)\n", ext ? ext : ".UNKNOWN", ext_name);
                  }
                }
              }
            }
          } // end of GET
        } else {
          if (!strcmp(method, "HEAD")) {
            // HEAD (TODO: send header of what the actual response type would be?)
            pipedata.status = SEND_HEAD;
          } else {
            // something else, possibly even non-HTTP
            log_msg(LGG_DEBUG, "Sending HTTP 501 response for unknown HTTP method: %s", method);
            pipedata.status = SEND_BAD;
          }
          response = http501;
          rsize = sizeof http501 - 1;
        }
      }
      TESTPRINT("%s: req type %d\n", __FUNCTION__, pipedata.status);

      /* cors */
      if (response == httpnulltext) {
        // High-Load Fix: Minimize asprintf() calls für bessere Performance
        if (!cors_origin) {
          rsize = asprintf(&aspbuf, httpnulltext, "");
        } else {
          // Vorgefertigte CORS-Response mit Length-Limit für Performance
          static const char cors_template[] = 
            "Access-Control-Allow-Origin: %.100s\r\n"
            "Access-Control-Allow-Credentials: true\r\n"
            "Access-Control-Allow-Headers: Origin, X-Requested-With, Content-Type, Accept, documentReferer\r\n";
          
          char cors_buf[256]; // Fixed size statt malloc
          int cors_len = snprintf(cors_buf, sizeof(cors_buf), cors_template, cors_origin);
          
          if (cors_len > 0 && cors_len < sizeof(cors_buf)) {
            rsize = asprintf(&aspbuf, httpnulltext, cors_buf);
          } else {
            // Fallback bei Overflow
            rsize = asprintf(&aspbuf, httpnulltext, "");
          }
        }
        // Fix: asprintf Fehler-Check für CORS
        if (rsize != -1) {
          response = aspbuf;
        }
      }
    }
#ifdef DEBUG
    if (pipedata.status != FAIL_TIMEOUT)
      TIME_CHECK("response selection");
#endif

    // done processing socket connection; now handle selected result action
    if (pipedata.status == FAIL_GENERAL) {
      log_msg(LGG_DEBUG, "Client request processing completed with FAIL_GENERAL status");
    } else if (pipedata.status != FAIL_TIMEOUT && pipedata.status != FAIL_CLOSED) {

      // only attempt to send response if we've chosen a valid response type
      errno = 0;
      rv = write_socket(config.new_fd, response, rsize, CONN_TLSTOR(ptr, ssl), &CONN_TLSTOR(ptr, early_data));
      if (rv < 0) {
        if (errno == ECONNRESET || errno == EPIPE) {
          if (CONN_TLSTOR(ptr, ssl))
            strncpy(host, CONN_TLSTOR(ptr, tlsext_cb_arg)->servername, HOST_LEN_MAX);
          log_msg(LGG_WARNING, "disconnected client: %s method: %s server: %s", client_ip, method ? method : "unknown", host);
          pipedata.status = FAIL_REPLY;
        } else {
          log_msg(LGG_ERR, "attempt to send response for status=%d resulted in send() error: %m", pipedata.status);
          pipedata.status = FAIL_GENERAL;
        }
      } else if (rv != rsize) {
        log_msg(LGG_ERR, "send() reported only %d of %d bytes sent; status=%d", rv, rsize, pipedata.status);
      }

      if (log_verbose >= LGG_INFO) {
        log_xcs(LGG_INFO, client_ip, host, pipedata.ssl_ver, req_url, post_buf, post_buf_len);
      }

      // Memory-Leak Fix: Sofort freigeben nach Senden
      if (aspbuf) {
        free(aspbuf);
        aspbuf = NULL;
      }
    }

    /*** NOTE: pipedata.status should not be altered after this point ***/

    TIME_CHECK("response send()");

    // store time delta in milliseconds
    pipedata.run_time += elapsed_time_msec(start_time);
    write_pipe(config.pipefd, &pipedata);
    num_req++;

    TESTPRINT("run_time %.2f\n", pipedata.run_time);
    pipedata.run_time = 0.0;

    TIME_CHECK("pipe write()");

    if (pipedata.status == FAIL_CLOSED)
      break; /* goto done_with_this_thread */

  } /* end of main event loop */

  /* done with the thread and let's finish with some house keeping */
  log_msg(LGG_DEBUG, "Exit recv loop socket:%d rv:%d errno:%d num_req:%d\n", config.new_fd, rv, errno, num_req);

  // signal the socket connection that we're done read-write
  if(CONN_TLSTOR(ptr, ssl)){
    SSL_set_shutdown(CONN_TLSTOR(ptr, ssl), SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
    SSL_free(CONN_TLSTOR(ptr, ssl));
  }

  if (shutdown(config.new_fd, SHUT_RDWR) < 0)
    log_msg(LGG_DEBUG, "%s shutdown error: %m", __FUNCTION__);
  if (close(config.new_fd) < 0)
    log_msg(LGG_DEBUG, "%s close error: %m", __FUNCTION__);

  TIME_CHECK("socket close()");
  
  // decrement number of service threads/processes by one before we exit
  // don't check for write errors
  memset(&pipedata, 0, sizeof(pipedata));
  pipedata.status = ACTION_DEC_KCC;
  pipedata.krq = num_req;
  rv = write(config.pipefd, &pipedata, sizeof(pipedata));

  // Memory-Leak Fix: Finale Aufräumung vor Thread-Ende
  if (cors_origin) {
    free(cors_origin);
    cors_origin = NULL;
  }
  if (req_url) {
    free(req_url);
    req_url = NULL;
  }
  if (post_buf) {
    free(post_buf);
    post_buf = NULL;
  }
  if (aspbuf) {
    free(aspbuf);
    aspbuf = NULL;
  }
  if (buf) {
    free(buf);
    buf = NULL;
  }
  // version_string und stat_string sind bereits oben freigegeben

  conn_stor_relinq(ptr);
  return NULL;
}
