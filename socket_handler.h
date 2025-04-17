#ifndef SOCKET_HANDLER_H
#define SOCKET_HANDLER_H

#include "certs.h"
#include "logger.h"

#define DEFAULT_REPLY SEND_TXT
#define CHAR_BUF_SIZE       4095     /* initial/incremental size of msg buffer */
#define MAX_CHAR_BUF_LOTS   32       /* max msg buffer size in unit of CHAR_BUF_SIZE */
#define MAX_HTTP_POST_LEN   262143   /* max POST Content-Length before discarding */
#define MAX_HTTP_POST_RETRY 3        /* 3 times */

typedef enum {
  FAIL_GENERAL,
  FAIL_TIMEOUT,
  FAIL_CLOSED,
  FAIL_REPLY,
  SEND_GIF,
  SEND_TXT,
  SEND_JPG,
  SEND_PNG,
  SEND_SWF,
  SEND_ICO,
  SEND_BAD,
  SEND_STATS,
  SEND_STATSTEXT,
  SEND_204,
  SEND_REDIRECT,
  SEND_NO_EXT,
  SEND_UNK_EXT,
  SEND_NO_URL,
  SEND_BAD_PATH,
  SEND_POST,
  SEND_HEAD,
  SEND_OPTIONS,
  ACTION_LOG_VERB,
  ACTION_DEC_KCC
} response_enum;

typedef struct {
    response_enum status;
    union {
        int rx_total;
        int krq;
        logger_level verb;
    };
    double run_time;
    ssl_enum ssl;
    int ssl_ver;
} response_struct;

void* conn_handler(void *ptr);
void get_client_ip(int socket_fd, char *ip, int ip_len, char *port, int port_len);
#endif // SOCKET_HANDLER_H
