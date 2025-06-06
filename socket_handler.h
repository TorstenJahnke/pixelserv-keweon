#ifndef SOCKET_HANDLER_H
#define SOCKET_HANDLER_H

#include "certs.h"
#include "logger.h"

/* Buffer sizes */
#define DEFAULT_REPLY SEND_TXT
#define CHAR_BUF_SIZE       4095     /* initial/incremental size of msg buffer */
#define MAX_CHAR_BUF_LOTS   32       /* max msg buffer size in unit of CHAR_BUF_SIZE */
#define MAX_HTTP_POST_LEN   262143   /* max POST Content-Length before discarding */
#define MAX_HTTP_POST_RETRY 3        /* 3 times */

/* Response types enum */
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
  /* New response types for extended file support */
  SEND_JSON,
  SEND_XML,
  SEND_WEBP,
  SEND_SVG,
  SEND_FONT,
  SEND_VIDEO,
  SEND_AUDIO,
  SEND_PDF,
  SEND_DOC,
  SEND_ZIP,
  SEND_BIN,
  SEND_CSS,
  SEND_HTML,
  /* ASP/Server-side script support */
  SEND_ASP,
  SEND_ASPX,
  SEND_ASHX,
  SEND_PHP,
  SEND_JSP,
  SEND_JS,
  /* Special actions */
  ACTION_LOG_VERB,
  ACTION_DEC_KCC
} response_enum;

/* Response structure */
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

/* Public functions */
void* conn_handler(void *ptr);
void get_client_ip(int socket_fd, char *ip, int ip_len, char *port, int port_len);

/* Enhanced functions for scalability */
void socket_handler_init(void);
void socket_handler_cleanup(void);
void socket_handler_get_metrics(char *buffer, size_t size);

/* Configuration functions */
void socket_handler_set_thread_pool(int enable);
void socket_handler_set_rate_limit(int tokens_per_sec);
void socket_handler_set_memory_pool_size(size_t size);

/* ASP/Server-side script configuration */
void socket_handler_set_asp_config(int enable_logging, int enable_mime, const char *charset);

#endif /* SOCKET_HANDLER_H */
