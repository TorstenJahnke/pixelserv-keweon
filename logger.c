#include <stdarg.h>
#include <string.h>
#include <syslog.h>
#include <openssl/ssl.h>
#include "logger.h"

#ifndef DEBUG
static logger_level _verb = LGG_ERR;
#else
static logger_level _verb = LGG_DEBUG;
#endif

static int ctrl_char(char *buf, size_t len) {
    if (strlen(buf) < len)
        return 1;
    for (size_t i=0; i<(len - 1); i++) {
        if (buf[i] >= 10 && buf[i] <= 13)
            continue;
        if (buf[i] < 32) {
            return 1;
        }
    }
    return 0;
}

void log_set_verb(logger_level verb) { _verb = verb; }
logger_level log_get_verb() { return _verb; }

void log_msg(logger_level verb, char *fmt, ...)
{
    if (verb > _verb)
        return;
      
    va_list args;
    va_start(args, fmt);
    vsyslog(LOG_CRIT + verb, fmt, args);
    va_end(args);
}

void log_xcs(logger_level verb, char *client_ip, char *host, int tls, char *req, char *body, size_t body_len)
{
    if (verb > _verb || !client_ip || !host || !req)
      return;

    const char* tls_ver;
    switch (tls) {
#ifdef TLS1_3_VERSION
        case TLS1_3_VERSION: tls_ver = "1.3"; break;
#endif
        case TLS1_2_VERSION: tls_ver = "1.2"; break;
        case TLS1_VERSION:   tls_ver = "1.0"; break;
        case 0:
        default:
            tls_ver = "none";
    }

    if (strlen(req) < MAX_LOG_CHUNK_SIZE)
        syslog(LOG_CRIT + verb, "%s %s %s tls_%s", client_ip, host, req, tls_ver);
    else {
        int num_chunks = strlen(req) / MAX_LOG_CHUNK_SIZE + 1;
        char store = req[MAX_LOG_CHUNK_SIZE];
        req[MAX_LOG_CHUNK_SIZE] = '\0';
        syslog(LOG_CRIT + verb, "%s %s %s", client_ip, host, req);
        req[MAX_LOG_CHUNK_SIZE] = store;

        int chunk = 1;
        if (num_chunks > 2)
          for (; chunk < num_chunks - 1; chunk++) {
              store = req[MAX_LOG_CHUNK_SIZE * (chunk + 1)];
              req[MAX_LOG_CHUNK_SIZE * (chunk + 1)] = '\0';
              syslog(LOG_CRIT + verb, "%s", req + MAX_LOG_CHUNK_SIZE * chunk);
              req[MAX_LOG_CHUNK_SIZE * (chunk + 1)] = store;
          }
        syslog(LOG_CRIT + verb, "%s tls_%s", req + MAX_LOG_CHUNK_SIZE * chunk, tls_ver);
    }

    if (body_len > 0 && body) {
      if (ctrl_char(body, body_len))
          syslog(LOG_CRIT + verb, "[%s]", "-binary POST content not dumped-");
      else if (strlen(body) < MAX_LOG_CHUNK_SIZE)
          syslog(LOG_CRIT + verb, "[%s]", body);
      else {
          int num_chunks = strlen(body) / MAX_LOG_CHUNK_SIZE + 1;
          char store = body[MAX_LOG_CHUNK_SIZE];
          body[MAX_LOG_CHUNK_SIZE] = '\0';
          syslog(LOG_CRIT + verb, "[%s", body);
          body[MAX_LOG_CHUNK_SIZE] = store;

          int chunk = 1;
          if (num_chunks > 2)
            for (; chunk < num_chunks - 1; chunk++) {
                store = body[MAX_LOG_CHUNK_SIZE * (chunk + 1)];
                body[MAX_LOG_CHUNK_SIZE * (chunk + 1)] = '\0';
                syslog(LOG_CRIT + verb, "%s", body + MAX_LOG_CHUNK_SIZE * chunk);
                body[MAX_LOG_CHUNK_SIZE * (chunk + 1)] = store;
            }
          syslog(LOG_CRIT + verb, "%s]", body + MAX_LOG_CHUNK_SIZE * chunk);
      }
    }
}
