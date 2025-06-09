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

__attribute__((unused)) static int ctrl_char(char *buf, size_t len) {
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
    // Alle Logging-Nachrichten werden ignoriert
    (void)verb;
    (void)fmt;
}

void log_xcs(logger_level verb, char *client_ip, char *host, int tls, char *req, char *body, size_t body_len)
{
    // Alle Logging-Nachrichten werden ignoriert
    (void)verb;
    (void)client_ip;
    (void)host;
    (void)tls;
    (void)req;
    (void)body;
    (void)body_len;
}
