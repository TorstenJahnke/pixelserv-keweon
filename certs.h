#ifndef _CERTS_H_
#define _CERTS_H_

#include <arpa/inet.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/opensslv.h>

/* OpenSSL version compatibility */
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
#define OPENSSL_API_1_1 1
#else
#define OPENSSL_API_1_1 0
#endif

#define PIXEL_SSL_SESS_CACHE_SIZE 128*20
#define PIXEL_SSL_SESS_TIMEOUT 30 /* seconds - HTTPS Session Länge für AdBlock optimiert */
#define PIXEL_TLS_EARLYDATA_SIZE 16384

#ifndef DEFAULT_PEM_PATH
#define DEFAULT_PEM_PATH "/opt/var/cache/pixelserv"
#endif

#define PIXELSERV_MAX_PATH 1024
#define PIXELSERV_MAX_SERVER_NAME 255

extern char pixel_cert_pipe[PIXELSERV_MAX_PATH];

/* Updated cipher lists for modern TLS */
#define PIXELSERV_CIPHER_LIST \
  "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:" \
  "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:" \
  "ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:" \
  "ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:" \
  "DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256:" \
  "DHE-RSA-AES128-SHA:AES128-GCM-SHA256:AES128-SHA256:AES128-SHA"

#define PIXELSERV_TLSV1_3_CIPHERS \
  "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"

/* Certificate storage structure */
typedef struct {
    const char* pem_dir;
    STACK_OF(X509_INFO) *cachain;
    X509_NAME *issuer;
    EVP_PKEY *privkey;
} cert_tlstor_t;

/* SSL status enumeration */
typedef enum {
    SSL_NOT_TLS,
    SSL_ERR,
    SSL_MISS,
    SSL_HIT,
    SSL_HIT_CLS,
    SSL_HIT_RTT0,
    SSL_UNKNOWN
} ssl_enum;

/* TLS extension callback argument structure */
typedef struct {
    const char *tls_pem;
    const STACK_OF(X509_INFO) *cachain;
    char servername[65]; /* max legal domain name 63 chars; INET6_ADDRSTRLEN 46 bytes */
    char server_ip[INET6_ADDRSTRLEN];
    ssl_enum status;
    int sslctx_idx;
} tlsext_cb_arg_struct;

/* Connection TLS storage structure */
typedef struct {
    int new_fd;
    SSL *ssl;
    double init_time;
    tlsext_cb_arg_struct *tlsext_cb_arg;
    int allow_admin;
    char *early_data;
    tlsext_cb_arg_struct v;
} conn_tlstor_struct;

/* SSL context cache structure - optimized with atomic operations */
typedef struct {
    int alloc_len;
    char *cert_name;
    unsigned int last_use; /* seconds since process up - made atomic in implementation */
    int reuse_count;       /* made atomic in implementation */
    SSL_CTX *sslctx;
    pthread_mutex_t lock;  /* Keep individual locks for SSL_CTX operations */
} sslctx_cache_struct;

#define CONN_TLSTOR(p, e) ((conn_tlstor_struct*)p)->e

/* Function declarations */
void ssl_init_locks(void);
void ssl_free_locks(void);
void cert_tlstor_init(const char *pem_dir, cert_tlstor_t *c);
void cert_tlstor_cleanup(cert_tlstor_t *c);
void *cert_generator(void *ptr);

/* SSL context table management */
void sslctx_tbl_init(int tbl_size);
void sslctx_tbl_cleanup(void);
void sslctx_tbl_load(const char* pem_dir, const STACK_OF(X509_INFO) *cachain);
void sslctx_tbl_save(const char* pem_dir);
void sslctx_tbl_lock(int idx);
void sslctx_tbl_unlock(int idx);

/* Statistics functions - now with atomic operations */
int sslctx_tbl_get_cnt_total(void);
int sslctx_tbl_get_cnt_hit(void);
int sslctx_tbl_get_cnt_miss(void);
int sslctx_tbl_get_cnt_purge(void);
int sslctx_tbl_get_sess_cnt(void);
int sslctx_tbl_get_sess_hit(void);
int sslctx_tbl_get_sess_miss(void);
int sslctx_tbl_get_sess_purge(void);

/* SSL context creation and management */
SSL_CTX *create_default_sslctx(const char *pem_dir);
int is_ssl_conn(int fd, char *srv_ip, int srv_ip_len, const int *ssl_ports, int num_ssl_ports);

/* Connection storage management - keep original API */
void conn_stor_init(int slots);
void conn_stor_relinq(conn_tlstor_struct *p);
conn_tlstor_struct* conn_stor_acquire(void);
void conn_stor_flush(void);

/* TLS 1.3 specific functions */
#ifdef TLS1_3_VERSION
int tls_clienthello_cb(SSL *ssl, int *ad, void *arg);
char* read_tls_early_data(SSL *ssl, int *err);
#endif

/* Benchmark function */
void run_benchmark(const cert_tlstor_t *ct, const char *cert);

/* Additional utility functions */
SSL_CTX* sslctx_tbl_get_ctx(const char *cert_name);
int validate_certificate_chain(SSL_CTX *ctx);
int check_cert_expiration(const char *cert_path, time_t *expires_at);
void log_ssl_errors(const char *operation);
void sslctx_tbl_cleanup_expired(void);
size_t sslctx_tbl_memory_usage(void);
void pregenerate_common_certs(cert_tlstor_t *ct);
void print_cert_statistics(void);

#endif /* _CERTS_H_ */
