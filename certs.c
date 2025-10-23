#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509v3.h>
#include <openssl/opensslv.h>
#include "util.h"

#include "certs.h"
#include "logger.h"
#include "util.h"

#if defined(__GLIBC__) && !defined(__UCLIBC__)
#  include <malloc.h>
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
#define OPENSSL_API_1_1 1
#else
#define OPENSSL_API_1_1 0
#endif

#if !OPENSSL_API_1_1
static pthread_mutex_t *locks;
#endif

static SSL_CTX *g_sslctx;

static sslctx_cache_struct *sslctx_tbl;
static int sslctx_tbl_size, sslctx_tbl_end;
static int sslctx_tbl_cnt_hit, sslctx_tbl_cnt_miss, sslctx_tbl_cnt_purge;
static unsigned int sslctx_tbl_last_flush;

static void **conn_stor;
static int conn_stor_last = -1, conn_stor_max = -1;
static pthread_mutex_t cslock = PTHREAD_MUTEX_INITIALIZER;

typedef struct cert_job {
    char cert_name[PIXELSERV_MAX_SERVER_NAME+1];
    struct cert_job *next;
} cert_job_t;

static cert_job_t *cert_q_head = NULL, *cert_q_tail = NULL;
static pthread_mutex_t cert_q_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  cert_q_cond = PTHREAD_COND_INITIALIZER;
static volatile int cert_workers_shutdown = 0;

static void generate_cert(const char *cert_name,
                          const char *pem_dir,
                          X509_NAME *issuer,
                          EVP_PKEY *privkey,
                          const STACK_OF(X509_INFO) *cachain);

static int is_ip_address(const char *addr) {
    struct sockaddr_in sa4;
    struct sockaddr_in6 sa6;
    
    if (inet_pton(AF_INET, addr, &(sa4.sin_addr)) == 1) return 4;
    if (inet_pton(AF_INET6, addr, &(sa6.sin6_addr)) == 1) return 6;
    return 0;
}

static void generate_universal_ip_cert(const char *pem_dir,
                                      X509_NAME *issuer,
                                      EVP_PKEY *privkey,
                                      const STACK_OF(X509_INFO) *cachain)
{
    char fname[PIXELSERV_MAX_PATH];
    EVP_PKEY *key = NULL;
    X509 *x509 = NULL;
    X509_EXTENSION *ext = NULL;
    EVP_MD_CTX *p_ctx = NULL;
    
    const char *mega_san =
        "IP:127.0.0.1,IP:127.0.0.254,"
        "IP:10.0.0.1,IP:10.255.255.254,"
        "IP:192.168.0.1,IP:192.168.255.254,"
        "IP:172.16.0.1,IP:172.31.255.254,"
        "IP:192.168.1.1,IP:192.168.0.1,IP:10.0.0.1,"
        "DNS:localhost,DNS:*.local,DNS:*.lan";

#if OPENSSL_API_1_1
    p_ctx = EVP_MD_CTX_new();
#else
    p_ctx = EVP_MD_CTX_create();
#endif
    if (!p_ctx || EVP_DigestSignInit(p_ctx, NULL, EVP_sha256(), NULL, privkey) != 1) {
        goto free_all;
    }

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    key = EVP_RSA_gen(2048);
    if (!key) {
        goto free_all;
    }
#elif OPENSSL_API_1_1
    key = EVP_PKEY_new();
    if (!key) goto free_all;
    
    EVP_PKEY_CTX *pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!pkey_ctx) goto free_all;
    
    if (EVP_PKEY_keygen_init(pkey_ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(pkey_ctx, 2048) <= 0 ||
        EVP_PKEY_keygen(pkey_ctx, &key) <= 0) {
        EVP_PKEY_CTX_free(pkey_ctx);
        goto free_all;
    }
    EVP_PKEY_CTX_free(pkey_ctx);
#else
    BIGNUM *e = BN_new();
    if (!e) goto free_all;
    BN_set_word(e, RSA_F4);
    
    RSA *rsa = RSA_new();
    if (!rsa || RSA_generate_key_ex(rsa, 2048, e, NULL) < 0) {
        BN_free(e);
        RSA_free(rsa);
        goto free_all;
    }
    BN_free(e);
    
    key = EVP_PKEY_new();
    if (!key || !EVP_PKEY_assign_RSA(key, rsa)) {
        RSA_free(rsa);
        goto free_all;
    }
#endif

    x509 = X509_new();
    if (!x509) goto free_all;
    
    ASN1_INTEGER_set(X509_get_serialNumber(x509), rand());
    X509_set_version(x509, 2);
    
    int offset = -(rand() % (864000 - 172800 + 1) + 172800);
    X509_gmtime_adj(X509_get_notBefore(x509), offset);
    X509_gmtime_adj(X509_get_notAfter(x509), 3600*24*390L);
    
    X509_set_issuer_name(x509, issuer);
    X509_NAME *name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"*.universal.ip", -1, -1, 0);

    ext = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name, mega_san);
    if (!ext) goto free_all;
    X509_add_ext(x509, ext, -1);
    X509_EXTENSION_free(ext);
    ext = NULL;
    
    ext = X509V3_EXT_conf_nid(NULL, NULL, NID_ext_key_usage, "TLS Web Server Authentication");
    if (!ext) goto free_all;
    X509_add_ext(x509, ext, -1);
    
    X509_set_pubkey(x509, key);
    X509_sign_ctx(x509, p_ctx);

    snprintf(fname, PIXELSERV_MAX_PATH, "%s/universal_ips.pem", pem_dir);
    
    FILE *fp = fopen(fname, "wb");
    if (!fp) {
        goto free_all;
    }

    PEM_write_X509(fp, x509);

    if (cachain) {
        for (int i = 0; i < sk_X509_INFO_num(cachain); i++) {
            X509_INFO *xi = sk_X509_INFO_value(cachain, i);
            if (xi && xi->x509) {
                PEM_write_X509(fp, xi->x509);
            }
        }
    }

    PEM_write_PrivateKey(fp, key, NULL, NULL, 0, NULL, NULL);
    fclose(fp);

free_all:
    EVP_PKEY_free(key);
    X509_EXTENSION_free(ext);
    X509_free(x509);
    if (p_ctx) {
#if OPENSSL_API_1_1
        EVP_MD_CTX_free(p_ctx);
#else
        EVP_MD_CTX_destroy(p_ctx);
#endif
    }
}

static void *cert_worker(void *arg) {
    cert_tlstor_t *ct = (cert_tlstor_t *)arg;
    
    while (!cert_workers_shutdown) {
        pthread_mutex_lock(&cert_q_lock);
        while (!cert_q_head && !cert_workers_shutdown) {
            pthread_cond_wait(&cert_q_cond, &cert_q_lock);
        }
        
        if (cert_workers_shutdown) {
            pthread_mutex_unlock(&cert_q_lock);
            break;
        }
        
        cert_job_t *job = cert_q_head;
        cert_q_head = job->next;
        if (!cert_q_head) cert_q_tail = NULL;
        pthread_mutex_unlock(&cert_q_lock);

        generate_cert(job->cert_name, ct->pem_dir, ct->issuer, ct->privkey, ct->cachain);
        
        free(job);
    }
    return NULL;
}

static void shutdown_cert_workers(void) {
    cert_workers_shutdown = 1;
    pthread_cond_broadcast(&cert_q_cond);
}

static void enqueue_cert_job(const char *cert_name) {
    cert_job_t *job = malloc(sizeof(*job));
    if (!job) {
        return;
    }
    
    strncpy(job->cert_name, cert_name, PIXELSERV_MAX_SERVER_NAME);
    job->cert_name[PIXELSERV_MAX_SERVER_NAME] = '\0';
    job->next = NULL;
    
    pthread_mutex_lock(&cert_q_lock);
    if (!cert_q_tail) {
        cert_q_head = job;
    } else {
        cert_q_tail->next = job;
    }
    cert_q_tail = job;
    pthread_cond_signal(&cert_q_cond);
    pthread_mutex_unlock(&cert_q_lock);
}

#define SSLCTX_TBL_ptr(h)         ((sslctx_cache_struct *)(sslctx_tbl + h))
#define SSLCTX_TBL_get(h, k)      SSLCTX_TBL_ptr(h)->k
#define SSLCTX_TBL_set(h, k, v)   SSLCTX_TBL_ptr(h)->k = v

inline int sslctx_tbl_get_cnt_total() { return sslctx_tbl_end; }
inline int sslctx_tbl_get_cnt_hit() { return sslctx_tbl_cnt_hit; }
inline int sslctx_tbl_get_cnt_miss() { return sslctx_tbl_cnt_miss; }
inline int sslctx_tbl_get_cnt_purge() { return sslctx_tbl_cnt_purge; }
inline int sslctx_tbl_get_sess_cnt() { return SSL_CTX_sess_number(g_sslctx); }
inline int sslctx_tbl_get_sess_hit() { return SSL_CTX_sess_hits(g_sslctx); }
inline int sslctx_tbl_get_sess_miss() { return SSL_CTX_sess_misses(g_sslctx); }
inline int sslctx_tbl_get_sess_purge() { return SSL_CTX_sess_cache_full(g_sslctx); }

static int sslctx_tbl_insert(const char *cert_name, SSL_CTX *sslctx, int ins_idx);
static SSL_CTX* create_child_sslctx(const char* full_pem_path, const STACK_OF(X509_INFO) *cachain);

#ifdef DEBUG
static void sslctx_tbl_dump(int idx, const char * func);
#endif

void conn_stor_init(int slots) {
    if (slots < 0) {
        return;
    }
    conn_stor = calloc(slots, sizeof(void *));
    if (!conn_stor) {
        return;
    }
    conn_stor_last = -1;
    conn_stor_max = slots;
}

void conn_stor_flush() {
    if (conn_stor_max < 0 || conn_stor_last < 0 || conn_stor_last <= conn_stor_max / 2)
        return;
        
    int threshold = conn_stor_max / 2;
    pthread_mutex_lock(&cslock);
    for (; conn_stor_last >= threshold && conn_stor[conn_stor_last] != NULL; conn_stor_last--) {
        free(conn_stor[conn_stor_last]);
        conn_stor[conn_stor_last] = NULL;
    }
    pthread_mutex_unlock(&cslock);
}

void conn_stor_relinq(conn_tlstor_struct *p) {
    if (!p) return;
    
    pthread_mutex_lock(&cslock);
    if (conn_stor_last >= conn_stor_max - 1) {
        pthread_mutex_unlock(&cslock);
        free(p);
    } else {
        conn_stor[++conn_stor_last] = p;
        pthread_mutex_unlock(&cslock);
    }
}

conn_tlstor_struct* conn_stor_acquire() {
    conn_tlstor_struct *ret = NULL;

    pthread_mutex_lock(&cslock);
    if (conn_stor_last >= 0) {
        ret = conn_stor[conn_stor_last];
        conn_stor[conn_stor_last--] = NULL;
    }
    pthread_mutex_unlock(&cslock);

    if (ret == NULL) {
        ret = calloc(1, sizeof(conn_tlstor_struct));
        if (ret != NULL) {
            ret->tlsext_cb_arg = &ret->v;
        }
    } else {
        memset(ret, 0, sizeof(conn_tlstor_struct));
        ret->tlsext_cb_arg = &ret->v;
    }
    return ret;
}

void sslctx_tbl_init(int tbl_size)
{
    if (tbl_size <= 0)
        return;
        
    sslctx_tbl_end = 0;
    sslctx_tbl = calloc(tbl_size, sizeof(sslctx_cache_struct));
    if (!sslctx_tbl) {
        sslctx_tbl_size = 0;
        return;
    }
    
    sslctx_tbl_size = tbl_size;
    sslctx_tbl_cnt_hit = sslctx_tbl_cnt_miss = sslctx_tbl_cnt_purge = sslctx_tbl_last_flush = 0;
    
    for (int i = 0; i < tbl_size; i++) {
        pthread_mutex_init(&SSLCTX_TBL_get(i, lock), NULL);
    }
}

void sslctx_tbl_cleanup()
{
    if (!sslctx_tbl) return;
    
    shutdown_cert_workers();
    
    for (int idx = 0; idx < sslctx_tbl_end; idx++) {
        free(SSLCTX_TBL_get(idx, cert_name));
        SSL_CTX_free(SSLCTX_TBL_get(idx, sslctx));
        pthread_mutex_destroy(&SSLCTX_TBL_get(idx, lock));
    }
    
    free(sslctx_tbl);
    sslctx_tbl = NULL;
    
    pthread_mutex_destroy(&cslock);
    
    if (conn_stor) {
        for (int i = 0; i <= conn_stor_last; i++) {
            free(conn_stor[i]);
        }
        free(conn_stor);
        conn_stor = NULL;
    }
}

static int cmp_sslctx_reuse_count(const void *p1, const void *p2)
{
    return ((sslctx_cache_struct *)p2)->reuse_count - ((sslctx_cache_struct *)p1)->reuse_count;
}

static int cmp_sslctx_certname(const void *k, const void *p)
{
    return strcmp(((sslctx_cache_struct *)k)->cert_name, ((sslctx_cache_struct *)p)->cert_name);
}

void sslctx_tbl_load(const char* pem_dir, const STACK_OF(X509_INFO) *cachain)
{
    char *fname = NULL, *line = NULL;
    size_t line_len = PIXELSERV_MAX_PATH;
    FILE *fp = NULL;
    
    if (!(line = malloc(line_len)) || !(fname = malloc(PIXELSERV_MAX_PATH))) {
        goto quit_load;
    }

    snprintf(fname, PIXELSERV_MAX_PATH, "%s/prefetch", pem_dir);
    if (!(fp = fopen(fname, "r"))) {
        goto quit_load;
    }

    while (getline(&line, &line_len, fp) != -1) {
        char *cert_name = strtok(line, " \n\t");
        if (!cert_name) continue;
        
        snprintf(fname, PIXELSERV_MAX_PATH, "%s/%s", pem_dir, cert_name);

        SSL_CTX *sslctx = create_child_sslctx(fname, cachain);
        if (sslctx) {
            int ins_idx = sslctx_tbl_end;
            sslctx_tbl_insert(cert_name, sslctx, ins_idx);
        }
        if (sslctx_tbl_end >= sslctx_tbl_size)
            break;
    }
    
    fclose(fp);
    fp = NULL;
    
    sslctx_tbl_cnt_miss = 0;
    qsort(SSLCTX_TBL_ptr(0), sslctx_tbl_end, sizeof(sslctx_cache_struct), cmp_sslctx_certname);

quit_load:
    free(fname);
    free(line);
    if (fp) fclose(fp);
}

void sslctx_tbl_save(const char* pem_dir)
{
    #define RATIO_TO_SAVE 1
    char *fname = NULL;
    FILE *fp = NULL;

    if (!(fname = malloc(PIXELSERV_MAX_PATH))) {
        return;
    }
    
    snprintf(fname, PIXELSERV_MAX_PATH, "%s/prefetch", pem_dir);
    if (!(fp = fopen(fname, "w"))) {
        goto quit_save;
    }
    
    qsort(SSLCTX_TBL_ptr(0), sslctx_tbl_end, sizeof(sslctx_cache_struct), cmp_sslctx_reuse_count);
    
    int save_count = (sslctx_tbl_end > (sslctx_tbl_size * RATIO_TO_SAVE)) 
                     ? (sslctx_tbl_size * RATIO_TO_SAVE) 
                     : sslctx_tbl_end;

    for (int idx = 0; idx < save_count; idx++) {
        fprintf(fp, "%s\t%d\n", SSLCTX_TBL_get(idx, cert_name), SSLCTX_TBL_get(idx, reuse_count));
    }
    
    fclose(fp);
    fp = NULL;

quit_save:
    free(fname);
    if (fp) fclose(fp);
}

void sslctx_tbl_lock(int idx)
{
    if (idx < 0 || idx >= sslctx_tbl_size) {
        return;
    }
    pthread_mutex_lock(&SSLCTX_TBL_get(idx, lock));
}

void sslctx_tbl_unlock(int idx)
{
    if (idx < 0 || idx >= sslctx_tbl_size) {
        return;
    }
    pthread_mutex_unlock(&SSLCTX_TBL_get(idx, lock));
}

static int sslctx_tbl_check_and_flush(void)
{
    int pixel_now = process_uptime();
#ifdef DEBUG
#endif

    int do_flush = pixel_now - sslctx_tbl_last_flush - PIXEL_SSL_SESS_TIMEOUT / 2;
    if (do_flush < 0) {
        return -1;
    }
    
    SSL_CTX_flush_sessions(g_sslctx, time(NULL));
    sslctx_tbl_last_flush = pixel_now;
    return 1;
}

static int sslctx_tbl_lookup(const char* cert_name, int* found_idx, int* ins_idx)
{
    *found_idx = -1; 
    *ins_idx = -1;
    
    if (!cert_name || !found_idx || !ins_idx) {
        return -1;
    }

    sslctx_cache_struct key, *found;
    key.cert_name = (char*)cert_name;
    found = bsearch(&key, SSLCTX_TBL_ptr(0), sslctx_tbl_end, sizeof(sslctx_cache_struct), cmp_sslctx_certname);

    if (found != NULL) {
        sslctx_tbl_cnt_hit++;
        found->reuse_count++;
        found->last_use = process_uptime();
        *found_idx = (found - SSLCTX_TBL_ptr(0));
    } else if (sslctx_tbl_end < sslctx_tbl_size) {
        *ins_idx = sslctx_tbl_end;
    } else {
        int purge_idx = 0;
        unsigned int oldest_use = process_uptime();

        for (int idx = 0; idx < sslctx_tbl_end; idx++) {
            if (SSLCTX_TBL_get(idx, last_use) < oldest_use) {
                oldest_use = SSLCTX_TBL_get(idx, last_use);
                purge_idx = idx;
            }
        }
        *ins_idx = purge_idx;
    }
    return 0;
}

static int sslctx_tbl_insert(const char *cert_name, SSL_CTX *sslctx, int ins_idx)
{
    if (!cert_name || !sslctx || ins_idx >= sslctx_tbl_size || ins_idx < 0) {
        return -1;
    }
    
    sslctx_tbl_cnt_miss++;

    unsigned int pixel_now = process_uptime();
    int len = strlen(cert_name);
    char *str = SSLCTX_TBL_get(ins_idx, cert_name);
    
    if ((len + 1) > SSLCTX_TBL_get(ins_idx, alloc_len)) {
        str = realloc(str, len + 1);
        if (!str) {
            return -1;
        }
        SSLCTX_TBL_set(ins_idx, alloc_len, len + 1);
    }
    
    strncpy(str, cert_name, len + 1);
    SSLCTX_TBL_set(ins_idx, cert_name, str);
    SSLCTX_TBL_set(ins_idx, last_use, pixel_now);
    SSLCTX_TBL_set(ins_idx, reuse_count, 0);
    
    if (ins_idx == sslctx_tbl_end && sslctx_tbl_end < sslctx_tbl_size) {
        sslctx_tbl_end++;
    } else {
#ifdef DEBUG
#endif
        SSL_CTX_free(SSLCTX_TBL_get(ins_idx, sslctx));
        sslctx_tbl_cnt_purge++;
    }
    
    SSLCTX_TBL_set(ins_idx, sslctx, sslctx);
    return 0;
}

static int sslctx_tbl_cache(const char *cert_name, SSL_CTX *sslctx, int ins_idx)
{
    if (sslctx_tbl_insert(cert_name, sslctx, ins_idx) == 0) {
        qsort(SSLCTX_TBL_ptr(0), sslctx_tbl_end, sizeof(sslctx_cache_struct), cmp_sslctx_certname);
        return 0;
    }
    return -1;
}

static int sslctx_tbl_purge(int idx) {
    if (idx < 0 || idx >= sslctx_tbl_end) {
        return -1;
    }

    free(SSLCTX_TBL_get(idx, cert_name));
    SSL_CTX_free(SSLCTX_TBL_get(idx, sslctx));
    
    --sslctx_tbl_end;
    if (idx < sslctx_tbl_end) {
        memmove(SSLCTX_TBL_ptr(idx), SSLCTX_TBL_ptr(idx+1), 
                sizeof(sslctx_cache_struct) * (sslctx_tbl_end - idx));
    }
    memset(SSLCTX_TBL_ptr(sslctx_tbl_end), 0, sizeof(sslctx_cache_struct));

    return 0;
}

#ifdef DEBUG
static void sslctx_tbl_dump(int idx, const char * func)
{
    if (idx < 0 || idx >= sslctx_tbl_end) return;
}
#endif

#if !OPENSSL_API_1_1
static void ssl_lock_cb(int mode, int type, const char *file, int line)
{
    if (mode & CRYPTO_LOCK)
        pthread_mutex_lock(&(locks[type]));
    else
        pthread_mutex_unlock(&(locks[type]));
}

static void ssl_thread_id(CRYPTO_THREADID *id)
{
    CRYPTO_THREADID_set_numeric(id, (unsigned long) pthread_self());
}
#endif

void ssl_init_locks()
{
#if !OPENSSL_API_1_1
    int num_locks = CRYPTO_num_locks();
#ifdef DEBUG
#endif
    locks = OPENSSL_malloc(num_locks * sizeof(pthread_mutex_t));
    if (!locks) {
        return;
    }
    
    for (int i = 0; i < num_locks; i++) {
        pthread_mutex_init(&(locks[i]), NULL);
    }

    CRYPTO_THREADID_set_callback(ssl_thread_id);
    CRYPTO_set_locking_callback(ssl_lock_cb);
#else
#endif
}

void ssl_free_locks()
{
#if !OPENSSL_API_1_1
    if (!locks) return;
    
    CRYPTO_set_locking_callback(NULL);
    int num_locks = CRYPTO_num_locks();
    for (int i = 0; i < num_locks; i++) {
        pthread_mutex_destroy(&(locks[i]));
    }
    OPENSSL_free(locks);
    locks = NULL;
#endif
}

static void generate_cert(const char* cert_name,
                          const char *pem_dir,
                          X509_NAME *issuer,
                          EVP_PKEY *privkey,
                          const STACK_OF(X509_INFO) *cachain)
{
    char fname[PIXELSERV_MAX_PATH];
    EVP_PKEY *key = NULL;
    X509 *x509 = NULL;
    X509_EXTENSION *ext = NULL;
    char san_str[PIXELSERV_MAX_SERVER_NAME + 4];
    EVP_MD_CTX *p_ctx = NULL;
    char *pem_fn = NULL;
    
    pem_fn = strdup(cert_name);
    if (!pem_fn) {
        return;
    }

#if OPENSSL_API_1_1
    p_ctx = EVP_MD_CTX_new();
#else
    p_ctx = EVP_MD_CTX_create();
#endif
    if (!p_ctx || EVP_DigestSignInit(p_ctx, NULL, EVP_sha256(), NULL, privkey) != 1) {
        goto free_all;
    }

    if (pem_fn[0] == '_') pem_fn[0] = '*';

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    key = EVP_RSA_gen(2048);
    if (!key) {
        goto free_all;
    }
#elif OPENSSL_API_1_1
    key = EVP_PKEY_new();
    if (!key) goto free_all;
    
    EVP_PKEY_CTX *pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!pkey_ctx) goto free_all;
    
    if (EVP_PKEY_keygen_init(pkey_ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(pkey_ctx, 2048) <= 0 ||
        EVP_PKEY_keygen(pkey_ctx, &key) <= 0) {
        EVP_PKEY_CTX_free(pkey_ctx);
        goto free_all;
    }
    EVP_PKEY_CTX_free(pkey_ctx);
#else
    BIGNUM *e = BN_new();
    if (!e) goto free_all;
    BN_set_word(e, RSA_F4);
    
    RSA *rsa = RSA_new();
    if (!rsa || RSA_generate_key_ex(rsa, 2048, e, NULL) < 0) {
        BN_free(e);
        RSA_free(rsa);
        goto free_all;
    }
    BN_free(e);
    
    key = EVP_PKEY_new();
    if (!key || !EVP_PKEY_assign_RSA(key, rsa)) {
        RSA_free(rsa);
        goto free_all;
    }
#endif

#ifdef DEBUG
#endif

    x509 = X509_new();
    if (!x509) goto free_all;
    
    ASN1_INTEGER_set(X509_get_serialNumber(x509), rand());
    X509_set_version(x509, 2);
    
    int offset = -(rand() % (864000 - 172800 + 1) + 172800);
    X509_gmtime_adj(X509_get_notBefore(x509), offset);
    X509_gmtime_adj(X509_get_notAfter(x509), 3600*24*390L);
    
    X509_set_issuer_name(x509, issuer);
    X509_NAME *name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)pem_fn, -1, -1, 0);

    int ip_version = is_ip_address(pem_fn);
    if (ip_version > 0) {
        snprintf(san_str, sizeof(san_str), "IP:%s", pem_fn);
    } else {
        snprintf(san_str, sizeof(san_str), "DNS:%s", pem_fn);
    }
    
    ext = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name, san_str);
    if (!ext) goto free_all;
    X509_add_ext(x509, ext, -1);
    X509_EXTENSION_free(ext);
    ext = NULL;
    
    ext = X509V3_EXT_conf_nid(NULL, NULL, NID_ext_key_usage, "TLS Web Server Authentication");
    if (!ext) goto free_all;
    X509_add_ext(x509, ext, -1);
    
    X509_set_pubkey(x509, key);
    X509_sign_ctx(x509, p_ctx);

#ifdef DEBUG
#endif

    if (pem_fn[0] == '*') pem_fn[0] = '_';
    snprintf(fname, PIXELSERV_MAX_PATH, "%s/%s", pem_dir, pem_fn);
    
    FILE *fp = fopen(fname, "wb");
    if (!fp) {
        goto free_all;
    }

    PEM_write_X509(fp, x509);

    if (cachain) {
        for (int i = 0; i < sk_X509_INFO_num(cachain); i++) {
            X509_INFO *xi = sk_X509_INFO_value(cachain, i);
            if (xi && xi->x509) {
                PEM_write_X509(fp, xi->x509);
            }
        }
    }

    PEM_write_PrivateKey(fp, key, NULL, NULL, 0, NULL, NULL);
    fclose(fp);

free_all:
    free(pem_fn);
    EVP_PKEY_free(key);
    X509_EXTENSION_free(ext);
    X509_free(x509);
    if (p_ctx) {
#if OPENSSL_API_1_1
        EVP_MD_CTX_free(p_ctx);
#else
        EVP_MD_CTX_destroy(p_ctx);
#endif
    }
}

static int pem_passwd_cb(char *buf, int size, int rwflag, void *u) {
    int rv = 0, fp;
    char *fname = NULL;
    
    if (asprintf(&fname, "%s/rootCA/ca.key.passphrase", (char*)u) < 0)
        goto quit_cb;

    if ((fp = open(fname, O_RDONLY)) < 0) {
    } else {
        rv = read(fp, buf, size - 1);
        close(fp);
        if (rv > 0 && buf[rv-1] == '\n') {
            rv--;
        }
        if (rv > 0) buf[rv] = '\0';
#ifdef DEBUG
#endif
    }

quit_cb:
    free(fname);
    return rv;
}

void cert_tlstor_init(const char *pem_dir, cert_tlstor_t *ct)
{
    FILE *fp = NULL;
    char cert_file[PIXELSERV_MAX_PATH];
    X509 *x509 = NULL;

    memset(ct, 0, sizeof(cert_tlstor_t));
    
    snprintf(cert_file, PIXELSERV_MAX_PATH, "%s/rootCA/ca.crt", pem_dir);
    fp = fopen(cert_file, "r");
    x509 = X509_new();

    if (!fp || !x509 || !PEM_read_X509(fp, &x509, NULL, NULL)) {
        goto cleanup_ca;
    }

    char *cafile = NULL;
    long fsz;
    
    if (fseek(fp, 0L, SEEK_END) < 0 || (fsz = ftell(fp)) < 0 || fseek(fp, 0L, SEEK_SET) < 0) {
        goto cleanup_ca;
    }

    cafile = malloc(fsz + 1);
    if (!cafile || fread(cafile, 1, fsz, fp) != (size_t)fsz) {
        free(cafile);
        goto cleanup_ca;
    }

    BIO *bioin = BIO_new_mem_buf(cafile, fsz);
    if (!bioin) {
        free(cafile);
        goto cleanup_ca;
    }

    ct->pem_dir = pem_dir;
    ct->cachain = PEM_X509_INFO_read_bio(bioin, NULL, NULL, NULL);
    ct->issuer = X509_NAME_dup(X509_get_subject_name(x509));

    if (!ct->cachain) {
    }

    BIO_free(bioin);
    free(cafile);

cleanup_ca:
    if (fp) fclose(fp);
    X509_free(x509);

    snprintf(cert_file, PIXELSERV_MAX_PATH, "%s/rootCA/ca.key", pem_dir);
    fp = fopen(cert_file, "r");
    if (!fp || !PEM_read_PrivateKey(fp, &ct->privkey, pem_passwd_cb, (void*)pem_dir)) {
    }
    if (fp) fclose(fp);

    char universal_ip_file[PIXELSERV_MAX_PATH];
    snprintf(universal_ip_file, sizeof(universal_ip_file), "%s/universal_ips.pem", pem_dir);
    struct stat st;
    if (stat(universal_ip_file, &st) != 0 && ct->privkey && ct->issuer) {
        generate_universal_ip_cert(pem_dir, ct->issuer, ct->privkey, ct->cachain);
    }

    cert_workers_shutdown = 0;
    for (int i = 0; i < 4; i++) {
        pthread_t tid;
        if (pthread_create(&tid, NULL, cert_worker, ct) == 0) {
            pthread_detach(tid);
        }
    }
}

void cert_tlstor_cleanup(cert_tlstor_t *c)
{
    if (!c) return;
    
    shutdown_cert_workers();
    
    sk_X509_INFO_pop_free(c->cachain, X509_INFO_free);
    X509_NAME_free(c->issuer);
    EVP_PKEY_free(c->privkey);
    
    memset(c, 0, sizeof(*c));
}

void *cert_generator(void *ptr) {
#ifdef DEBUG
#endif
    int idle = 0;
    cert_tlstor_t *ct = (cert_tlstor_t *) ptr;

    char buf[PIXELSERV_MAX_SERVER_NAME * 4 + 1];
    char *half_token = buf + PIXELSERV_MAX_SERVER_NAME * 4;
    buf[PIXELSERV_MAX_SERVER_NAME * 4] = '\0';

    int fd = open(pixel_cert_pipe, O_RDONLY | O_NONBLOCK);
    srand((unsigned int)time(NULL));

    while (!cert_workers_shutdown) {
        if (fd == -1) {
            sleep(1);
            fd = open(pixel_cert_pipe, O_RDONLY | O_NONBLOCK);
            continue;
        }
        
        strcpy(buf, half_token);
        struct pollfd pfd = { fd, POLLIN, 0 };
        int ret = poll(&pfd, 1, 1000 * PIXEL_SSL_SESS_TIMEOUT / 4);
        
        if (ret <= 0) {
            sslctx_tbl_check_and_flush();
            if (kcc == 0) {
                if (++idle >= (3600 / (PIXEL_SSL_SESS_TIMEOUT / 4))) {
                    conn_stor_flush();
                    idle = 0;
                }
#if defined(__GLIBC__) && !defined(__UCLIBC__)
                malloc_trim(0);
#endif
            }
            continue;
        }
        
        ssize_t cnt = read(fd, buf + strlen(half_token), PIXELSERV_MAX_SERVER_NAME * 4 - strlen(half_token));
        if (cnt == 0) {
#ifdef DEBUG
#endif
            close(fd);
            fd = open(pixel_cert_pipe, O_RDONLY | O_NONBLOCK);
            continue;
        }
        
        if (cnt < 0) continue;
        
        if ((size_t)cnt < PIXELSERV_MAX_SERVER_NAME * 4 - strlen(half_token)) {
            buf[cnt + strlen(half_token)] = '\0';
            half_token = buf + PIXELSERV_MAX_SERVER_NAME * 4;
        } else {
            size_t i = 1;
            for (i = 1; buf[PIXELSERV_MAX_SERVER_NAME * 4 - i] != ':' && i < strlen(buf); i++);
            half_token = buf + PIXELSERV_MAX_SERVER_NAME * 4 - i + 1;
            buf[PIXELSERV_MAX_SERVER_NAME * 4 - i + 1] = '\0';
        }
        
        if (!ct->privkey || !ct->issuer) continue;
        
        char *p_buf, *p_buf_sav = NULL;
        p_buf = strtok_r(buf, ":", &p_buf_sav);
        while (p_buf != NULL) {
            char cert_file[PIXELSERV_MAX_PATH];
            struct stat st;
            snprintf(cert_file, PIXELSERV_MAX_PATH, "%s/%s", ct->pem_dir, p_buf);
            
            if (stat(cert_file, &st) != 0) {
                enqueue_cert_job(p_buf);
            }
            p_buf = strtok_r(NULL, ":", &p_buf_sav);
        }
        
        sslctx_tbl_check_and_flush();
    }
    
    if (fd >= 0) close(fd);
    return NULL;
}

#ifdef TLS1_3_VERSION
static const unsigned char *get_server_name(SSL *s, size_t *len)
{
    const unsigned char *p;
    size_t remaining;

    if (!SSL_client_hello_get0_ext(s, TLSEXT_TYPE_server_name, &p, &remaining) ||
        remaining <= 2)
        return NULL;
        
    size_t list_len = (*(p++) << 8);
    list_len += *(p++);
    if (list_len + 2 != remaining)
        return NULL;
        
    remaining = list_len;
    if (remaining == 0 || *p++ != TLSEXT_NAMETYPE_host_name)
        return NULL;
        
    remaining--;
    if (remaining <= 2)
        return NULL;
        
    *len = (*(p++) << 8);
    *len += *(p++);
    if (*len + 2 > remaining)
        return NULL;
        
    return p;
}

int tls_clienthello_cb(SSL *ssl, int *ad, void *arg) {
# define CB_OK   1
# define CB_ERR  0
#else
static int tls_servername_cb(SSL *ssl, int *ad, void *arg) {
# define CB_OK   0
# define CB_ERR  SSL_TLSEXT_ERR_ALERT_FATAL
#endif
    int rv = CB_OK;
    tlsext_cb_arg_struct *cbarg = (tlsext_cb_arg_struct *)arg;
    char full_pem_path[PIXELSERV_MAX_PATH + 2];
    int len;

    if (!cbarg || !cbarg->tls_pem) {
        rv = CB_ERR;
        goto quit_cb;
    }

    len = strlen(cbarg->tls_pem);
    if (len >= PIXELSERV_MAX_PATH) {
        rv = CB_ERR;
        goto quit_cb;
    }
    
    strncpy(full_pem_path, cbarg->tls_pem, PIXELSERV_MAX_PATH);
    full_pem_path[len++] = '/';
    full_pem_path[len] = '\0';

    const char *srv_name = NULL;
#ifdef TLS1_3_VERSION
    size_t name_len = 0;
    const unsigned char *name_data = get_server_name(ssl, &name_len);
    if (name_data && name_len > 0 && name_len < sizeof(cbarg->servername)) {
        memcpy(cbarg->servername, name_data, name_len);
        cbarg->servername[name_len] = '\0';
        srv_name = cbarg->servername;
    }
#else
    srv_name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (srv_name) {
        strncpy(cbarg->servername, srv_name, sizeof(cbarg->servername) - 1);
        cbarg->servername[sizeof(cbarg->servername) - 1] = '\0';
    }
#endif

    if (!srv_name) {
        if (strlen(cbarg->servername) > 0) {
            srv_name = cbarg->servername;
        } else {
            rv = CB_ERR;
            goto quit_cb;
        }
    }

#ifdef DEBUG
#endif

    if (is_ip_address(srv_name)) {
        char universal_ip_path[PIXELSERV_MAX_PATH];
        snprintf(universal_ip_path, sizeof(universal_ip_path), "%s/universal_ips.pem", cbarg->tls_pem);
        
        struct stat st;
        if (stat(universal_ip_path, &st) == 0) {
            SSL_CTX *ip_ctx = create_child_sslctx(universal_ip_path, cbarg->cachain);
            if (ip_ctx) {
                SSL_set_SSL_CTX(ssl, ip_ctx);
                cbarg->status = SSL_HIT;
                goto quit_cb;
            }
        }
    }

    int dot_count = 0;
    const char *tld = NULL;
    const char *dot_pos = strchr(srv_name, '.');
    while (dot_pos) {
        dot_count++;
        tld = dot_pos + 1;
        dot_pos = strchr(tld, '.');
    }

    const char *pem_file;
    if (dot_count <= 1 || 
        (dot_count == 2 && strlen(tld) == 2) || 
        (dot_count == 3 && atoi(tld) > 0)) {
        pem_file = srv_name;
        strncat(full_pem_path, srv_name, PIXELSERV_MAX_PATH - len);
        len += strlen(srv_name);
    } else {
        pem_file = full_pem_path + strlen(full_pem_path);
        strncat(full_pem_path, "_", PIXELSERV_MAX_PATH - len);
        len += 1;
        const char *wildcard_domain = strchr(srv_name, '.');
        if (wildcard_domain) {
            strncat(full_pem_path, wildcard_domain, PIXELSERV_MAX_PATH - len);
            len += strlen(wildcard_domain);
        }
    }

#ifdef DEBUG
#endif

    if (len > PIXELSERV_MAX_PATH) {
        rv = CB_ERR;
        goto quit_cb;
    }

    int handle, ins_handle;
    if (sslctx_tbl_lookup(pem_file, &handle, &ins_handle) != 0) {
        rv = CB_ERR;
        goto quit_cb;
    }

#ifdef DEBUG
    if (handle >= 0) sslctx_tbl_dump(handle, __FUNCTION__);
    if (ins_handle >= 0) sslctx_tbl_dump(ins_handle, __FUNCTION__);
#endif

    if (handle >= 0) {
        SSL_set_SSL_CTX(ssl, SSLCTX_TBL_get(handle, sslctx));
        
        X509 *cert = SSL_get_certificate(ssl);
        if (cert && X509_cmp_time(X509_get_notAfter(cert), NULL) > 0) {
            cbarg->status = SSL_HIT;
            goto quit_cb;
        }
        
        cbarg->status = SSL_ERR;
        sslctx_tbl_purge(handle);
        remove(full_pem_path);
        goto submit_missing_cert;
    }

    struct stat st;
    if (stat(full_pem_path, &st) != 0) {
        cbarg->status = SSL_MISS;
        
        struct timespec delay = {0, 300 * 1000000};
        nanosleep(&delay, NULL);

submit_missing_cert:
        enqueue_cert_job(pem_file);
        rv = CB_ERR;
        goto quit_cb;
    }

    SSL_CTX *sslctx = create_child_sslctx(full_pem_path, cbarg->cachain);
    if (!sslctx) {
        cbarg->status = SSL_ERR;
        rv = CB_ERR;
        goto quit_cb;
    }

    SSL_set_SSL_CTX(ssl, sslctx);
    
    X509 *cert = SSL_get_certificate(ssl);
    if (cert && X509_cmp_time(X509_get_notAfter(cert), NULL) < 0) {
        cbarg->status = SSL_ERR;
        remove(full_pem_path);
        goto submit_missing_cert;
    }

    if (sslctx_tbl_cache(pem_file, sslctx, ins_handle) < 0) {
        cbarg->status = SSL_ERR;
        rv = CB_ERR;
        goto quit_cb;
    }
    
    cbarg->status = SSL_HIT;

quit_cb:
    return rv;
}

static SSL_CTX* create_child_sslctx(const char* full_pem_path, const STACK_OF(X509_INFO) *cachain)
{
    SSL_CTX *sslctx = SSL_CTX_new(TLS_server_method());
    if (!sslctx) {
        return NULL;
    }

#if OPENSSL_VERSION_NUMBER >= 0x10101000L
    int groups[] = { NID_X9_62_prime256v1, NID_secp384r1 };
    SSL_CTX_set1_groups(sslctx, groups, sizeof(groups)/sizeof(groups[0]));
#elif OPENSSL_VERSION_NUMBER >= 0x10100000L
    SSL_CTX_set_ecdh_auto(sslctx, 1);
#else
    EC_KEY *ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (ecdh) {
        SSL_CTX_set_tmp_ecdh(sslctx, ecdh);
        EC_KEY_free(ecdh);
    }
#endif

    long options = SSL_OP_SINGLE_DH_USE |
                   SSL_OP_NO_COMPRESSION |
                   SSL_OP_NO_TICKET |
                   SSL_OP_NO_SSLv2 |
                   SSL_OP_NO_SSLv3 |
                   SSL_OP_CIPHER_SERVER_PREFERENCE;

#ifdef SSL_MODE_RELEASE_BUFFERS
    options |= SSL_MODE_RELEASE_BUFFERS;
#endif

#ifdef SSL_OP_NO_TLSv1_1
    options |= SSL_OP_NO_TLSv1_1;
#endif

    SSL_CTX_set_options(sslctx, options);

    SSL_CTX_set_session_cache_mode(sslctx, SSL_SESS_CACHE_NO_AUTO_CLEAR | SSL_SESS_CACHE_SERVER);
    SSL_CTX_set_timeout(sslctx, PIXEL_SSL_SESS_TIMEOUT);
    SSL_CTX_sess_set_cache_size(sslctx, 1);

    if (SSL_CTX_set_cipher_list(sslctx, PIXELSERV_CIPHER_LIST) <= 0) {
    }

#ifdef TLS1_3_VERSION
    SSL_CTX_set_min_proto_version(sslctx, TLS1_VERSION);
    SSL_CTX_set_max_proto_version(sslctx, TLS1_3_VERSION);
    if (SSL_CTX_set_ciphersuites(sslctx, PIXELSERV_TLSV1_3_CIPHERS) <= 0) {
    }
#endif

    if (SSL_CTX_use_certificate_file(sslctx, full_pem_path, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(sslctx, full_pem_path, SSL_FILETYPE_PEM) <= 0) {
        SSL_CTX_free(sslctx);
        return NULL;
    }

    if (cachain) {
        for (int i = sk_X509_INFO_num(cachain) - 1; i >= 0; i--) {
            X509_INFO *inf = sk_X509_INFO_value(cachain, i);
            if (inf && inf->x509) {
                X509 *cert_copy = X509_dup(inf->x509);
                if (!cert_copy || !SSL_CTX_add_extra_chain_cert(sslctx, cert_copy)) {
                    X509_free(cert_copy);
                    SSL_CTX_free(sslctx);
                    return NULL;
                }
            }
        }
    }

    return sslctx;
}

SSL_CTX* create_default_sslctx(const char *pem_dir)
{
    if (g_sslctx) return g_sslctx;

    g_sslctx = SSL_CTX_new(TLS_server_method());
    if (!g_sslctx) {
        return NULL;
    }

    long options = SSL_OP_NO_COMPRESSION |
                   SSL_OP_NO_SSLv2 |
                   SSL_OP_NO_SSLv3 |
                   SSL_OP_CIPHER_SERVER_PREFERENCE;

#ifdef SSL_MODE_RELEASE_BUFFERS
    options |= SSL_MODE_RELEASE_BUFFERS;
#endif

#ifdef SSL_OP_NO_TLSv1_1
    options |= SSL_OP_NO_TLSv1_1;
#endif

    SSL_CTX_set_options(g_sslctx, options);
    SSL_CTX_sess_set_cache_size(g_sslctx, PIXEL_SSL_SESS_CACHE_SIZE);
    SSL_CTX_set_session_cache_mode(g_sslctx, SSL_SESS_CACHE_SERVER);
    SSL_CTX_set_timeout(g_sslctx, PIXEL_SSL_SESS_TIMEOUT);

    if (SSL_CTX_set_cipher_list(g_sslctx, PIXELSERV_CIPHER_LIST) <= 0) {
    }

#ifdef TLS1_3_VERSION
    SSL_CTX_set_max_early_data(g_sslctx, PIXEL_TLS_EARLYDATA_SIZE);
    SSL_CTX_set_client_hello_cb(g_sslctx, tls_clienthello_cb, NULL);
#else
    SSL_CTX_set_tlsext_servername_callback(g_sslctx, tls_servername_cb);
#endif

    return g_sslctx;
}

int is_ssl_conn(int fd, char *srv_ip, int srv_ip_len, const int *ssl_ports, int num_ssl_ports) {
    char server_ip[INET6_ADDRSTRLEN] = {'\0'};
    struct sockaddr_storage sin_addr;
    socklen_t sin_addr_len = sizeof(sin_addr);
    char port[NI_MAXSERV] = {'\0'};
    int rv = 0;

    if (getsockname(fd, (struct sockaddr*)&sin_addr, &sin_addr_len) != 0 ||
        getnameinfo((struct sockaddr *)&sin_addr, sin_addr_len,
                   server_ip, sizeof server_ip,
                   port, sizeof port,
                   NI_NUMERICHOST | NI_NUMERICSERV) != 0) {
        return 0;
    }
    
    if (srv_ip && srv_ip_len > 0) {
        strncpy(srv_ip, server_ip, srv_ip_len - 1);
        srv_ip[srv_ip_len - 1] = '\0';
    }
    
    int port_num = atoi(port);
    for (int i = 0; i < num_ssl_ports; i++) {
        if (port_num == ssl_ports[i]) {
            rv = ssl_ports[i];
            break;
        }
    }

#ifdef DEBUG
    char client_ip[INET6_ADDRSTRLEN] = {'\0'};
    getpeername(fd, (struct sockaddr*)&sin_addr, &sin_addr_len);
    if (getnameinfo((struct sockaddr *)&sin_addr, sin_addr_len, client_ip,
                   sizeof client_ip, NULL, 0, NI_NUMERICHOST) == 0) {
    }
#endif

    return rv;
}

#ifdef TLS1_3_VERSION
char* read_tls_early_data(SSL *ssl, int *err)
{
    size_t buf_siz = PIXEL_TLS_EARLYDATA_SIZE;
    char *buf = malloc(PIXEL_TLS_EARLYDATA_SIZE + 1);
    if (!buf) {
        *err = SSL_ERROR_SYSCALL;
        return NULL;
    }

    char *pbuf = buf;
    int count = 0;
    *err = SSL_ERROR_NONE;

    for (;;) {
        size_t readbytes = 0;
        ERR_clear_error();
        int rv = SSL_read_early_data(ssl, pbuf, buf_siz, &readbytes);

        if (rv == SSL_READ_EARLY_DATA_FINISH) {
            if (buf == pbuf && readbytes == 0) {
                goto err_quit;
            } else {
                pbuf += readbytes;
                *pbuf = '\0';
            }
            break;
        } else if (rv == SSL_READ_EARLY_DATA_SUCCESS) {
            pbuf += readbytes;
            buf_siz -= readbytes;
            if (buf_siz <= 0) {
                goto err_quit;
            }
            continue;
        }

        switch (SSL_get_error(ssl, 0)) {
        case SSL_ERROR_WANT_WRITE:
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_ASYNC:
            if (count++ < 10) {
                struct timespec delay = {0, 60000000};
                nanosleep(&delay, NULL);
                continue;
            }
        default:
            *err = SSL_get_error(ssl, 0);
            goto err_quit;
        }
    }

#ifdef DEBUG
#endif

    return buf;

err_quit:
    free(buf);
    return NULL;
}
#endif

void run_benchmark(const cert_tlstor_t *ct, const char *cert)
{
    if (!ct || !ct->pem_dir) {
        return;
    }

    char *cert_file = NULL, *domain = NULL;
    struct stat st;
    struct timespec tm;
    float r_tm0 = 0.0, g_tm0 = 0.0, tm1;
    SSL_CTX *sslctx = NULL;

    printf("CERT_PATH: %s\n", ct->pem_dir);
    if (!ct->cachain) {
        printf("CA chain not loaded\n");
        goto quit;
    }

    const char *test_cert = cert ? cert : "_.bing.com";
    printf("CERT_FILE: ");
    
    if (asprintf(&cert_file, "%s/%s", ct->pem_dir, test_cert) < 0) {
        printf("Memory allocation failed\n");
        goto quit;
    }

    if (cert && stat(cert_file, &st) != 0) {
        printf("%s not found\n", cert);
        goto quit;
    }
    printf("%s\n", test_cert);

    if (asprintf(&domain, "%s", test_cert) < 0) {
        printf("Memory allocation failed for domain\n");
        goto quit;
    }
    
    if (domain[0] == '_') domain[0] = '*';

    for (int c = 1; c <= 10; c++) {
        get_time(&tm);
        for (int d = 0; d < 5; d++) {
            generate_cert(domain, ct->pem_dir, ct->issuer, ct->privkey, ct->cachain);
        }
        tm1 = elapsed_time_msec(tm) / 5.0;
        printf("%2d. generate cert to disk: %.3f ms\t", c, tm1);
        g_tm0 += tm1;

        get_time(&tm);
        for (int d = 0; d < 5; d++) {
            if (stat(cert_file, &st) == 0) {
                sslctx = create_child_sslctx(cert_file, ct->cachain);
                if (sslctx) {
                    sslctx_tbl_cache(test_cert, sslctx, 0);
                }
            }
        }
        tm1 = elapsed_time_msec(tm) / 5.0;
        printf("load from disk: %.3f ms\n", tm1);
        r_tm0 += tm1;
    }
    
    printf("generate to disk average: %.3f ms\n", g_tm0 / 10.0);
    printf("  load from disk average: %.3f ms\n", r_tm0 / 10.0);

quit:
    free(cert_file);
    free(domain);
}

SSL_CTX* sslctx_tbl_get_ctx(const char *cert_name) {
    if (!cert_name) return NULL;
    
    int found_idx, ins_idx;
    if (sslctx_tbl_lookup(cert_name, &found_idx, &ins_idx) == 0 && found_idx >= 0) {
        return SSLCTX_TBL_get(found_idx, sslctx);
    }
    return NULL;
}

int validate_certificate_chain(SSL_CTX *ctx) {
    if (!ctx) return 0;
    
    X509_STORE *store = SSL_CTX_get_cert_store(ctx);
    if (!store) return 0;
    
    return 1;
}

int check_cert_expiration(const char *cert_path, time_t *expires_at) {
    FILE *fp = fopen(cert_path, "r");
    if (!fp) return -1;
    
    X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);
    
    if (!cert) return -1;
    
    ASN1_TIME *not_after = X509_get_notAfter(cert);
    if (!not_after) {
        X509_free(cert);
        return -1;
    }
    
    int days, seconds;
    if (ASN1_TIME_diff(&days, &seconds, NULL, not_after)) {
        if (expires_at) {
            *expires_at = time(NULL) + days * 86400 + seconds;
        }
        X509_free(cert);
        return (days > 0 || (days == 0 && seconds > 0)) ? 1 : 0;
    }
    
    X509_free(cert);
    return -1;
}

void log_ssl_errors(const char *operation) {
    unsigned long err;
    char err_buf[256];
    
    while ((err = ERR_get_error()) != 0) {
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
    }
}

void sslctx_tbl_cleanup_expired(void) {
    time_t now = time(NULL);
    
    for (int i = 0; i < sslctx_tbl_end; i++) {
        SSL_CTX *ctx = SSLCTX_TBL_get(i, sslctx);
        if (!ctx) continue;
        
        X509 *cert = SSL_CTX_get0_certificate(ctx);
        if (!cert) continue;
        
        if (X509_cmp_time(X509_get_notAfter(cert), &now) < 0) {
            sslctx_tbl_purge(i);
            i--;
        }
    }
}

size_t sslctx_tbl_memory_usage(void) {
    size_t total = 0;
    
    total += sslctx_tbl_size * sizeof(sslctx_cache_struct);
    
    for (int i = 0; i < sslctx_tbl_end; i++) {
        total += SSLCTX_TBL_get(i, alloc_len);
        total += 64 * 1024;
    }
    
    return total;
}

void pregenerate_common_certs(cert_tlstor_t *ct) {
    const char *common_domains[] = {
        "google.com", "facebook.com", "amazon.com", "microsoft.com",
        "apple.com", "netflix.com", "youtube.com", "twitter.com",
        "instagram.com", "linkedin.com", "github.com", "stackoverflow.com",
        NULL
    };
    
    if (!ct || !ct->privkey || !ct->issuer) {
        return;
    }
    
    int i;
    for (i = 0; common_domains[i]; i++) {
        enqueue_cert_job(common_domains[i]);
    }
}

void print_cert_statistics(void) {
    printf("\n=== Certificate Statistics ===\n");
    printf("Cache entries: %d/%d\n", sslctx_tbl_get_cnt_total(), sslctx_tbl_size);
    printf("Cache hits: %d\n", sslctx_tbl_get_cnt_hit());
    printf("Cache misses: %d\n", sslctx_tbl_get_cnt_miss());
    printf("Cache purges: %d\n", sslctx_tbl_get_cnt_purge());
    printf("SSL sessions: %d\n", sslctx_tbl_get_sess_cnt());
    printf("SSL session hits: %d\n", sslctx_tbl_get_sess_hit());
    printf("SSL session misses: %d\n", sslctx_tbl_get_sess_miss());
    printf("Memory usage: %.2f MB\n", sslctx_tbl_memory_usage() / (1024.0 * 1024.0));
    printf("Connection store: %d/%d\n", conn_stor_last + 1, conn_stor_max);
    printf("===============================\n");
}
