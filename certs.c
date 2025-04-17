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
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509v3.h>

#include "certs.h"
#include "logger.h"
#include "util.h"

#if defined(__GLIBC__) && !defined(__UCLIBC__)
#  include <malloc.h>
#endif

static pthread_mutex_t *locks;
static SSL_CTX *g_sslctx;

static sslctx_cache_struct *sslctx_tbl;
static int sslctx_tbl_size, sslctx_tbl_end;
static int sslctx_tbl_cnt_hit, sslctx_tbl_cnt_miss, sslctx_tbl_cnt_purge;
static unsigned int  sslctx_tbl_last_flush;

static void **conn_stor;
static int conn_stor_last = -1, conn_stor_max = -1;
static pthread_mutex_t cslock;

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
        log_msg(LGG_ERR, "%s invalid slots %d", __FUNCTION__, slots);
        return;
    }
    conn_stor = malloc(slots * sizeof(void *));
    if (!conn_stor)
        log_msg(LGG_ERR, "Failed to allocate conn_stor of size %d", slots);
    conn_stor_last = -1;
    conn_stor_max = slots;
    pthread_mutex_init(&cslock, NULL);
}

void conn_stor_flush() {
    if (conn_stor_max < 0 || conn_stor_last < 0 || conn_stor_last <= conn_stor_max / 2)
        return;
    int threshold = conn_stor_max / 2;
    pthread_mutex_lock(&cslock);
    for (;conn_stor_last >= threshold && conn_stor[conn_stor_last] != NULL; conn_stor_last--) {
        free(conn_stor[conn_stor_last]);
    }
    pthread_mutex_unlock(&cslock);
}

void conn_stor_relinq(conn_tlstor_struct *p) {
    pthread_mutex_lock(&cslock);
    if (conn_stor_last >= conn_stor_max)
        log_msg(LGG_CRIT, "%s conn_stor overflow", __FUNCTION__);
    else
        conn_stor[++conn_stor_last] = p;
    pthread_mutex_unlock(&cslock);
}

conn_tlstor_struct* conn_stor_acquire() {
    conn_tlstor_struct *ret = NULL;

    pthread_mutex_lock(&cslock);
    if (conn_stor_last > 0) {
        ret = conn_stor[conn_stor_last];
        conn_stor[conn_stor_last--] = NULL;
    }
    pthread_mutex_unlock(&cslock);

    if (ret == NULL) {
        ret = malloc(sizeof(conn_tlstor_struct));
        if (ret != NULL) {
            memset(ret, 0, sizeof(conn_tlstor_struct));
            ret->tlsext_cb_arg = &ret->v;
        }
    }
    return ret;
}

void sslctx_tbl_init(int tbl_size)
{
    if (tbl_size <= 0)
        return;
    sslctx_tbl_end = 0;
    sslctx_tbl = malloc(tbl_size * sizeof(sslctx_cache_struct));
    if (!sslctx_tbl) {
        sslctx_tbl_size = 0;
        log_msg(LGG_ERR, "Failed to allocate sslctx_tbl of size %d", tbl_size);
    } else {
        sslctx_tbl_size = tbl_size;
        sslctx_tbl_cnt_hit = sslctx_tbl_cnt_miss = sslctx_tbl_cnt_purge = sslctx_tbl_last_flush = 0;
        memset(sslctx_tbl, 0, tbl_size * sizeof(sslctx_cache_struct));
    }
}

void sslctx_tbl_cleanup()
{
    int idx;
    for (idx = 0; idx < sslctx_tbl_end; idx++) {
        free(SSLCTX_TBL_get(idx, cert_name));
        SSL_CTX_free(SSLCTX_TBL_get(idx, sslctx));
    }
}

static int cmp_sslctx_reuse_count(const void *p1, const void *p2)
{
    /* reverse order */
    return ((sslctx_cache_struct *)p2)->reuse_count - ((sslctx_cache_struct *)p1)->reuse_count;
}

static int cmp_sslctx_certname(const void *k, const void *p)
{
    return strcmp(((sslctx_cache_struct *)k)->cert_name, ((sslctx_cache_struct *)p)->cert_name);
}

void sslctx_tbl_load(const char* pem_dir, const STACK_OF(X509_INFO) *cachain)
{
    FILE *fp;
    char *fname = NULL, *line;
    if ((line = malloc(PIXELSERV_MAX_PATH)) == NULL || (fname = malloc(PIXELSERV_MAX_PATH)) == NULL) {
        log_msg(LGG_ERR, "%s: failed to allocate memory", __FUNCTION__);
        goto quit_load;
    }

    (void)snprintf(fname, PIXELSERV_MAX_PATH, "%s/prefetch", pem_dir);
    if((fp = fopen(fname, "r")) == NULL) {
        log_msg(LGG_WARNING, "%s: %s doesn't exist.", __FUNCTION__, fname);
        goto quit_load;
    }

    while (getline(&line, &(size_t){ PIXELSERV_MAX_PATH }, fp) != -1) {
        char *cert_name = strtok(line, " \n\t");
        (void)snprintf(fname, PIXELSERV_MAX_PATH, "%s/%s", pem_dir, cert_name);

        SSL_CTX *sslctx = create_child_sslctx(fname, cachain);
        if (sslctx) {
            int ins_idx = sslctx_tbl_end;
            sslctx_tbl_insert(cert_name, sslctx, ins_idx);
            log_msg(LGG_NOTICE, "%s: %s", __FUNCTION__, cert_name);
        }
        if (sslctx_tbl_end >= sslctx_tbl_size)
            break;
    }
    fclose(fp);
    sslctx_tbl_cnt_miss = 0; /* reset */
    qsort(SSLCTX_TBL_ptr(0), sslctx_tbl_end, sizeof(sslctx_cache_struct), cmp_sslctx_certname);
quit_load:
    free(fname);
    free(line);
}

void sslctx_tbl_save(const char* pem_dir)
{
    #define RATIO_TO_SAVE 1
    int idx;
    char *fname;
    FILE *fp;

    if ((fname = malloc(PIXELSERV_MAX_PATH)) == NULL) {
        log_msg(LGG_ERR, "%s: failed to allocate memory", __FUNCTION__);
        goto quit_save;
    }
    (void)snprintf(fname, PIXELSERV_MAX_PATH, "%s/prefetch", pem_dir);

    if ((fp = fopen(fname, "w")) == NULL) {
        log_msg(LGG_ERR, "%s: failed to open %s", __FUNCTION__, fname);
        goto quit_save;
    }
    qsort(SSLCTX_TBL_ptr(0), sslctx_tbl_end, sizeof(sslctx_cache_struct), cmp_sslctx_reuse_count);
    if (sslctx_tbl_end > (sslctx_tbl_size * RATIO_TO_SAVE))
        sslctx_tbl_end = sslctx_tbl_size * RATIO_TO_SAVE;

    for (idx=0; idx < sslctx_tbl_end; idx++)
        fprintf(fp, "%s\t%d\n", SSLCTX_TBL_get(idx, cert_name), SSLCTX_TBL_get(idx, reuse_count));
    fclose(fp);
quit_save:
    free(fname);
}

void sslctx_tbl_lock(int idx)
{
    if (idx < 0 || idx >= sslctx_tbl_size) {
        log_msg(LOG_DEBUG, "%s: invalid idx %d", __FUNCTION__, idx);
        return;
    }
    pthread_mutex_lock(&SSLCTX_TBL_get(idx, lock));
}

void sslctx_tbl_unlock(int idx)
{
    if (idx < 0 || idx >= sslctx_tbl_size) {
        log_msg(LOG_DEBUG, "%s: invalid idx %d", __FUNCTION__, idx);
        return;
    }
    pthread_mutex_unlock(&SSLCTX_TBL_get(idx, lock));
}

static int sslctx_tbl_check_and_flush(void)
{
    int pixel_now = process_uptime(), rv = -1;
#ifdef DEBUG
    printf("%s: now %d last_flush %d", __FUNCTION__, pixel_now, sslctx_tbl_last_flush);
#endif

    /* flush at most every half of session timeout */
    int do_flush = pixel_now - sslctx_tbl_last_flush - PIXEL_SSL_SESS_TIMEOUT / 2;
    if (do_flush < 0) {
        rv = -1;
    } else {
        SSL_CTX_flush_sessions(g_sslctx, time(NULL));
        sslctx_tbl_last_flush = pixel_now;
        rv = 1;
    }
    return rv;
}

static int sslctx_tbl_lookup(char* cert_name, int* found_idx, int* ins_idx)
{
    *found_idx = -1; *ins_idx = -1;
    if (!cert_name || !found_idx || !ins_idx) {
        log_msg(LOG_ERR, "Invalid params. cert_name: %s. found_idx: %d, ins_idx: %d",
            cert_name, found_idx, ins_idx);
        return -1;
    }

    sslctx_cache_struct key, *found;
    key.cert_name = cert_name;
    found = bsearch(&key, SSLCTX_TBL_ptr(0), sslctx_tbl_end, sizeof(sslctx_cache_struct), cmp_sslctx_certname);

    if (found != NULL) {
        sslctx_tbl_cnt_hit++;
        found->reuse_count++;
        found->last_use = process_uptime();
        *found_idx = (found - SSLCTX_TBL_ptr(0));
    } else if (sslctx_tbl_end < sslctx_tbl_size) {
        *ins_idx = sslctx_tbl_end;
    } else {
        int idx, purge_idx = 0; // decimate the first entry if no suitable candiate
        unsigned int _last_use = process_uptime();

        for (idx = 0; idx < sslctx_tbl_end; idx++) {
            if (SSLCTX_TBL_get(idx, last_use) < _last_use) {
                _last_use = SSLCTX_TBL_get(idx, last_use);
                purge_idx = idx;
            }
        }
        *ins_idx = purge_idx;
    }
    return 0;
}

static int sslctx_tbl_insert(const char *cert_name, SSL_CTX *sslctx, int ins_idx)
{
    if (cert_name == NULL || sslctx == NULL || ins_idx >= sslctx_tbl_size || ins_idx < 0) {
        log_msg(LOG_ERR, "Invalid params. cert_name: %s. sslctx: %d, ins_idx: %d",
            cert_name, sslctx, ins_idx);
        return -1;
    }
    sslctx_tbl_cnt_miss++;

    /* add new cache entry */
    unsigned int pixel_now = process_uptime();
    int len = strlen(cert_name);
    char *str = SSLCTX_TBL_get(ins_idx, cert_name);
    if ((len + 1) > SSLCTX_TBL_get(ins_idx, alloc_len)) {
        str = realloc(str, len + 1);
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
        printf("%s: SSL_CTX_free %p sslctx_tbl_end %d\n", __FUNCTION__, SSLCTX_TBL_get(ins_idx, sslctx), sslctx_tbl_end);
#endif
        SSL_CTX_free(SSLCTX_TBL_get(ins_idx, sslctx));
        sslctx_tbl_cnt_purge++;
    }
    SSLCTX_TBL_set(ins_idx, sslctx, sslctx);
    return 0;
}

static int sslctx_tbl_cache(const char *cert_name, SSL_CTX *sslctx, int ins_idx)
{   int ret = -1;
    if (sslctx_tbl_insert(cert_name, sslctx, ins_idx) == 0) {
        qsort(SSLCTX_TBL_ptr(0), sslctx_tbl_end, sizeof(sslctx_cache_struct), cmp_sslctx_certname);
        ret = 0;
    }
    return ret;
}

static int sslctx_tbl_purge(int idx) {
    if (idx < 0 || idx >= sslctx_tbl_end || sslctx_tbl_end <= 0)
        return -1;

    if (!SSLCTX_TBL_get(idx, cert_name))
        free(SSLCTX_TBL_get(idx, cert_name));
    if (!SSLCTX_TBL_get(idx, sslctx))
        SSL_CTX_free(SSLCTX_TBL_get(idx, sslctx));
    --sslctx_tbl_end;
    if (idx < sslctx_tbl_end) {
        memmove(SSLCTX_TBL_ptr(idx), SSLCTX_TBL_ptr(idx+1), sizeof(sslctx_cache_struct) * (sslctx_tbl_end - idx));
        memset(SSLCTX_TBL_ptr(sslctx_tbl_end), 0, sizeof(sslctx_cache_struct));
    } else {
        memset(SSLCTX_TBL_ptr(sslctx_tbl_end), 0, sizeof(sslctx_cache_struct));
    }

    return 0;
}

#ifdef DEBUG
static void sslctx_tbl_dump(int idx, const char * func)
{
    printf("%s: idx %d now %d\n", func, idx, process_uptime());
    printf("** cert_name %s\n", sslctx_tbl[idx].cert_name);
    printf("** alloc_len %d\n", sslctx_tbl[idx].alloc_len);
    printf("** last_use %d\n", sslctx_tbl[idx].last_use);
    printf("** reuse_count %d\n", sslctx_tbl[idx].reuse_count);
    printf("** sslctx %p\n", sslctx_tbl[idx].sslctx);
}
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L
static void ssl_lock_cb(int mode, int type, const char *file, int line)
{
    if (mode & CRYPTO_LOCK)
        pthread_mutex_lock(&(locks[type]));
    else
        pthread_mutex_unlock(&(locks[type]));
}
#endif

void ssl_thread_id(CRYPTO_THREADID *id)
{
    CRYPTO_THREADID_set_numeric(id, (unsigned long) pthread_self());
}

void ssl_init_locks()
{
#ifdef DEBUG
    printf("%s: CRYPTO_num_locks = %d\n", __FUNCTION__, CRYPTO_num_locks());
#endif
    int i;
    locks = (pthread_mutex_t *)OPENSSL_malloc(CRYPTO_num_locks()*sizeof(pthread_mutex_t));
    for (i = 0; i < CRYPTO_num_locks(); i++)
        pthread_mutex_init(&(locks[i]), NULL);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    CRYPTO_THREADID_set_callback((void (*)(CRYPTO_THREADID *)) ssl_thread_id);
    CRYPTO_set_locking_callback((void (*)(int, int, const char *, int)) ssl_lock_cb);
#endif
}

void ssl_free_locks()
{
    int i;
    CRYPTO_set_locking_callback(NULL);
    for (i = 0; i < CRYPTO_num_locks(); i++)
        pthread_mutex_destroy(&(locks[i]));

    OPENSSL_free(locks);
}

static void generate_cert(char* pem_fn, const char *pem_dir, X509_NAME *issuer, EVP_PKEY *privkey)
{
    char fname[PIXELSERV_MAX_PATH];
    EVP_PKEY *key = NULL;
    X509 *x509 = NULL;
    X509_EXTENSION *ext = NULL;
#define SAN_STR_SIZE PIXELSERV_MAX_SERVER_NAME + 4 /* max("IP:", "DNS:") = 4 */
    char san_str[SAN_STR_SIZE];
    char *tld = NULL, *tld_tmp = NULL;
    int dot_count = 0;
    EVP_MD_CTX *p_ctx = NULL;

    p_ctx = EVP_MD_CTX_create();
    if(EVP_DigestSignInit(p_ctx, NULL, EVP_sha256(), NULL, privkey) != 1)
        log_msg(LGG_ERR, "%s: failed to init sign context", __FUNCTION__);

    if(pem_fn[0] == '_') pem_fn[0] = '*';

    // -- generate cert
    BIGNUM *e = BN_new();
    BN_set_word(e, RSA_F4);
#if OPENSSL_VERSION_MAJOR >= 3
    key = EVP_RSA_gen(2048);
    if (!key)
        goto free_all;
#else
    RSA *rsa = RSA_new();
    if (RSA_generate_key_ex(rsa, 2048, e, NULL) < 0)
        goto free_all;
    key = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(key, rsa); // rsa will be freed when key is freed
#endif
#ifdef DEBUG
    printf("%s: rsa key generated for [%s]\n", __FUNCTION__, pem_fn);
#endif
    if((x509 = X509_new()) == NULL)
        goto free_all;
    ASN1_INTEGER_set(X509_get_serialNumber(x509),rand());
    X509_set_version(x509, 2); // X509 v3
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 3600*24*825L); // cert valid for 825 days
    X509_set_issuer_name(x509, issuer);
    X509_NAME *name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)pem_fn, -1, -1, 0);

    tld_tmp = strchr(pem_fn, '.');
    while(tld_tmp != NULL) {
        dot_count++;
        tld = tld_tmp + 1;
        tld_tmp = strchr(tld, '.');
    }
    tld_tmp = (dot_count == 3 && (atoi(tld) > 0 || (atoi(tld) == 0 && strlen(tld) == 1))) ? "IP" : "DNS";
    snprintf(san_str, SAN_STR_SIZE, "%s:%s", tld_tmp, pem_fn);
    if ((ext = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name, san_str)) == NULL)
        goto free_all;
    X509_add_ext(x509, ext, -1);
    X509_EXTENSION_free(ext);
    if ((ext = X509V3_EXT_conf_nid(NULL, NULL, NID_ext_key_usage, "TLS Web Server Authentication")) == NULL)
        goto free_all;
    X509_add_ext(x509, ext, -1);
    X509_set_pubkey(x509, key);
    X509_sign_ctx(x509, p_ctx);
#ifdef DEBUG
    printf("%s: x509 cert created\n", __FUNCTION__);
#endif

    // -- save cert
    if(pem_fn[0] == '*')
        pem_fn[0] = '_';
    snprintf(fname, PIXELSERV_MAX_PATH, "%s/%s", pem_dir, pem_fn);
    FILE *fp = fopen(fname, "wb");
    if(fp == NULL) {
        log_msg(LGG_ERR, "%s: failed to open file for write: %s", __FUNCTION__, fname);
        goto free_all;
    }
    PEM_write_X509(fp, x509);
    PEM_write_PrivateKey(fp, key, NULL, NULL, 0, NULL, NULL);
    fclose(fp);
    log_msg(LGG_NOTICE, "cert generated to disk: %s", pem_fn);

free_all:
    BN_free(e);
    EVP_MD_CTX_destroy(p_ctx);
    EVP_PKEY_free(key);
    X509_EXTENSION_free(ext);
    X509_free(x509);
}


static int pem_passwd_cb(char *buf, int size, int rwflag, void *u) {
    int rv = 0, fp;
    char *fname = NULL;
    if (asprintf(&fname, "%s/ca.key.passphrase", (char*)u) < 0)
        goto quit_cb;

    if ((fp = open(fname, O_RDONLY)) < 0)
        log_msg(LGG_ERR, "%s: failed to open ca.key.passphrase", __FUNCTION__);
    else {
        rv = read(fp, buf, size);
        close(fp);
#ifdef DEBUG
        buf[rv] = '\0';
        printf("%s: %d, %d\n", buf, size, rv);
#endif
    }

quit_cb:
    free(fname);
    return --rv; // trim \n at the end
}

void cert_tlstor_init(const char *pem_dir, cert_tlstor_t *ct)
{
    FILE *fp;
    char cert_file[PIXELSERV_MAX_PATH];
    X509 *x509 = X509_new();

    memset(ct, 0, sizeof(cert_tlstor_t));
    snprintf(cert_file, PIXELSERV_MAX_PATH, "%s/ca.crt", pem_dir);
    fp = fopen(cert_file, "r");

    if(!fp || !PEM_read_X509(fp, &x509, NULL, NULL))
       log_msg(LGG_ERR, "%s: failed to load ca.crt", __FUNCTION__);
    else {
        char *cafile;
        int fsz;
        BIO *bioin;
        EVP_PKEY *pubkey = X509_get_pubkey(x509);

        if (fseek(fp, 0L, SEEK_END) < 0)
            log_msg(LGG_ERR, "%s: failed to seek ca.crt", __FUNCTION__);

        fsz = ftell(fp);
        cafile = malloc(fsz);
        fseek(fp, 0L, SEEK_SET);
        fsz = fread(cafile, 1, fsz, fp);

        bioin = BIO_new_mem_buf(cafile, fsz);
        if (!bioin)
            log_msg(LGG_ERR, "%s: failed to create BIO mem buffer", __FUNCTION__);

        ct->pem_dir = pem_dir;
        ct->cachain = PEM_X509_INFO_read_bio(bioin, NULL, NULL, NULL);
        ct->issuer = X509_NAME_dup(X509_get_subject_name(x509));

        if (ct->cachain == NULL)
            log_msg(LGG_ERR, "%s: failed to read CA chains", __FUNCTION__);

        BIO_free(bioin);
        EVP_PKEY_free(pubkey);
        free(cafile);
        fclose(fp);
    }
    X509_free(x509);

    snprintf(cert_file, PIXELSERV_MAX_PATH, "%s/ca.key", pem_dir);
    fp = fopen(cert_file, "r");
    if(!fp || !PEM_read_PrivateKey(fp, &ct->privkey, pem_passwd_cb, (void*)pem_dir))
        log_msg(LGG_ERR, "%s: failed to load ca.key", __FUNCTION__);
    fclose(fp);
}

void cert_tlstor_cleanup(cert_tlstor_t *c)
{
    sk_X509_INFO_pop_free(c->cachain, X509_INFO_free);
    X509_NAME_free(c->issuer);
    EVP_PKEY_free(c->privkey);
}

void *cert_generator(void *ptr) {
#ifdef DEBUG
    printf("%s: thread up and running\n", __FUNCTION__);
#endif
    int idle = 0;
    cert_tlstor_t *ct = (cert_tlstor_t *) ptr;

    char buf[PIXELSERV_MAX_SERVER_NAME * 4 + 1];
    char *half_token = buf + PIXELSERV_MAX_SERVER_NAME * 4;
    buf[PIXELSERV_MAX_SERVER_NAME * 4] = '\0';

    /* non block required. otherwise blocked until other side opens */
    int fd = open(PIXEL_CERT_PIPE, O_RDONLY | O_NONBLOCK);
    srand((unsigned int)time(NULL));

    for (;;) {
        int ret;
        if(fd == -1)
            log_msg(LGG_ERR, "%s: failed to open %s: %s", PIXEL_CERT_PIPE, strerror(errno));
        strcpy(buf, half_token);
        struct pollfd pfd = { fd, POLLIN, POLLIN };
        ret = poll(&pfd, 1, 1000 * PIXEL_SSL_SESS_TIMEOUT / 4);
        if (ret <= 0) {
            /* timeout */
            sslctx_tbl_check_and_flush();
            if (kcc == 0) {
                if (++idle >= (3600 / (PIXEL_SSL_SESS_TIMEOUT / 4))) {
                    /* flush conn_stor after 3600 seconds */
                    conn_stor_flush();
                    idle = 0;
                }
#if defined(__GLIBC__) && !defined(__UCLIBC__)
                malloc_trim(0);
#endif
            }
            continue;
        }
        ssize_t cnt;
        if((cnt = read(fd, buf + strlen(half_token), PIXELSERV_MAX_SERVER_NAME * 4 - strlen(half_token))) == 0) {
#ifdef DEBUG
             printf("%s: pipe EOF\n", __FUNCTION__);
#endif
            close(fd);
            fd = open(PIXEL_CERT_PIPE, O_RDONLY | O_NONBLOCK); /* non block required */
            continue;
        }
        if (!cnt) continue;
        if ((size_t)cnt < PIXELSERV_MAX_SERVER_NAME * 4 - strlen(half_token)) {
            buf[cnt + strlen(half_token)] = '\0';
            half_token = buf + PIXELSERV_MAX_SERVER_NAME * 4;
        } else {
            size_t i = 0;
            for (i=1; buf[PIXELSERV_MAX_SERVER_NAME * 4 - i]!=':' && i < strlen(buf); i++);
            half_token = buf + PIXELSERV_MAX_SERVER_NAME * 4 - i + 1;
            buf[PIXELSERV_MAX_SERVER_NAME * 4 - i + 1] = '\0';
        }
        if (ct->privkey == NULL || ct->issuer == NULL)
            continue;
        char *p_buf, *p_buf_sav = NULL;
        p_buf = strtok_r(buf, ":", &p_buf_sav);
        while (p_buf != NULL) {
            char cert_file[PIXELSERV_MAX_PATH];
            struct stat st;
            snprintf(cert_file, PIXELSERV_MAX_PATH, "%s/%s", ((cert_tlstor_t*)ct)->pem_dir, p_buf);
            if(stat(cert_file, &st) != 0) /* doesn't exist */
                generate_cert(p_buf, ct->pem_dir, ct->issuer, ct->privkey);
            p_buf = strtok_r(NULL, ":", &p_buf_sav);
        }
        /* quick check and flush if time due */
        sslctx_tbl_check_and_flush();
    }
    return NULL;
}

#ifdef TLS1_3_VERSION
static char* get_server_name(SSL *s)
{
    const unsigned char *p;
    size_t len, remaining;

    /*
     * The server_name extension was given too much extensibility when it
     * was written, so parsing the normal case is a bit complex.
     */
    if (!SSL_client_hello_get0_ext(s, TLSEXT_TYPE_server_name, &p,
                                   &remaining) ||
        remaining <= 2)
        return NULL;
    /* Extract the length of the supplied list of names. */
    len = (*(p++) << 8);
    len += *(p++);
    if (len + 2 != remaining)
        return NULL;
    remaining = len;
    /*
     * The list in practice only has a single element, so we only consider
     * the first one.
     */
    if (remaining == 0 || *p++ != TLSEXT_NAMETYPE_host_name)
        return NULL;
    remaining--;
    /* Now we can finally pull out the byte array with the actual hostname. */
    if (remaining <= 2)
        return NULL;
    len = (*(p++) << 8);
    len += *(p++);
    if (len + 2 > remaining)
        return NULL;
    return (char *)p;
}

int tls_clienthello_cb(SSL *ssl, int *ad, void *arg) {
# define    CB_OK   1
# define    CB_ERR  0
#else
static int tls_servername_cb(SSL *ssl, int *ad, void *arg) {
# define    CB_OK   0
# define    CB_ERR  SSL_TLSEXT_ERR_ALERT_FATAL
#endif
    int rv = CB_OK;
    tlsext_cb_arg_struct *cbarg = (tlsext_cb_arg_struct *)arg;
    char full_pem_path[PIXELSERV_MAX_PATH + 1 + 1]; /* worst case ':\0' */
    int len;

    len = strlen(cbarg->tls_pem);
    full_pem_path[PIXELSERV_MAX_PATH] = '\0';
    strncpy(full_pem_path, cbarg->tls_pem, PIXELSERV_MAX_PATH);
    full_pem_path[len++] = '/';
    full_pem_path[len] = '\0';

    char *srv_name = NULL;
#ifdef TLS1_3_VERSION
    srv_name = (char*)get_server_name(ssl);
#else
    srv_name = (char*)(char*)SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
#endif
    if (srv_name)
        strncpy(cbarg->servername, srv_name, sizeof(cbarg->servername) - 1);
    else if (strlen(cbarg->servername))
        srv_name = cbarg->servername;
    else {
        log_msg(LGG_WARNING, "SNI failed. server name and ip empty.");
        rv = CB_ERR;
        goto quit_cb;
    }
#ifdef DEBUG
    printf("SNI servername: %s\n", srv_name);
#endif

    int dot_count = 0;
    char *tld = NULL;
    char *pem_file = strchr(srv_name, '.');
    while(pem_file){
        dot_count++;
        tld = pem_file + 1;
        pem_file = strchr(tld, '.');
    }
    if (dot_count <= 1 || (dot_count == 2 && strlen(tld) == 2) || (dot_count == 3 && atoi(tld) > 0)) {
        pem_file = srv_name;
        strncat(full_pem_path, srv_name, PIXELSERV_MAX_PATH - len);
        len += strlen(srv_name);
    } else {
        pem_file = full_pem_path + strlen(full_pem_path);
        strncat(full_pem_path, "_", PIXELSERV_MAX_PATH - len);
        len += 1;
        strncat(full_pem_path, strchr(srv_name, '.'), PIXELSERV_MAX_PATH - len);
        len += strlen(strchr(srv_name, '.'));
    }
#ifdef DEBUG
    printf("PEM filename: %s\n",full_pem_path);
#endif
    if (len > PIXELSERV_MAX_PATH) {
        log_msg(LGG_ERR, "%s: buffer overflow. %s", __FUNCTION__, full_pem_path);
        rv = CB_ERR;
        goto quit_cb;
    }

    int handle, ins_handle;
    sslctx_tbl_lookup(pem_file, &handle, &ins_handle);
#ifdef DEBUG
    printf("%s: handle %d ins_handle %d\n", __FUNCTION__, handle, ins_handle);
    if (handle >=0)
        sslctx_tbl_dump(handle, __FUNCTION__);
    if (ins_handle >=0) sslctx_tbl_dump(ins_handle, __FUNCTION__);
#endif

    if (handle >= 0) {
        SSL_set_SSL_CTX(ssl, SSLCTX_TBL_get(handle, sslctx));
        if (X509_cmp_time(X509_get_notAfter(SSL_get_certificate(ssl)), NULL) > 0) {
            cbarg->status = SSL_HIT;
            goto quit_cb;
        }
        // the certificate has expired. let's re-generate
        cbarg->status = SSL_ERR;
        log_msg(LGG_WARNING, "Expired certificate %s", pem_file);
        sslctx_tbl_purge(handle);
        remove(full_pem_path);
        goto submit_missing_cert;
    }

    struct stat st;
    if (stat(full_pem_path, &st) != 0) {
        int fd;
        cbarg->status = SSL_MISS;
        log_msg(LGG_WARNING, "%s %s missing", srv_name, pem_file);

submit_missing_cert:

        if ((fd = open(PIXEL_CERT_PIPE, O_WRONLY)) < 0)
            log_msg(LGG_ERR, "%s: failed to open pipe: %s", __FUNCTION__, strerror(errno));
        else {
            size_t i = 0;
            for(i=0; i< strlen(pem_file); i++)
                *(full_pem_path + i) = *(pem_file + i);
            *(full_pem_path + i) = ':';
            *(full_pem_path + i + 1) = '\0';

            if (write(fd, full_pem_path, strlen(full_pem_path)) < 0)
                log_msg(LGG_ERR, "%s: failed to write pipe: %s", __FUNCTION__, strerror(errno));
            close(fd);
        }

        rv = CB_ERR;
        goto quit_cb;
    }

    SSL_CTX *sslctx = NULL;
    if (NULL == (sslctx = create_child_sslctx(full_pem_path, cbarg->cachain))) {
        log_msg(LGG_ERR, "%s: fail to create sslctx or cache %s", __FUNCTION__, pem_file);
        cbarg->status = SSL_ERR;
        rv = CB_ERR;
        goto quit_cb;
    }

    SSL_set_SSL_CTX(ssl, sslctx);
    if (X509_cmp_time(X509_get_notAfter(SSL_get_certificate(ssl)), NULL) < 0) {
        // the certificate has expired. let's re-generate
        cbarg->status = SSL_ERR;
        log_msg(LGG_WARNING, "Expired certificate %s", pem_file);
        remove(full_pem_path);
        goto submit_missing_cert;
    }

    if (sslctx_tbl_cache(pem_file, sslctx, ins_handle) < 0) {
        log_msg(LGG_ERR, "%s: fail to create sslctx or cache %s", __FUNCTION__, pem_file);
        cbarg->status = SSL_ERR;
        rv = CB_ERR;
        goto quit_cb;
    }
    cbarg->status = SSL_HIT;

quit_cb:
    return rv;
}

/*
static int new_session(SSL *ssl, SSL_SESSION *sess) {
    return 1; // keep internal session
}

static void remove_session(SSL_CTX *sslctx, SSL_SESSION *sess) {
}

static SSL_SESSION *get_session(SSL *ssl, unsigned char *id, int idlen, int *do_copy) {
    return NULL;
}
*/

static SSL_CTX* create_child_sslctx(const char* full_pem_path, const STACK_OF(X509_INFO) *cachain)
{
    SSL_CTX *sslctx = SSL_CTX_new(SSLv23_server_method());
#if OPENSSL_VERSION_NUMBER < 0x10101000L
    EC_KEY *ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ecdh)
        log_msg(LGG_ERR, "%s: cannot get ECDH curve", __FUNCTION__);
    SSL_CTX_set_tmp_ecdh(sslctx, ecdh);
    EC_KEY_free(ecdh);
#else
    int glist [] = { NID_X9_62_prime256v1 };
    SSL_CTX_set1_groups(sslctx, glist, sizeof(glist)/sizeof(glist[0]));
#endif

    SSL_CTX_set_options(sslctx,
          SSL_OP_SINGLE_DH_USE |
          SSL_MODE_RELEASE_BUFFERS |
          SSL_OP_NO_COMPRESSION | SSL_OP_NO_TICKET |
          SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1_1 |
          SSL_OP_CIPHER_SERVER_PREFERENCE);
    /* server-side caching */
    SSL_CTX_set_session_cache_mode(sslctx, SSL_SESS_CACHE_NO_AUTO_CLEAR | SSL_SESS_CACHE_SERVER);
    SSL_CTX_set_timeout(sslctx, PIXEL_SSL_SESS_TIMEOUT);
    SSL_CTX_sess_set_cache_size(sslctx, 1);
    if (SSL_CTX_set_cipher_list(sslctx, PIXELSERV_CIPHER_LIST) <= 0)
        log_msg(LGG_DEBUG, "%s: failed to set cipher list", __FUNCTION__);
#ifdef TLS1_3_VERSION
    SSL_CTX_set1_groups_list(sslctx, "X25519:P-256");
    SSL_CTX_set_min_proto_version(sslctx, TLS1_VERSION);
    SSL_CTX_set_max_proto_version(sslctx, TLS1_3_VERSION);
    if (SSL_CTX_set_ciphersuites(sslctx, PIXELSERV_TLSV1_3_CIPHERS) <= 0)
        log_msg(LGG_DEBUG, "%s: failed to set TLSv1.3 ciphersuites", __FUNCTION__);
#endif
    if(SSL_CTX_use_certificate_file(sslctx, full_pem_path, SSL_FILETYPE_PEM) <= 0
       || SSL_CTX_use_PrivateKey_file(sslctx, full_pem_path, SSL_FILETYPE_PEM) <= 0)
    {
        SSL_CTX_free(sslctx);
        log_msg(LGG_ERR, "%s: cannot find or use %s\n", __FUNCTION__, full_pem_path);
        return NULL;
    }
    if (cachain) {
        X509_INFO *inf; int i;
        for (i=sk_X509_INFO_num(cachain)-1; i >= 0; i--) {
            if ((inf = sk_X509_INFO_value(cachain, i)) && inf->x509 &&
                    !SSL_CTX_add_extra_chain_cert(sslctx, X509_dup(inf->x509)))
            {
                SSL_CTX_free(sslctx);
                log_msg(LGG_ERR, "%s: cannot add CA cert %d\n", i, __FUNCTION__);  /* X509_ref_up requires >= v1.1 */
                return NULL;
            }
        }
    }
    return sslctx;
}

SSL_CTX* create_default_sslctx(const char *pem_dir)
{
    if (g_sslctx)
        return g_sslctx;

    g_sslctx = SSL_CTX_new(SSLv23_server_method());
    SSL_CTX_set_options(g_sslctx,
          SSL_MODE_RELEASE_BUFFERS |
          SSL_OP_NO_COMPRESSION |
          SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1_1 |
          SSL_OP_CIPHER_SERVER_PREFERENCE);
    SSL_CTX_sess_set_cache_size(g_sslctx, PIXEL_SSL_SESS_CACHE_SIZE);
    SSL_CTX_set_session_cache_mode(g_sslctx, SSL_SESS_CACHE_SERVER);
    SSL_CTX_set_timeout(g_sslctx, PIXEL_SSL_SESS_TIMEOUT);
/*    // cb for server-side caching
    SSL_CTX_sess_set_new_cb(g_sslctx, new_session);
    SSL_CTX_sess_set_remove_cb(g_sslctx, remove_session); */
    if (SSL_CTX_set_cipher_list(g_sslctx, PIXELSERV_CIPHER_LIST) <= 0)
        log_msg(LGG_DEBUG, "cipher_list cannot be set");
#ifndef TLS1_3_VERSION
    SSL_CTX_set_tlsext_servername_callback(g_sslctx, tls_servername_cb);
#else
    SSL_CTX_set_max_early_data(g_sslctx, PIXEL_TLS_EARLYDATA_SIZE);
#endif
    return g_sslctx;
}

int is_ssl_conn(int fd, char *srv_ip, int srv_ip_len, const int *ssl_ports, int num_ssl_ports) {

    char server_ip[INET6_ADDRSTRLEN] = {'\0'};
    struct sockaddr_storage sin_addr;
    socklen_t sin_addr_len = sizeof(sin_addr);
    char port[NI_MAXSERV] = {'\0'};
    int rv = 0, i;
    errno = 0;
    getsockname(fd, (struct sockaddr*)&sin_addr, &sin_addr_len);
    if(getnameinfo((struct sockaddr *)&sin_addr, sin_addr_len,
                   server_ip, sizeof server_ip,
                   port, sizeof port,
                   NI_NUMERICHOST | NI_NUMERICSERV) != 0)
        log_msg(LGG_ERR, "getnameinfo: %s", strerror(errno));
    if (srv_ip)
        strncpy(srv_ip, server_ip, srv_ip_len);
    for(i=0; i<num_ssl_ports; i++)
        if(atoi(port) == ssl_ports[i])
            rv = ssl_ports[i];
#ifdef DEBUG
    char client_ip[INET6_ADDRSTRLEN]= {'\0'};
    getpeername(fd, (struct sockaddr*)&sin_addr, &sin_addr_len);
    if(getnameinfo((struct sockaddr *)&sin_addr, sin_addr_len, client_ip, \
            sizeof client_ip, NULL, 0, NI_NUMERICHOST) != 0)
        perror("getnameinfo");
    printf("** NEW CONNECTION ** %s:%s\n", client_ip, port);
#endif

    return rv;
}

#ifdef TLS1_3_VERSION
char* read_tls_early_data(SSL *ssl, int *err)
{
    ssize_t buf_siz = PIXEL_TLS_EARLYDATA_SIZE;
    char *buf, *pbuf;
    int count = 0;

    *err = SSL_ERROR_NONE;
    buf = malloc(PIXEL_TLS_EARLYDATA_SIZE + 1);
    if (!buf) {
        log_msg(LGG_DEBUG, "%s out of memory\n", __FUNCTION__);
        goto err_quit;
    }
    pbuf = buf;
    for (;;) {
        size_t readbytes = 0;
        ERR_clear_error();
        int rv = SSL_read_early_data(ssl, pbuf, buf_siz, &readbytes);
        if (rv == SSL_READ_EARLY_DATA_FINISH) {
            if (buf == pbuf && readbytes == 0)
                goto err_quit;
            else {
                pbuf += readbytes;
                *pbuf = '\0';
            }
            break;
        } else if (rv == SSL_READ_EARLY_DATA_SUCCESS) {
            pbuf += readbytes;
            buf_siz -= readbytes;
            if (buf_siz < 0) {
                log_msg(LGG_DEBUG, "%s API error\n", __FUNCTION__);
                goto err_quit;
            }
            continue;
        }
        /* SSL_READ_EARLY_DATA_ERROR */
        switch (SSL_get_error(ssl, 0)) {
        case SSL_ERROR_WANT_WRITE:
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_ASYNC:
            if (count++ < 10) /* 600ms total */
              continue;
              /* fall through */
        default:
            *err = SSL_get_error(ssl, 0);
            log_msg(LGG_DEBUG, "%s error: %d count: %d\n", __FUNCTION__, *err, count);
            goto err_quit;
        }
    }
#ifdef DEBUG
    printf("%s buf: %s\n", __FUNCTION__, buf);
#endif

    return buf;

err_quit:
    free(buf);
    return NULL;
}
#endif

void run_benchmark(const cert_tlstor_t *ct, const char *cert)
{
    int c, d;
    char *cert_file = NULL, *domain;
    struct stat st;
    struct timespec tm;
    float r_tm0, g_tm0, tm1;
    SSL_CTX *sslctx = NULL;

    printf("CERT_PATH: %s\n", ct->pem_dir);
    if (ct->cachain == NULL)
        goto quit;

    printf("CERT_FILE: ");
    if (cert) {
        if (asprintf(&cert_file, "%s/%s", ct->pem_dir, cert) < 0 \
            || stat(cert_file, &st) != 0)
        {
            printf("%s not found\n", cert);
            goto quit;
        }
    } else
        cert = "_.bing.com";
    if (asprintf(&cert_file, "%s/%s", ct->pem_dir, cert) > 0)
      printf("%s\n", cert);

    if (asprintf(&domain, "%s", cert) > 0 && domain[0] == '_')
      domain[0] = '*';

    r_tm0 = 0; g_tm0 = 0;
    for (c=1; c<=10; c++) {
        get_time(&tm);
        for (d=0; d<5; d++)
            generate_cert(domain, ct->pem_dir, ct->issuer, ct->privkey);
        tm1 = elapsed_time_msec(tm) / 5.0;
        printf("%2d. generate cert to disk: %.3f ms\t", c, tm1);
        g_tm0 += tm1;

        get_time(&tm);
        for (d=0; d<5; d++) {
            stat(cert_file, &st);
            sslctx = create_child_sslctx(cert_file, ct->cachain);
            sslctx_tbl_cache(cert, sslctx, 0);
        }
        tm1 = elapsed_time_msec(tm) / 5.0;
        printf("load from disk: %.3f ms\n", tm1);
        r_tm0 += tm1;

    }
    printf("generate to disk average: %.3f ms\n", g_tm0 / 10.0);
    printf("  load from disk average: %.3f ms\n", r_tm0 / 10.0);

    free(domain);
quit:
    free(cert_file);
}
