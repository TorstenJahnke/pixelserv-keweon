/*
* pixelserv.c a small mod to public domain server.c -- a stream socket server demo
* from http://beej.us/guide/bgnet/
* single pixel http string from http://proxytunnel.sourceforge.net/pixelserv.php
*/

#include <fcntl.h>
#include <pthread.h>
#ifdef DROP_ROOT
#include <pwd.h>
#endif
#ifdef TEST
#include <arpa/inet.h>
#endif
#ifdef linux
#include <linux/version.h>
#endif
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

#include "certs.h"
#include "logger.h"
#include "socket_handler.h"
#include "util.h"

#if defined(__GLIBC__) && !defined(__UCLIBC__)
#  include <malloc.h>
#endif

#ifndef SO_BINDTODEVICE
#  define SO_BINDTODEVICE IP_RECVIF
#endif

#define PAGE_SIZE 4096
#define THREAD_STACK_SIZE  9*PAGE_SIZE
#define TCP_FASTOPEN_QLEN  25

const char *tls_pem = DEFAULT_PEM_PATH;
int tls_ports[MAX_TLS_PORTS + 1] = {0}; /* one extra port for admin */
int num_tls_ports = 0;
int admin_port = 0;
struct Global *g;
cert_tlstor_t cert_tlstor;
pthread_t certgen_thread;

/* Signal handler with improved cleanup */
void signal_handler(int sig)
{
  if (sig != SIGTERM
   && sig != SIGUSR1
#ifdef DEBUG
   && sig != SIGUSR2
#endif
  ) {
    log_msg(LGG_WARNING, "Ignoring unsupported signal number: %d", sig);
    return;
  }

#ifdef DEBUG
  if (sig == SIGUSR2) {
    log_msg(LGG_INFO, "Main process caught signal %d file %s", sig, __FILE__);
  } else {
#endif
    if (sig == SIGTERM) {
      signal(SIGTERM, SIG_IGN);
    }

    /* Cleanup connection storage */
    conn_stor_flush();
    
    /* Remove certificate pipe */
    if (unlink(pixel_cert_pipe) == 0) {
        log_msg(LGG_NOTICE, "Removed cert pipe: %s", pixel_cert_pipe);
    } else {
        log_msg(LGG_WARNING, "Could not remove cert pipe %s: %s", pixel_cert_pipe, strerror(errno));
    }

#if defined(__GLIBC__) && !defined(__UCLIBC__)
    malloc_trim(0);
#endif

    /* Log final statistics */
    char* stats_string = get_stats(0, 0);
    if (stats_string) {
        log_msg(LGG_CRIT, "%s", stats_string);
        free(stats_string);
    }

    /* Save SSL context table */
    sslctx_tbl_save(tls_pem);

    if (sig == SIGTERM) {
      log_msg(LGG_NOTICE, "exit on SIGTERM");
      exit(EXIT_SUCCESS);
    }
#ifdef DEBUG
  }
#endif
}

int main (int argc, char* argv[])
{
  int sockfd = 0;
  int new_fd = 0;
  struct sockaddr_storage their_addr;
  socklen_t sin_size;
  char* version_string = NULL;
  time_t select_timeout = DEFAULT_TIMEOUT;
  time_t http_keepalive = DEFAULT_KEEPALIVE;
  int rv = 0;
  char* ip_addr = DEFAULT_IP;
  int use_ip = 0;
  struct addrinfo hints, *servinfo = NULL;
  int error = 0;
  int pipefd[2];
  response_struct pipedata = { 0 };
  char* ports[MAX_PORTS + 1];
  char *port = NULL;
  fd_set readfds;
  fd_set selectfds;
  int sockfds[MAX_PORTS] = {0};
  int select_rv = 0;
  int nfds = 0;
  int num_ports = 0;
  int i;
#ifdef IF_MODE
  char *ifname = "";
  int use_if = 0;
#endif
#ifdef DROP_ROOT
  char *user = DEFAULT_USER;
  struct passwd *pw = 0;
#endif
  char* stats_url = DEFAULT_STATS_URL;
  char* stats_text_url = DEFAULT_STATS_TEXT_URL;
  int do_204 = 1;
#ifndef TEST
  int do_foreground = 0;
#endif
  int do_redirect = 0;
  int do_benchmark = 0;
  char *bm_cert = NULL;
#ifdef DEBUG
  int warning_time = 0;
#endif
  int max_num_threads = DEFAULT_THREAD_MAX;
  int cert_cache_size = DEFAULT_CERT_CACHE_SIZE;

  /* Initialize OpenSSL */
#if !OPENSSL_API_1_1
  SSL_library_init();
  SSL_load_error_strings();
#else
  OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
#endif

  /* Optimize memory allocation for high connection counts */
#if defined(__GLIBC__) && !defined(__UCLIBC__)
  mallopt(M_ARENA_MAX, 2); /* Increased for better multi-threading */
  mallopt(M_MMAP_THRESHOLD, 64 * 1024); /* Use mmap for larger allocations */
#endif

  /* Set resource limits */
  struct rlimit l = {THREAD_STACK_SIZE, THREAD_STACK_SIZE * 2};
  if (setrlimit(RLIMIT_STACK, &l) == -1) {
    log_msg(LGG_ERR, "setrlimit STACK failed: %ld %ld errno:%d", 
            (long)l.rlim_cur, (long)l.rlim_max, errno);
  }

  /* Set file descriptor limits for high-scale deployment */
  l.rlim_cur = max_num_threads + 100;
  l.rlim_max = max_num_threads * 2 + 200;
  if (setrlimit(RLIMIT_NOFILE, &l) == -1) {
    log_msg(LGG_ERR, "setrlimit NOFILE failed: %ld %ld errno:%d", 
            (long)l.rlim_cur, (long)l.rlim_max, errno);
  }

  /* Command line arguments processing */
  for (i = 1; i < argc && error == 0; ++i) {
    if (argv[i][0] == '-') {
      switch (argv[i][1]) {
        case '2': do_204 = 0; continue;
        case 'B':
          if ((i + 1) == argc || argv[i + 1][0] == '-') {
            do_benchmark = 1; 
            bm_cert = NULL;
            continue;
          }
          break;
#ifndef TEST
        case 'f': do_foreground = 1; continue;
#endif
        case 'r': /* deprecated - ignoring */ continue;
        case 'R': do_redirect = 1; continue;
        case 'l':
          if ((i + 1) == argc || argv[i + 1][0] == '-') {
            log_set_verb(LGG_INFO);
            continue;
          }
          /* fall through */
      }
      
      if ((i + 1) < argc) {
        switch (argv[i++][1]) {
          case 'B':
            do_benchmark = 1;
            if (argv[i][0] == '-') {
              error = 1;
            } else {
              bm_cert = argv[i];
            }
            continue;
          case 'c':
            errno = 0;
            cert_cache_size = strtol(argv[i], NULL, 10);
            if (errno || cert_cache_size <= 0) {
              error = 1;
            }
            continue;
          case 'l':
            if ((logger_level)atoi(argv[i]) > LGG_DEBUG || atoi(argv[i]) < 0) {
              error = 1;
            } else {
              log_set_verb((logger_level)atoi(argv[i]));
            }
            continue;
#ifdef IF_MODE
          case 'n':
            ifname = argv[i];
            use_if = 1;
            continue;
#endif
          case 'o':
            log_msg(LGG_ERR, "'-o SELECT_TIMEOUT' is deprecated. will be removed in a future version");
            continue;
          case 'O':
            errno = 0;
            http_keepalive = strtol(argv[i], NULL, 10);
            if (errno || http_keepalive <= 0) {
              error = 1;
            }
            continue;
          case 'A':
            if (num_tls_ports < MAX_TLS_PORTS) {
              admin_port = atoi(argv[i]);
            } else {
              error = 1;
            }
            /* fall through to case 'k' */
          case 'k':
            if (num_tls_ports < MAX_TLS_PORTS) {
              tls_ports[num_tls_ports++] = atoi(argv[i]);
            } else {
              error = 1;
            }
            /* fall through to case 'p' */
          case 'p':
            if (num_ports < MAX_PORTS) {
              ports[num_ports++] = argv[i];
            } else {
              error = 1;
            }
            continue;
          case 's': stats_url = argv[i]; continue;
          case 't': stats_text_url = argv[i]; continue;
          case 'T':
            errno = 0;
            max_num_threads = strtol(argv[i], NULL, 10);
            if (errno || max_num_threads <= 0) {
              error = 1;
            }
            continue;
#ifdef DROP_ROOT
          case 'u': user = argv[i]; continue;
#endif
#ifdef DEBUG
          case 'w':
            errno = 0;
            warning_time = strtol(argv[i], NULL, 10);
            if (errno || warning_time <= 0) {
              error = 1;
            }
            continue;
#endif
          case 'z':
            tls_pem = argv[i];
            continue;
          default: error = 1; continue;
        }
      } else {
        error = 1;
      }
    } else if (use_ip == 0) {
      ip_addr = argv[i];
      use_ip = 1;
    } else {
      error = 1;
    }
  }

  if (error) {
    printf("pixelserv-tls %s (compiled: " __DATE__ " " __TIME__ FEATURE_FLAGS ")\n"
           "Usage: pixelserv-tls [OPTION]" "\n"
           "options:" "\n"
           "\t" "ip_addr/hostname\t(default: 0.0.0.0)" "\n"
           "\t" "-2\t\t\t(disable HTTP 204 reply to generate_204 URLs)" "\n"
           "\t" "-A  ADMIN_PORT\t\t(HTTPS only. Default is none)" "\n"
           "\t" "-B  [CERT_FILE]\t\t(Benchmark crypto and disk then quit)" "\n"
           "\t" "-c  CERT_CACHE_SIZE\t(default: %d)" "\n"
#ifndef TEST
           "\t" "-f\t\t\t(stay in foreground/don't daemonize)" "\n"
#endif
           "\t" "-k  HTTPS_PORT\t\t(default: " SECOND_PORT ")" "\n"
           "\t" "-l  LEVEL\t\t(0:critical 1:error<default> 2:warning 3:notice 4:info 5:debug)" "\n"
#ifdef IF_MODE
           "\t" "-n  IFACE\t\t(default: all interfaces)" "\n"
#endif
           "\t" "-o  SELECT_TIMEOUT\t(deprecated; will be removed in a future version)" "\n"
           "\t" "-O  KEEPALIVE_TIME\t(for HTTP/1.1 connections; default: %ds)" "\n"
           "\t" "-p  HTTP_PORT\t\t(default: " DEFAULT_PORT ")" "\n"
           "\t" "-R\t\t\t(enable redirect to encoded path in URLs)" "\n"
           "\t" "-s  STATS_HTML_URL\t(default: " DEFAULT_STATS_URL ")" "\n"
           "\t" "-t  STATS_TXT_URL\t(default: " DEFAULT_STATS_TEXT_URL ")" "\n"
           "\t" "-T  MAX_THREADS\t\t(default: %d)\n"
#ifdef DROP_ROOT
           "\t" "-u  USER\t\t(default: \"nobody\")" "\n"
#endif
#ifdef DEBUG
           "\t" "-w  warning_time\t(warn when elapsed connection time exceeds value in msec)" "\n"
#endif
           "\t" "-z  CERT_PATH\t\t(default: " DEFAULT_PEM_PATH ")" "\n"
           , VERSION, DEFAULT_CERT_CACHE_SIZE, DEFAULT_KEEPALIVE, DEFAULT_THREAD_MAX);
    exit(EXIT_FAILURE);
  }

#ifndef TEST
  if (!do_foreground && !do_benchmark && daemon(0, 0)) {
    log_msg(LGG_ERR, "failed to daemonize, exit: %m");
    exit(EXIT_FAILURE);
  }
#endif

  openlog("pixelserv-tls",
#ifdef DEBUG
    LOG_PERROR |
#endif
    LOG_PID, LOG_DAEMON);

  version_string = get_version(argc, argv);
  if (version_string) {
    if (!do_benchmark) log_msg(LGG_CRIT, "%s", version_string);
    free(version_string);
  } else {
    exit(EXIT_FAILURE);
  }

  /* Generate random pipe path */
  generate_random_pipe_path(pixel_cert_pipe, sizeof(pixel_cert_pipe));
  if (mkfifo(pixel_cert_pipe, 0600) < 0 && errno != EEXIST) {
    log_msg(LGG_ERR, "Failed to create cert pipe: %s", strerror(errno));
    exit(EXIT_FAILURE);
  }

#ifdef DROP_ROOT
  pw = getpwnam(user);
  if (!pw) {
    log_msg(LGG_ERR, "Unknown user: %s", user);
    exit(EXIT_FAILURE);
  }
  if (chown(pixel_cert_pipe, pw->pw_uid, pw->pw_gid) < 0) {
    log_msg(LGG_CRIT, "chown failed to set owner of %s to %s", pixel_cert_pipe, user);
    exit(EXIT_FAILURE);
  }
#endif

  /* Initialize SSL and certificate handling */
  ssl_init_locks();
  cert_tlstor_init(tls_pem, &cert_tlstor);
  sslctx_tbl_init(cert_cache_size);
  conn_stor_init(max_num_threads);

  /* Load existing certificates */
  sslctx_tbl_load(tls_pem, cert_tlstor.cachain);
  SSL_CTX *sslctx = create_default_sslctx(tls_pem);
  if (!sslctx) {
    log_msg(LGG_ERR, "Failed to create default SSL context");
    exit(EXIT_FAILURE);
  }

  if (do_benchmark) {
    run_benchmark(&cert_tlstor, bm_cert);
    goto quit_main;
  } else {
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, THREAD_STACK_SIZE);
    if (pthread_create(&certgen_thread, &attr, cert_generator, (void*)&cert_tlstor) != 0) {
      log_msg(LGG_ERR, "Failed to create certificate generator thread");
      exit(EXIT_FAILURE);
    }
    pthread_attr_destroy(&attr);
  }

  /* Set up address hints */
  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  if (!use_ip) {
    hints.ai_flags = AI_PASSIVE;
  }

  /* Set default ports if none specified */
  if ((!admin_port && !num_ports) || (admin_port && num_ports == 1)) {
    tls_ports[num_tls_ports++] = atoi(SECOND_PORT);
    ports[num_ports++] = SECOND_PORT;
    ports[num_ports++] = DEFAULT_PORT;
  } else if ((!admin_port && !num_tls_ports) || (admin_port && num_tls_ports == 1)) {
    tls_ports[num_tls_ports++] = atoi(SECOND_PORT);
    ports[num_ports++] = SECOND_PORT;
  } else if (num_ports == num_tls_ports) {
    ports[num_ports++] = DEFAULT_PORT;
  }

  /* Initialize socket monitoring */
  FD_ZERO(&readfds);
  
  for (i = 0; i < num_ports; i++) {
    port = ports[i];

    rv = getaddrinfo(use_ip ? ip_addr : NULL, port, &hints, &servinfo);
    if (rv) {
      log_msg(LGG_ERR, "getaddrinfo: %s", gai_strerror(rv));
      exit(EXIT_FAILURE);
    }

    sockfd = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);
    if (sockfd < 1) {
      log_msg(LGG_CRIT, "socket() failed: %m");
      freeaddrinfo(servinfo);
      exit(EXIT_FAILURE);
    }

    /* Set socket options */
    int off = 0;
    if (servinfo->ai_family == AF_INET6 && 
        setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off)) < 0) {
      log_msg(LGG_WARNING, "Failed to set IPV6_V6ONLY: %m");
    }

    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int)) < 0 ||
        setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &(int){ 1 }, sizeof(int)) < 0) {
      log_msg(LGG_ERR, "Failed to set socket options: %m");
      close(sockfd);
      freeaddrinfo(servinfo);
      exit(EXIT_FAILURE);
    }

#ifdef IF_MODE
    if (use_if && setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname)) < 0) {
      log_msg(LGG_ERR, "Failed to bind to interface %s: %m", ifname);
      close(sockfd);
      freeaddrinfo(servinfo);
      exit(EXIT_FAILURE);
    }
#endif

#ifdef linux
#  if LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0) || defined(TCP_FASTOPEN)
    if (setsockopt(sockfd, IPPROTO_TCP, TCP_FASTOPEN, &(int){ TCP_FASTOPEN_QLEN }, sizeof(int)) < 0) {
      log_msg(LGG_DEBUG, "TCP_FASTOPEN not supported: %m");
    }
#  endif
#endif

    if (bind(sockfd, servinfo->ai_addr, servinfo->ai_addrlen) < 0 ||
        listen(sockfd, BACKLOG) < 0 ||
        fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL) | O_NONBLOCK) < 0) {
#ifdef IF_MODE
      log_msg(LGG_CRIT, "Abort: %m - %s:%s:%s", ifname, ip_addr, port);
#else
      log_msg(LGG_CRIT, "Abort: %m - %s:%s", ip_addr, port);
#endif
      close(sockfd);
      freeaddrinfo(servinfo);
      exit(EXIT_FAILURE);
    }

    sockfds[i] = sockfd;
    FD_SET(sockfd, &readfds);
    if (sockfd > nfds) {
      nfds = sockfd;
    }

    freeaddrinfo(servinfo);
    servinfo = NULL;

#ifdef IF_MODE
    log_msg(LGG_CRIT, "Listening on %s:%s:%s", ifname, ip_addr, port);
#else
    log_msg(LGG_CRIT, "Listening on %s:%s", ip_addr, port);
#endif
  }

  /* Set up signal handling */
  {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    
    if (sigaction(SIGTERM, &sa, NULL)) {
      log_msg(LGG_ERR, "SIGTERM %m");
      exit(EXIT_FAILURE);
    }
    
    if (signal(SIGCHLD, SIG_IGN) == SIG_ERR) {
      log_msg(LGG_WARNING, "SIGCHLD %m");
    }
    
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGUSR1, &sa, NULL)) {
      log_msg(LGG_ERR, "SIGUSR1 %m");
      exit(EXIT_FAILURE);
    }

#if defined(__GLIBC__) && defined(BACKTRACE)
    sa.sa_handler = print_trace;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);
    sigaction(SIGILL, &sa, NULL);
    sigaction(SIGFPE, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
#endif

#ifdef DEBUG
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGUSR2, &sa, NULL)) {
      log_msg(LGG_ERR, "SIGUSR2 %m");
      exit(EXIT_FAILURE);
    }
#endif
  }

#ifdef DROP_ROOT
  if (pw && setuid(pw->pw_uid)) {
    log_msg(LGG_WARNING, "setuid %d: %m", pw->pw_uid);
  }
#endif

  signal(SIGPIPE, SIG_IGN);

  /* Set up inter-process communication pipe */
  if (pipe(pipefd) == -1) {
    log_msg(LGG_ERR, "pipe() error: %m");
    exit(EXIT_FAILURE);
  }
  
  if (fcntl(pipefd[0], F_SETFL, fcntl(pipefd[0], F_GETFL) | O_NONBLOCK) == -1) {
    log_msg(LGG_ERR, "fcntl() error setting O_NONBLOCK on read end of pipe: %m");
    exit(EXIT_FAILURE);
  }

  FD_SET(pipefd[0], &readfds);
  if (pipefd[0] > nfds) {
    nfds = pipefd[0];
  }

  ++nfds;
  sin_size = sizeof their_addr;

  struct Global _g = {
        argc,
        argv,
        select_timeout,
        http_keepalive,
        pipefd[1],
        stats_url,
        stats_text_url,
        do_204,
        do_redirect,
#ifdef DEBUG
        warning_time,
#endif
        tls_pem,
  };
  g = &_g;

  /* Main accept loop */
  while(1) {
    if (select_rv <= 0) {
      selectfds = readfds;
      select_rv = TEMP_FAILURE_RETRY(select(nfds, &selectfds, NULL, NULL, NULL));
      if (select_rv < 0) {
        log_msg(LGG_ERR, "main select() error: %m");
        exit(EXIT_FAILURE);
      } else if (select_rv == 0) {
        log_msg(LGG_WARNING, "main select() returned zero (timeout?)");
        continue;
      }
    }

    /* Find first ready socket descriptor */
    for (i = 0, sockfd = 0; i < num_ports; i++) {
      if (FD_ISSET(sockfds[i], &selectfds)) {
        sockfd = sockfds[i];
        --select_rv;
        FD_CLR(sockfd, &selectfds);
        break;
      }
    }

    /* Check for pipe I/O */
    if (!sockfd && FD_ISSET(pipefd[0], &selectfds)) {
      rv = read(pipefd[0], &pipedata, sizeof(pipedata));
      if (rv < 0) {
        log_msg(LGG_WARNING, "error reading from pipe: %m");
      } else if (rv == 0) {
        log_msg(LGG_WARNING, "pipe read() returned zero");
      } else if (rv != sizeof(pipedata)) {
        log_msg(LGG_WARNING, "pipe read() got %d bytes, but %u bytes were expected - discarding",
          rv, (unsigned int)sizeof(pipedata));
      } else {
        /* Process response statistics */
        switch (pipedata.status) {
          case FAIL_GENERAL:   ++ers; break;
          case FAIL_TIMEOUT:   ++tmo; break;
          case FAIL_CLOSED:    ++cls; break;
          case FAIL_REPLY:     ++cly; break;
          case SEND_GIF:       ++gif; break;
          case SEND_TXT:       ++txt; break;
          case SEND_JPG:       ++jpg; break;
          case SEND_PNG:       ++png; break;
          case SEND_SWF:       ++swf; break;
          case SEND_ICO:       ++ico; break;
          case SEND_BAD:       ++bad; break;
          case SEND_STATS:     ++sta; break;
          case SEND_STATSTEXT: ++stt; break;
          case SEND_204:       ++noc; break;
          case SEND_REDIRECT:  ++rdr; break;
          case SEND_NO_EXT:    ++nfe; break;
          case SEND_UNK_EXT:   ++ufe; break;
          case SEND_NO_URL:    ++nou; break;
          case SEND_BAD_PATH:  ++pth; break;
          case SEND_POST:      ++pst; break;
          case SEND_HEAD:      ++hed; break;
          case SEND_OPTIONS:   ++opt; break;
          case ACTION_LOG_VERB:  log_set_verb(pipedata.verb); break;
          case ACTION_DEC_KCC: --kcc; break;
          default:
            log_msg(LGG_DEBUG, "conn_handler reported unknown response value: %d", pipedata.status);
        }
        
        switch (pipedata.ssl) {
          case SSL_HIT_RTT0:   ++zrt; /* fall through */
          case SSL_HIT:        ++slh; break;
          case SSL_HIT_CLS:    ++slc; break;
          default:             ;
        }
        
        if (pipedata.ssl == SSL_HIT ||
            pipedata.ssl == SSL_HIT_RTT0 ||
            pipedata.ssl == SSL_HIT_CLS) {
          switch (pipedata.ssl_ver) {
#ifdef TLS1_3_VERSION
            case TLS1_3_VERSION: ++v13; break;
#endif
            case TLS1_2_VERSION: ++v12; break;
            case TLS1_VERSION:   ++v10; break;
            default:             ;
          }
        }
        
        if (pipedata.status < ACTION_LOG_VERB) {
          count++;
          if (pipedata.rx_total > 0) {
            static float favg = 0.0;
            static int favg_cnt = 0;
            favg = ema(favg, pipedata.rx_total, &favg_cnt);
            avg = favg + 0.5;
            if (pipedata.rx_total > rmx)
              rmx = pipedata.rx_total;
          }

          if (pipedata.status != FAIL_TIMEOUT && pipedata.rx_total > 0) {
            static float ftav = 0.0;
            static int ftav_cnt = 0;
            ftav = ema(ftav, pipedata.run_time, &ftav_cnt);
            tav = ftav + 0.5;
            if (pipedata.run_time + 0.5 > tmx)
              tmx = (pipedata.run_time + 0.5);
          }
        } else if (pipedata.status == ACTION_DEC_KCC) {
          static int kvg_cnt = 0;
          kvg = ema(kvg, pipedata.krq, &kvg_cnt);
          if (pipedata.krq > krq)
            krq = pipedata.krq;
        }
      }
      --select_rv;
      continue;
    }

    if (!sockfd) {
      log_msg(LGG_WARNING, "select() returned a value of %d but no file descriptors of interest are ready for read", select_rv);
      select_rv = 0;
      continue;
    }

    struct timespec init_time = {0, 0};
    get_time(&init_time);
    new_fd = accept(sockfd, (struct sockaddr *) &their_addr, &sin_size);
    if (new_fd < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            cls++;
        }
        log_msg(LGG_DEBUG, "accept: %m");
        continue;
    }
    
    if (kcc >= max_num_threads) {
        clt++;
        shutdown(new_fd, SHUT_RDWR);
        close(new_fd);
        continue;
    }

    conn_tlstor_struct *conn_tlstor = conn_stor_acquire();
    if (conn_tlstor == NULL) {
      log_msg(LGG_WARNING, "%s conn_tlstor alloc failed", __FUNCTION__);
      shutdown(new_fd, SHUT_RDWR);
      close(new_fd);
      continue;
    }

    /* Set fd to blocking explicitly */
    int flags;
    if ((flags = fcntl(new_fd, F_GETFL, 0)) < 0 || 
        fcntl(new_fd, F_SETFL, flags & (~O_NONBLOCK)) < 0) {
        log_msg(LGG_WARNING, "%s fail to set new_fd to blocking", __FUNCTION__);
    }

    /* Set socket options */
    if (setsockopt(new_fd, IPPROTO_TCP, TCP_NODELAY, &(int){ 1 }, sizeof(int)) ||
        setsockopt(new_fd, SOL_SOCKET, SO_RCVTIMEO, 
                  (char*)&(struct timeval){ 0, 150000 }, sizeof(struct timeval))) {
        log_msg(LGG_WARNING, "%s setsockopt() failed on new_fd", __FUNCTION__);
    }

    conn_tlstor->new_fd = new_fd;
    conn_tlstor->ssl = NULL;
    conn_tlstor->allow_admin = (!admin_port) ? 1 : 0;
    
    char *server_ip = conn_tlstor->tlsext_cb_arg->server_ip;
    int ssl_port = is_ssl_conn(new_fd, server_ip, INET6_ADDRSTRLEN, tls_ports, num_tls_ports);
    
    if (ssl_port) {
      int ssl_attempt = 5;
      int sslerr = SSL_ERROR_NONE;
      char ip_buf[NI_MAXHOST], port_buf[NI_MAXSERV];

      tlsext_cb_arg_struct *t = conn_tlstor->tlsext_cb_arg;
      SSL *ssl = NULL;
      t->tls_pem = tls_pem;
      t->cachain = cert_tlstor.cachain;
      t->status = SSL_UNKNOWN;
      t->sslctx_idx = -1;

      ssl = SSL_new(sslctx);
      if (!ssl) {
        log_msg(LGG_ERR, "SSL_new() failed");
        goto cleanup_connection;
      }
      
      SSL_set_fd(ssl, new_fd);
      conn_tlstor->ssl = ssl;
      
      if (ssl_port == admin_port)
        conn_tlstor->allow_admin = 1;

#ifdef TLS1_3_VERSION
      SSL_CTX_set_client_hello_cb(sslctx, tls_clienthello_cb, t);
      conn_tlstor->early_data = read_tls_early_data(ssl, &sslerr);
      if (conn_tlstor->early_data) {
        conn_tlstor->init_time = elapsed_time_msec(init_time);
        goto start_service_thread;
      }

      if (sslerr != SSL_ERROR_NONE)
        goto skip_ssl_accept;
#else
      SSL_CTX_set_tlsext_servername_arg(sslctx, t);
      conn_tlstor->early_data = NULL;
#endif
      conn_tlstor->init_time = elapsed_time_msec(init_time);

redo_ssl_accept:
      errno = 0;
      ERR_clear_error();
      int sslret = SSL_accept(ssl);
      if (sslret == 1)
        goto start_service_thread;
      sslerr = SSL_get_error(ssl, sslret);

#ifdef TLS1_3_VERSION
skip_ssl_accept:
#endif

      if (log_get_verb() >= LGG_WARNING && 
          getnameinfo((struct sockaddr *)&their_addr, sin_size,
                     ip_buf, sizeof ip_buf, port_buf, sizeof port_buf, 
                     NI_NUMERICHOST | NI_NUMERICSERV) != 0) {
        ip_buf[0] = '\0';
        port_buf[0] = '\0';
        log_msg(LGG_ERR, "failed to get client_ip: %s", strerror(errno));
      }

      switch(sslerr) {
        case SSL_ERROR_WANT_READ:
          ssl_attempt--;
          if (ssl_attempt > 0) {
            get_time(&init_time);
            goto redo_ssl_accept;
          }
          log_msg(LGG_WARNING, "handshake failed: reached max retries. client %s:%s server %s",
              ip_buf, port_buf, t->servername);
          break;
        case SSL_ERROR_SSL:
          switch(ERR_GET_REASON(ERR_peek_last_error())) {
              case SSL_R_SSLV3_ALERT_BAD_CERTIFICATE:
                  ucb++;
                  log_msg(LGG_WARNING, "handshake failed: bad cert. client %s:%s server %s",
                      ip_buf, port_buf, t->servername);
                  break;
              case SSL_R_TLSV1_ALERT_UNKNOWN_CA:
                  uca++;
                  log_msg(LGG_WARNING, "handshake failed: unknown CA. client %s:%s server %s",
                      ip_buf, port_buf, t->servername);
                  break;
              case SSL_R_SSLV3_ALERT_CERTIFICATE_UNKNOWN:
                  uce++;
                  log_msg(LGG_WARNING, "handshake failed: unknown cert. client %s:%s server %s",
                      ip_buf, port_buf, t->servername);
                  break;
              case SSL_R_PARSE_TLSEXT:
                  if (t->status == SSL_MISS)
                    break;
                  /* fall through */
              default:
                  log_msg(LGG_WARNING, "handshake failed: client %s:%s server %s. Lib(%d) Func(%d) Reason(%d)",
                      ip_buf, port_buf, t->servername,
                      ERR_GET_LIB(ERR_peek_last_error()), 
                      0,
                      ERR_GET_REASON(ERR_peek_last_error()));
          }
          break;
        case SSL_ERROR_SYSCALL:
            if (t->status == SSL_MISS)
              break;

            if (errno == 0 || errno == 104) {
              char m[2];
              int rv = recv(new_fd, m, 2, MSG_PEEK);
              if (rv == 0) {
                ush++;
                log_msg(LGG_WARNING, "handshake failed: shutdown after ServerHello. client %s:%s server %s",
                  ip_buf, port_buf, t->servername);
                break;
              }
            }
            log_msg(LGG_WARNING, "handshake failed: socket I/O error. client %s:%s server %s. errno: %d",
                ip_buf, port_buf, t->servername, errno);
            break;
        default:
          log_msg(LGG_WARNING, "handshake failed: unknown error %d. client %s:%s server %s",
              sslerr, ip_buf, port_buf, t->servername);
      }
      
      count++;
      switch(t->status) {
        case SSL_ERR:        ++sle; break;
        case SSL_MISS:       ++slm; break;
        case SSL_HIT:
        case SSL_UNKNOWN:    ++slu; break;
        default:             ;
      }

cleanup_connection:
      if (ssl) {
        SSL_set_shutdown(ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
        SSL_free(ssl);
      }
      shutdown(new_fd, SHUT_RDWR);
      close(new_fd);
      conn_stor_relinq(conn_tlstor);
      continue;
    }

start_service_thread:
    conn_tlstor->init_time += elapsed_time_msec(init_time);
    pthread_t conn_thread;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_attr_setstacksize(&attr, THREAD_STACK_SIZE);
    
    int err = pthread_create(&conn_thread, &attr, conn_handler, (void*)conn_tlstor);
    if (err) {
      log_msg(LGG_ERR, "Failed to create conn_handler thread. err: %d", err);
      if (conn_tlstor->ssl) {
        SSL_set_shutdown(conn_tlstor->ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
        SSL_free(conn_tlstor->ssl);
      }
      shutdown(new_fd, SHUT_RDWR);
      close(new_fd);
      conn_stor_relinq(conn_tlstor);
      continue;
    }
    pthread_attr_destroy(&attr);

    if (++kcc > kmx)
      kmx = kcc;
  }

  pthread_cancel(certgen_thread);
  pthread_join(certgen_thread, NULL);

quit_main:
  SSL_CTX_free(sslctx);
  conn_stor_flush();
  sslctx_tbl_cleanup();
  cert_tlstor_cleanup(&cert_tlstor);
  ssl_free_locks();
  
  /* Close pipe file descriptors */
  if (pipefd[0] >= 0) close(pipefd[0]);
  if (pipefd[1] >= 0) close(pipefd[1]);
  
  /* Close listening sockets */
  for (i = 0; i < num_ports; i++) {
    if (sockfds[i] >= 0) close(sockfds[i]);
  }
  
  return (EXIT_SUCCESS);
}
