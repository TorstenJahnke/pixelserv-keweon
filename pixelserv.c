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
      // Ignore this signal while we are quitting
      signal(SIGTERM, SIG_IGN);
    }

    conn_stor_flush();
#if defined(__GLIBC__) && !defined(__UCLIBC__)
    malloc_trim(0);
#endif

    // log stats
    char* stats_string = get_stats(0, 0);
    log_msg(LGG_CRIT, "%s", stats_string);
    free(stats_string);

    sslctx_tbl_save(tls_pem);

    if (sig == SIGTERM) {
      log_msg(LGG_NOTICE, "exit on SIGTERM");
      exit(EXIT_SUCCESS);
    }
#ifdef DEBUG
  }
#endif
  return;
}

int main (int argc, char* argv[])
{
  int sockfd = 0;  // listen on sock_fd
  int new_fd = 0;  // new connection on new_fd
  struct sockaddr_storage their_addr;  // connector's address information
  socklen_t sin_size;
  char* version_string;
  time_t select_timeout = DEFAULT_TIMEOUT;
  time_t http_keepalive = DEFAULT_KEEPALIVE;
  int rv = 0;
  char* ip_addr = DEFAULT_IP;
  int use_ip = 0;
  struct addrinfo hints, *servinfo;
  int error = 0;
  int pipefd[2];  // IPC pipe ends (0 = read, 1 = write)
  response_struct pipedata = { 0 };
  char* ports[MAX_PORTS + 1]; /* one extra port for admin */
  char *port = NULL;
  fd_set readfds;
  fd_set selectfds;
  int sockfds[MAX_PORTS];
  int select_rv = 0;
  int nfds = 0;
  int num_ports = 0;
  int i;
#ifdef IF_MODE
  char *ifname = "";
  int use_if = 0;
#endif
#ifdef DROP_ROOT
  char *user = DEFAULT_USER;  // used to be long enough
  struct passwd *pw = 0;
#endif
  char* stats_url = DEFAULT_STATS_URL;
  char* stats_text_url = DEFAULT_STATS_TEXT_URL;
  int do_204 = 1;
#ifndef TEST
  int do_foreground = 0;
#endif // !TEST
  int do_redirect = 0;
  int do_benchmark = 0;
  char *bm_cert = NULL;
#ifdef DEBUG
  int warning_time = 0;
#endif //DEBUG
  int max_num_threads = DEFAULT_THREAD_MAX;
  int cert_cache_size = DEFAULT_CERT_CACHE_SIZE;

#if defined(__GLIBC__) && !defined(__UCLIBC__)
  mallopt(M_ARENA_MAX, 1);
#endif
  struct rlimit l = {THREAD_STACK_SIZE, THREAD_STACK_SIZE * 2};
  if (setrlimit(RLIMIT_STACK, &l) == -1)
    log_msg(LGG_ERR, "setrlimit STACK failed: %d %d errno:%d", l.rlim_cur, l.rlim_max, errno);

  l.rlim_cur = max_num_threads + 50;
  l.rlim_max = max_num_threads * 2;

  if (setrlimit(RLIMIT_NOFILE, &l) == -1)
    log_msg(LGG_ERR, "setrlimit NOFILE failed: %d %d errno:%d", l.rlim_cur, l.rlim_max, errno);

  // command line arguments processing
  for (i = 1; i < argc && error == 0; ++i) {
    if (argv[i][0] == '-') {
      // handle arguments that don't require a subsequent argument
      switch (argv[i][1]) {
        case '2': do_204 = 0;                                 continue;
        case 'B':
          if ((i + 1) == argc || argv[i + 1][0] == '-') {
            do_benchmark = 1; bm_cert = NULL;
            continue;
          }
          break;
#ifndef TEST
        case 'f': do_foreground = 1;                          continue;
#endif // !TEST
        case 'r': /* deprecated - ignoring */                 continue;
        case 'R': do_redirect = 1;                            continue;
        // no default here because we want to move on to the next section
        case 'l':
          if ((i + 1) == argc || argv[i + 1][0] == '-') {
            log_set_verb(LGG_INFO);
            continue;
          }
          /* fall through */
      }
      // handle arguments that require a subsequent argument
      if ((i + 1) < argc) {
        // switch on parameter letter and process subsequent argument
        switch (argv[i++][1]) {
          case 'B':
            do_benchmark = 1;
            if (argv[i][0] == '-')
              error = 1;
            else
              bm_cert = argv[i];
          continue;
          case 'c':
            errno = 0;
            cert_cache_size = strtol(argv[i], NULL, 10);
            if (errno || cert_cache_size <= 0) {
              error = 1;
            }
          continue;
          case 'l':
            if ((logger_level)atoi(argv[i]) > LGG_DEBUG
                || atoi(argv[i]) < 0)
              error = 1;
            else
              log_set_verb((logger_level)atoi(argv[i]));
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
            if (num_tls_ports < MAX_TLS_PORTS)
              admin_port = atoi(argv[i]);
            else
              error = 1;
              // fall through to case 'k'
          case 'k':
            if (num_tls_ports < MAX_TLS_PORTS)
              tls_ports[num_tls_ports++] = atoi(argv[i]);
            else
              error = 1;
              // fall through to case 'p'
          case 'p':
            if (num_ports < MAX_PORTS) {
              ports[num_ports++] = argv[i];
            } else {
              error = 1;
            }
          continue;
          case 's': stats_url = argv[i];                      continue;
          case 't': stats_text_url = argv[i];                 continue;
          case 'T':
            errno = 0;
            max_num_threads = strtol(argv[i], NULL, 10);
            if (errno || max_num_threads <= 0) {
              error = 1;
            }
          continue;
#ifdef DROP_ROOT
          case 'u': user = argv[i];                           continue;
#endif
#ifdef DEBUG
          case 'w':
            errno = 0;
            warning_time = strtol(argv[i], NULL, 10);
            if (errno || warning_time <= 0) {
              error = 1;
            }
          continue;
#endif //DEBUG
          case 'z':
            tls_pem = argv[i];
          continue;
          default:  error = 1;                                continue;
        }
      } else {
        error = 1;
      }
    } else if (use_ip == 0) {  // assume its a listening IP address
      ip_addr = argv[i];
      use_ip = 1;
    } else {
      error = 1;  // fix bug with 2 IP like args
    } // -
  } // for

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
#endif // !TEST
           "\t" "-k  HTTPS_PORT\t\t(default: "
           SECOND_PORT
           ")" "\n"
           "\t" "-l  LEVEL\t\t(0:critical 1:error<default> 2:warning 3:notice 4:info 5:debug)" "\n"
#ifdef IF_MODE
           "\t" "-n  IFACE\t\t(default: all interfaces)" "\n"
#endif // IF_MODE
           "\t" "-o  SELECT_TIMEOUT\t(deprecated; will be removed in a future version)" "\n"
           "\t" "-O  KEEPALIVE_TIME\t(for HTTP/1.1 connections; default: %ds)" "\n"
           "\t" "-p  HTTP_PORT\t\t(default: "
           DEFAULT_PORT
           ")" "\n"
           "\t" "-R\t\t\t(enable redirect to encoded path in URLs)" "\n"
           "\t" "-s  STATS_HTML_URL\t(default: "
           DEFAULT_STATS_URL
           ")" "\n"
           "\t" "-t  STATS_TXT_URL\t(default: "
           DEFAULT_STATS_TEXT_URL
           ")" "\n"
           "\t" "-T  MAX_THREADS\t\t(default: %d)\n"
#ifdef DROP_ROOT
           "\t" "-u  USER\t\t(default: \"nobody\")" "\n"
#endif // DROP_ROOT
#ifdef DEBUG
           "\t" "-w  warning_time\t(warn when elapsed connection time exceeds value in msec)" "\n"
#endif //DEBUG
           "\t" "-z  CERT_PATH\t\t(default: "
           DEFAULT_PEM_PATH
           ")" "\n"
           , VERSION, DEFAULT_CERT_CACHE_SIZE, DEFAULT_KEEPALIVE,
           DEFAULT_THREAD_MAX);
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

  mkfifo(PIXEL_CERT_PIPE, 0600);
#ifdef DROP_ROOT
  pw = getpwnam(user);
  if (chown(PIXEL_CERT_PIPE, pw->pw_uid, pw->pw_gid) < 0) {
      log_msg(LGG_CRIT, "chown failed to set owner of %s to %s", PIXEL_CERT_PIPE, user);
      exit(EXIT_FAILURE);
  }
#endif

  SSL_library_init();
  ssl_init_locks();
  cert_tlstor_init(tls_pem, &cert_tlstor);
  sslctx_tbl_init(cert_cache_size);
  conn_stor_init(max_num_threads);

  sslctx_tbl_load(tls_pem, cert_tlstor.cachain);
  SSL_CTX *sslctx = create_default_sslctx(tls_pem);

  if (do_benchmark) {
    run_benchmark(&cert_tlstor, bm_cert);
    goto quit_main;
  } else {
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, THREAD_STACK_SIZE);
    pthread_create(&certgen_thread, &attr, cert_generator, (void*)&cert_tlstor);
    pthread_attr_destroy(&attr);
  }

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_INET;  // AF_UNSPEC - AF_INET restricts to IPV4
  hints.ai_socktype = SOCK_STREAM;
  if (!use_ip) {
    hints.ai_flags = AI_PASSIVE;  // use my IP
  }

  if ((!admin_port && !num_ports) || (admin_port && num_ports == 1)) {
    /* no -p no -k */
    tls_ports[num_tls_ports++] = atoi(SECOND_PORT);
    ports[num_ports++] = SECOND_PORT;
    ports[num_ports++] = DEFAULT_PORT;
  } else if ((!admin_port && !num_tls_ports) || (admin_port && num_tls_ports == 1)) {
    /* no -k */
    tls_ports[num_tls_ports++] = atoi(SECOND_PORT);
    ports[num_ports++] = SECOND_PORT;
  } else if (num_ports == num_tls_ports) {
    /* no -p */
    ports[num_ports++] = DEFAULT_PORT;
  }

  // clear the set
  FD_ZERO(&readfds);
  for (i = 0; i < num_ports; i++) {
    port = ports[i];

    rv = getaddrinfo(use_ip ? ip_addr : NULL, port, &hints, &servinfo);
    if (rv) {
      log_msg(LGG_ERR, "getaddrinfo: %s", gai_strerror(rv) );
      exit(EXIT_FAILURE);
    }

    if ( ((sockfd = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol)) < 1)
      || setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int))
      || setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &(int){ 1 }, sizeof(int))
#ifdef IF_MODE
      || (use_if && (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname))))
#endif
#ifdef linux
#  if LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0) || ENABLE_TCP_FASTOPEN
      || setsockopt(sockfd, IPPROTO_TCP, TCP_FASTOPEN, &(int){ TCP_FASTOPEN_QLEN }, sizeof(int))
#  endif
#endif
      || bind(sockfd, servinfo->ai_addr, servinfo->ai_addrlen)
      || listen(sockfd, BACKLOG)
      || fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL) | O_NONBLOCK)
      ) {
#ifdef IF_MODE
      log_msg(LGG_CRIT, "Abort: %m - %s:%s:%s", ifname, ip_addr, port);
#else
      log_msg(LOG_CRIT, "Abort: %m - %s:%s", ip_addr, port);
#endif
      exit(EXIT_FAILURE);
    }

    sockfds[i] = sockfd;
    // add descriptor to the set
    FD_SET(sockfd, &readfds);
    if (sockfd > nfds) {
      nfds = sockfd;
    }

    freeaddrinfo(servinfo); // all done with this structure
#ifdef IF_MODE
    log_msg(LGG_CRIT, "Listening on %s:%s:%s", ifname, ip_addr, port);
#else
    log_msg(LGG_CRIT, "Listening on %s:%s", ip_addr, port);
#endif
  }

  // set up signal handling
  {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    // set signal handler for termination
    if (sigaction(SIGTERM, &sa, NULL)) {
      log_msg(LOG_ERR, "SIGTERM %m");
      exit(EXIT_FAILURE);
    }
    // attempt to set SIGCHLD to ignore
    // in K26 this should cause children to be automatically reaped on exit
    // in K24 it will accomplish nothing, so we still need to use waitpid()
    if (signal(SIGCHLD, SIG_IGN) == SIG_ERR) {
      log_msg(LGG_WARNING, "SIGCHLD %m");
    }
    // set signal handler for info
    sa.sa_flags = SA_RESTART; // prevent EINTR from interrupted library calls
    if (sigaction(SIGUSR1, &sa, NULL)) {
      log_msg(LOG_ERR, "SIGUSR1 %m");
      exit(EXIT_FAILURE);
    }
#if defined(__GLIBC__) && defined(BACKTRACE)
    sa.sa_handler = print_trace;
    if (sigaction(SIGSEGV, &sa, NULL))
      log_msg(LOG_ERR, "SIGSEGV %m");
    if (sigaction(SIGABRT, &sa, NULL))
      log_msg(LOG_ERR, "SIGABRT %m");
    if (sigaction(SIGILL, &sa, NULL))
      log_msg(LOG_ERR, "SIGILL %m");
    if (sigaction(SIGFPE, &sa, NULL))
      log_msg(LOG_ERR, "SIGFPE %m");
    if (sigaction(SIGBUS, &sa, NULL))
      log_msg(LOG_ERR, "SIGBUS %m");
#endif

#ifdef DEBUG
    // set signal handler for debug
    sa.sa_flags = SA_RESTART; // prevent EINTR from interrupted library calls
    if (sigaction(SIGUSR2, &sa, NULL)) {
      log_msg(LOG_ERR, "SIGUSR2 %m");
      exit(EXIT_FAILURE);
    }
#endif
  }

#ifdef DROP_ROOT // no longer fatal error if doesn't work
  if ( (pw = getpwnam(user)) == NULL ) {
    log_msg(LGG_WARNING, "Unknown user \"%s\"", user);
  }
  else if ( setuid(pw->pw_uid) ) {
    log_msg(LGG_WARNING, "setuid %d: %m", pw->pw_uid);
  }
#endif

  // cause failed pipe I/O calls to result in error return values instead of
  //  SIGPIPE signals
  signal(SIGPIPE, SIG_IGN);

  // open pipe for children to use for writing data back to main
  if (pipe(pipefd) == -1) {
    log_msg(LOG_ERR, "pipe() error: %m");
    exit(EXIT_FAILURE);
  }
  // set non-blocking read mode
  // note that writes are left as blocking because otherwise weird things happen
  if (fcntl(pipefd[0], F_SETFL, fcntl(pipefd[0], F_GETFL) | O_NONBLOCK) == -1) {
    log_msg(LOG_ERR, "fcntl() error setting O_NONBLOCK on read end of pipe: %m");
    exit(EXIT_FAILURE);
  }

  // also have select() monitor the read end of the stats pipe
  FD_SET(pipefd[0], &readfds);
  // note if pipe read descriptor is the largest fd number we care about
  if (pipefd[0] > nfds) {
    nfds = pipefd[0];
  }

  // nfds now contains the largest fd number of interest;
  //  increment by 1 for use with select()
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

  // main accept() loop
  while(1) {
    // only call select() if we have something more to process
    if (select_rv <= 0) {
      // select() modifies its fd set, so make a working copy
      // readfds should not be referenced after this point, as it must remain
      //  intact
      selectfds = readfds;
      // NOTE: MACRO needs "_GNU_SOURCE"; without this the select gets
      //       interrupted with errno EINTR
      select_rv = TEMP_FAILURE_RETRY(select(nfds, &selectfds, NULL, NULL, NULL));
      if (select_rv < 0) {
        log_msg(LOG_ERR, "main select() error: %m");
        exit(EXIT_FAILURE);
      } else if (select_rv == 0) {
        // this should be pathological, as we don't specify a timeout
        log_msg(LGG_WARNING, "main select() returned zero (timeout?)");
        continue;
      }
    }

    // find first socket descriptor that is ready to read (if any)
    // note that even though multiple sockets may be ready, we only process one
    //  per loop iteration; subsequent ones will be handled on subsequent passes
    //  through the loop
    for (i = 0, sockfd = 0; i < num_ports; i++) {
      if ( FD_ISSET(sockfds[i], &selectfds) ) {
        // select sockfds[i] for servicing during this loop pass
        sockfd = sockfds[i];
        --select_rv;
        FD_CLR(sockfd, &selectfds);
        break;
      }
    }

    // if select() didn't return due to a socket connection, check for pipe I/O
    if (!sockfd && FD_ISSET(pipefd[0], &selectfds)) {
      // perform a single read from pipe
      rv = read(pipefd[0], &pipedata, sizeof(pipedata));
      if (rv < 0) {
        log_msg(LGG_WARNING, "error reading from pipe: %m");
      } else if (rv == 0) {
        log_msg(LGG_WARNING, "pipe read() returned zero");
      } else if (rv != sizeof(pipedata)) {
        log_msg(LGG_WARNING, "pipe read() got %d bytes, but %u bytes were expected - discarding",
          rv, (unsigned int)sizeof(pipedata));
      } else {
        // process response type
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
            log_msg(LOG_DEBUG, "conn_handler reported unknown response value: %d", pipedata.status);
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
          // count only positive receive sizes
          if (pipedata.rx_total <= 0) {
            log_msg(LOG_DEBUG, "pipe read() got nonsensical rx_total data value %d - ignoring", pipedata.rx_total);
          } else {
            // calculate average byte per request (avg) using
            static float favg = 0.0; 
            static int favg_cnt = 0;
            favg = ema(favg, pipedata.rx_total, &favg_cnt);
            avg = favg + 0.5;
            // look for a new high score
            if (pipedata.rx_total > rmx)
              rmx = pipedata.rx_total;
          }

          if (pipedata.status != FAIL_TIMEOUT && pipedata.rx_total > 0) {
            // calculate average process time (tav) using
            static float ftav = 0.0;
            static int ftav_cnt = 0;
            ftav = ema(ftav, pipedata.run_time, &ftav_cnt);
            tav = ftav + 0.5;
            // look for a new high score, adding 0.5 for rounding
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

    // if select() returned but no fd's of interest were found, give up
    // note that this is bad because it means that select() will probably never
    //  block again because something will always be waiting on the unhandled
    //  file descriptor
    // on the other hand, this should be a pathological case unless something is
    //  added to FD_SET that is not checked before this point
    if (!sockfd) {
      log_msg(LGG_WARNING, "select() returned a value of %d but no file descriptors of interest are ready for read", select_rv);
      // force select_rv to zero so that select() will be called on the next
      //  loop iteration
      select_rv = 0;
      continue;
    }

    struct timespec init_time = {0, 0};
    get_time(&init_time);
    new_fd = accept(sockfd, (struct sockaddr *) &their_addr, &sin_size);
    if (new_fd < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            cls++;   /* client closed connection before we got a chance to accept it */
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
      log_msg(LGG_WARNING, "%s conn_tlstor alloc failed ", __FUNCTION__);
      continue;
    }

    /* Set fd to blocking explicitly.
       On Linux, fd attributes are not inherited from parent.
       On macOS, the attributes are inherited from parent. */
    int flags;
    if ((flags = fcntl(new_fd, F_GETFL, 0)) < 0 || fcntl(new_fd, F_SETFL, flags & (~O_NONBLOCK)) < 0)
        log_msg(LGG_WARNING, "%s fail to set new_fd to blocking", __FUNCTION__);

    /* Set socket to TCP_NODELAY explicitly.
       On Linux, socket options are inherited from parent.
       On macOS, the attributes are not inherited from parent. */
    if (setsockopt(new_fd, IPPROTO_TCP, TCP_NODELAY, &(int){ 1 }, sizeof(int)) ||
        setsockopt(new_fd, SOL_SOCKET, SO_RCVTIMEO, (char*)&(struct timeval){ 0, 150000 },
            sizeof(struct timeval)))  {
        log_msg(LGG_WARNING, "%s setsockopt() failed on new_fd", __FUNCTION__);
    }

    conn_tlstor->new_fd = new_fd;
    conn_tlstor->ssl = NULL;
    conn_tlstor->allow_admin = (!admin_port) ? 1 : 0;
    char *server_ip = conn_tlstor->tlsext_cb_arg->servername;
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

      /* handle TLS error if any and skip further TLS handshake */
      if (sslerr != SSL_ERROR_NONE)
        goto skip_ssl_accept;
#else
      SSL_CTX_set_tlsext_servername_arg(sslctx, t);
      conn_tlstor->early_data = NULL;
#endif
      conn_tlstor->init_time = elapsed_time_msec(init_time);

      /* proceed or continue with TLS handshake */

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
      if (log_get_verb() >= LGG_WARNING && getnameinfo((struct sockaddr *)&their_addr, sin_size,
            ip_buf, sizeof ip_buf, port_buf, sizeof port_buf, NI_NUMERICHOST | NI_NUMERICSERV ) != 0) {
        ip_buf[0] = '\0';
        port_buf[0] = '\0';
        log_msg(LOG_ERR, "failed to get client_ip: %s", strerror(errno));
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
                          ERR_GET_LIB(ERR_peek_last_error()), ERR_GET_FUNC(ERR_peek_last_error()),
                              ERR_GET_REASON(ERR_peek_last_error()));
          }
          break;
        case SSL_ERROR_SYSCALL:
             /* OpenSSL 1.1.x clienthello will reach here
                but we want to skip if it's known error such as missing certs */
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
        default:
          ;
      }
      count++;
      switch(t->status) {
        case SSL_ERR:        ++sle; break;
        case SSL_MISS:       ++slm; break;
        case SSL_HIT:
        case SSL_UNKNOWN:    ++slu; break;
        default:             ;
      }
      SSL_set_shutdown(ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
      SSL_free(ssl);
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
    int err;
    if ((err=pthread_create(&conn_thread, &attr, conn_handler, (void*)conn_tlstor))) {
      log_msg(LGG_ERR, "Failed to create conn_handler thread. err: %d", err);
      if(conn_tlstor->ssl){
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
  } // end of perpetual accept() loop

  pthread_cancel(certgen_thread);
  pthread_join(certgen_thread, NULL);

quit_main:
  SSL_CTX_free(sslctx);
  conn_stor_flush();
  sslctx_tbl_cleanup();
  cert_tlstor_cleanup(&cert_tlstor);
  ssl_free_locks();
  return (EXIT_SUCCESS);
}
