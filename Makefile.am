bin_PROGRAMS = pixelserv-tls

man1_MANS = pixelserv-tls.1

# Globale Compiler-Flags
AM_CFLAGS = -O3 -Wall -ffunction-sections -fdata-sections -fno-strict-aliasing $(EXTRA_CFLAGS)

# Programmspezifische Compiler-Flags
pixelserv_tls_CFLAGS = \
    -DDROP_ROOT \
    -DIF_MODE \
    -DDEFAULT_PEM_PATH=\"/var/cache/pixelserv\"

# Linker-Flags (z. B. für statisches Bauen oder Optimierungen)
pixelserv_tls_LDFLAGS = $(EXTRA_LDFLAGS)

# Quellcode-Dateien
pixelserv_tls_SOURCES = \
    pixelserv.c \
    socket_handler.c \
    certs.c \
    util.c \
    logger.c
