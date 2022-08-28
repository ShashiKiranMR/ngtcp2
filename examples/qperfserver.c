/* qperf server for ngtcp2 which is similar to qperf server for quicly */

#include "qperfserver.h"
#include <unistd.h>
#include <float.h>
#include <inttypes.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <ev.h>
#include <netinet/udp.h>
#include <memory.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_openssl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

static int server_socket;
SSL_CTX *server_ctx;
const char *ciphers;
const char *groups;
const char *cert = "server.crt";
const char *key = "server.key";
const char *sid_ctx = "qperf server";

struct addrinfo *get_address(const char *host, const char *port) {
    struct addrinfo hints;
    struct addrinfo *result;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV | AI_PASSIVE;
    hints.ai_protocol = IPPROTO_UDP;

    if (getaddrinfo(host, port, &hints, &result) != 0)
        return NULL;
    
    else
        return result;
}

static int udp_listen(struct addrinfo *addr) {
    printf("Creating a udp listening socket\n");
    for(const struct addrinfo *rp = addr; rp != NULL; rp = rp->ai_next) {
        int s = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if(s == -1) {
            continue;
        }

        int on = 1;
        if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) != 0) {
            close(s);
            printf("setsockopt(SO_REUSEADDR) failed");
            return -1;
        }

        if(bind(s, rp->ai_addr, rp->ai_addrlen) == 0) {
            return s; // success
        }

        // fail -> close socket and try with next addr
        close(s);
    }
    return -1;
}

const char *crypto_default_ciphers() {
  return "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_"
         "SHA256:TLS_AES_128_CCM_SHA256";
}

const char *crypto_default_groups() { return "X25519:P-256:P-384:P-521"; }

int get_tlsctx() {
    printf("Creating ssl context for the server\n");
    server_ctx = SSL_CTX_new(TLS_server_method());
    if (!server_ctx) {
        printf("Failed to create a new ssl context\n");
        return 1;
    }

    if (ngtcp2_crypto_openssl_configure_server_context(server_ctx) != 0) {
        printf("Failed to configure ngtcp2 ssl server context\n");
        return 1;
    }
    SSL_CTX_set_max_early_data(server_ctx, UINT32_MAX);

    SSL_CTX_set_options(server_ctx, (SSL_OP_ALL &
                                    ~SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS) |
                                    SSL_OP_SINGLE_ECDH_USE |
                                    SSL_OP_CIPHER_SERVER_PREFERENCE |
                                    SSL_OP_NO_ANTI_REPLAY);
    
    ciphers = crypto_default_ciphers();
    if (SSL_CTX_set_ciphersuites(server_ctx, ciphers) != 1) {
        printf("SSL_CTX_set_ciphersuites failed\n");
        return 1;
    }
    groups = crypto_default_groups();
    if (SSL_CTX_set1_groups_list(server_ctx, groups) != 1) {
        printf("SSL_CTX_set1_groups_list failed\n");
        return 1;
    }

    SSL_CTX_set_mode(server_ctx, SSL_MODE_RELEASE_BUFFERS);
    SSL_CTX_set_default_verify_paths(server_ctx);
  
    if (SSL_CTX_use_PrivateKey_file(server_ctx, key, 
                                    SSL_FILETYPE_PEM) != 1) {
        printf("SSL_CTX_use_PrivateKey_file failed\n");
        return 1;
    }

    if (SSL_CTX_use_certificate_chain_file(server_ctx, cert) != 1) {
        printf("SSL_CTX_use_certificate_chain_file failed\n");
        return 1;
    }

    if (SSL_CTX_check_private_key(server_ctx) != 1) {
        printf("SSL_CTX_check_private_key failed\n");
        return 1;
    }

    SSL_CTX_set_session_id_context(server_ctx, sid_ctx, strlen(sid_ctx));
  
    return 0;
}

static void server_read_cb(EV_P_ ev_io *w, int revents) {
    printf("Got something on the socket to read\n");
    /*
    sockaddr_union su;
    uint8_t buf[4096];
    ngtcp2_pkt_hd hd;
    ngtcp2_pkt_info pi;

    iovec msg_iov;
    msg_iov.iov_base = buf;
    msg_iov.iov_len = sizeof(buf);
    */
}

int run_server (const char *port, bool gso, const char *logfile) {
    /* Either take the listening ip and port as input like server 
     * in ngtcp2 or use default like qperf, follow qperf one for
     * consistency. */
    struct addrinfo *addr = get_address("0.0.0.0", port);
    if (addr == NULL) {
        printf("failed get addrinfo for port %s\n", port);
        return -1;
    }

    server_socket = udp_listen(addr);
    freeaddrinfo(addr);
    if (server_socket == -1) {
        printf("failed to listen on port %s\n", port);
        return 1;
    }

    /* Setup tls context
     * quicly uses pico tls 1.3 library 
     * ngtcp2 uses quictls which is a fork of openssl to enable quic 
     * TBD: Which ssl library to use for qperf for ngtcp2? */
    if (get_tlsctx()) {
        printf("Failed to configure the server side ssl context\n");
        return 1;
    }

    /* qperf and ngtcp2 server use the same event libraries */
    printf("Setting up the event handling callbacks\n");
    struct ev_loop *loop = EV_DEFAULT;
    ev_io socket_watcher;
    /* Will watch for the server_socket to be readable and notify us */
    ev_io_init(&socket_watcher, &server_read_cb, server_socket, EV_READ);

    printf("Starting the event monitoring loop\n");
    ev_io_start(loop, &socket_watcher);
    ev_run(loop, 0);
    return 0;
}

int main (void) {
    char port_char[16];
    int port = 18080;
    bool gso = false;

    sprintf(port_char, "%d", port);
    run_server(port_char, gso, NULL);
    return 0;
}
