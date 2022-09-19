/* qperf server for ngtcp2 which is similar to qperf server for quicly */

#include "qperfserver.h"

#include <assert.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_openssl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

struct qperf_conn_wrapper {
    struct ngtcp2_conn *conn;
    struct ngtcp2_crypto_conn_ref *conn_ref;
    SSL *ssl;
    size_t dcidlen;
    const uint8_t *dcid;
};

static int server_socket;
SSL_CTX *server_ctx;
const char *ciphers;
const char *groups;
const char *cert = "server.crt";
const char *key = "server.key";
const char *sid_ctx = "qperf server";
static struct qperf_conn_wrapper **conns;
static size_t num_conns = 0;

static uint8_t null_secret[32];
static uint8_t null_iv[16];

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

struct qperf_conn_wrapper *find_conn(const uint8_t *dcid, size_t dcidlen) {
    size_t i;
    
    for (i=0; i < num_conns; i++) {
        if (memcmp(dcid, (conns[i])->dcid, dcidlen) == 0) {
            return conns[i];
        }
    }
    return NULL;
}

struct qperf_conn_wrapper *new_conn_wrapper(struct ngtcp2_conn *conn, uint8_t *dcid, size_t dcidlen) {
    struct qperf_conn_wrapper *conn_wrapper = (struct qperf_conn_wrapper *)malloc(sizeof(struct qperf_conn_wrapper));
    conn_wrapper->conn                      = conn;
    conn_wrapper->dcid                      = dcid;
    conn_wrapper->dcidlen                   = dcidlen;
    conn_wrapper->conn_ref                  = (struct ngtcp2_crypto_conn_ref *)malloc(sizeof(struct ngtcp2_crypto_conn_ref));
    return conn_wrapper;
}

void append_conn(struct qperf_conn_wrapper *conn_wrapper) {
    ++num_conns;
    conns                   = realloc(conns, sizeof(struct qperf_conn_wrapper *) * num_conns);
    conns[num_conns - 1]    = conn_wrapper;
}

static void addr_init(ngtcp2_sockaddr_in *dest, uint32_t addr, uint16_t port) {
    memset(dest, 0, sizeof(*dest));    
    dest->sin_family = AF_INET;
    dest->sin_port = port;
    dest->sin_addr.s_addr = addr;
}
 
void path_init(ngtcp2_path_storage *path, uint32_t local_addr,
                uint16_t local_port, uint32_t remote_addr,
                uint16_t remote_port) {
    ngtcp2_sockaddr_in la, ra;     
    addr_init(&la, local_addr, local_port);
    addr_init(&ra, remote_addr, remote_port);           
    ngtcp2_path_storage_init(path, (ngtcp2_sockaddr *)&la, sizeof(la),
                            (ngtcp2_sockaddr *)&ra, sizeof(ra), NULL);
}

static int recv_crypto_data_server(ngtcp2_conn *conn,
                                   ngtcp2_crypto_level crypto_level,
                                   uint64_t offset, const uint8_t *data,
                                   size_t datalen, void *user_data) {
    return ngtcp2_crypto_recv_crypto_data_cb(conn, crypto_level, offset, data,
                                                datalen, user_data);
}

static int null_hp_mask(uint8_t *dest, const ngtcp2_crypto_cipher *hp,
                        const ngtcp2_crypto_cipher_ctx *hp_ctx,
                        const uint8_t *sample) {
    if (ngtcp2_crypto_hp_mask(dest, hp, hp_ctx, sample) != 0)
        return NGTCP2_ERR_CALLBACK_FAILURE;

    return 0;
}

static void genrand(uint8_t *dest, size_t destlen,
                    const ngtcp2_rand_ctx *rand_ctx) {
    (void)rand_ctx;
    memset(dest, 0, destlen);
}

static int get_new_connection_id(ngtcp2_conn *conn, ngtcp2_cid *cid,
                                 uint8_t *token, size_t cidlen,
                                 void *user_data) {
    (void)user_data;
    memset(cid->data, 0, cidlen);
    ngtcp2_conn_get_scid(conn, cid);
    memset(token, 0, NGTCP2_STATELESS_RESET_TOKENLEN);
    return 0;
}

static int update_key(ngtcp2_conn *conn, uint8_t *rx_secret, uint8_t *tx_secret,
                      ngtcp2_crypto_aead_ctx *rx_aead_ctx, uint8_t *rx_iv,
                      ngtcp2_crypto_aead_ctx *tx_aead_ctx, uint8_t *tx_iv,
                      const uint8_t *current_rx_secret,
                      const uint8_t *current_tx_secret, size_t secretlen,
                      void *user_data) {
    (void)conn;
    (void)current_rx_secret;
    (void)current_tx_secret;
    (void)user_data;
    (void)secretlen;

    assert(sizeof(null_secret) == secretlen);

    memset(rx_secret, 0xff, sizeof(null_secret));
    memset(tx_secret, 0xff, sizeof(null_secret));
    rx_aead_ctx->native_handle = NULL;
    memset(rx_iv, 0xff, sizeof(null_iv));
    tx_aead_ctx->native_handle = NULL;
    memset(tx_iv, 0xff, sizeof(null_iv));

    return 0;
}

static void delete_crypto_aead_ctx(ngtcp2_conn *conn,
                                   ngtcp2_crypto_aead_ctx *aead_ctx,
                                   void *user_data) {
  (void)conn;
  (void)aead_ctx;
  (void)user_data;
}

static void delete_crypto_cipher_ctx(ngtcp2_conn *conn,
                                     ngtcp2_crypto_cipher_ctx *cipher_ctx,
                                     void *user_data) {
  (void)conn;
  (void)cipher_ctx;
  (void)user_data;
}

static int get_path_challenge_data(ngtcp2_conn *conn, uint8_t *data,
                                   void *user_data) {
  (void)conn;
  (void)user_data;

  memset(data, 0, NGTCP2_PATH_CHALLENGE_DATALEN);

  return 0;
}

static int version_negotiation(ngtcp2_conn *conn, uint32_t version,
                               const ngtcp2_cid *client_dcid, void *user_data) {
  ngtcp2_crypto_aead_ctx aead_ctx = {0};
  ngtcp2_crypto_cipher_ctx hp_ctx = {0};
  (void)client_dcid;
  (void)user_data;

  ngtcp2_conn_install_vneg_initial_key(conn, version, &aead_ctx, null_iv,
                                       &hp_ctx, &aead_ctx, null_iv, &hp_ctx,
                                       sizeof(null_iv));

  return 0;
}

static void server_default_callbacks(ngtcp2_callbacks *cb) {
    memset(cb, 0, sizeof(*cb));
    cb->recv_client_initial = ngtcp2_crypto_recv_client_initial_cb;
    cb->recv_crypto_data = recv_crypto_data_server;
    cb->decrypt = ngtcp2_crypto_decrypt_cb;
    cb->encrypt = ngtcp2_crypto_encrypt_cb;
    cb->hp_mask = null_hp_mask;
    cb->rand = genrand;
    cb->get_new_connection_id = get_new_connection_id;
    cb->update_key = update_key;
    cb->delete_crypto_aead_ctx = delete_crypto_aead_ctx;
    cb->delete_crypto_cipher_ctx = delete_crypto_cipher_ctx;
    cb->get_path_challenge_data = get_path_challenge_data;
    cb->version_negotiation = version_negotiation;
}

void dcid_init(ngtcp2_cid *cid) {
  static const uint8_t id[] = "\xff\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                              "\xaa\xaa\xaa\xaa\xaa\xff";
  ngtcp2_cid_init(cid, id, sizeof(id) - 1);
}

void scid_init(ngtcp2_cid *cid) {
  static const uint8_t id[] = "\xee\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                              "\xaa\xaa\xaa\xaa\xaa\xee";
  ngtcp2_cid_init(cid, id, sizeof(id) - 1);
}

void server_tls_session_init(struct qperf_conn_wrapper *conn_wrapper) {
    SSL *ssl;

    ngtcp2_conn_set_tls_native_handle(conn_wrapper->conn, server_ctx);
    ssl = SSL_new(server_ctx);
    if (!ssl) {
        printf("Error while creating SSL_new\n");
        return;
    }
    SSL_set_app_data(ssl, conn_wrapper->conn_ref);
    SSL_set_accept_state(ssl);
    SSL_set_quic_early_data_enabled(ssl, 1);
}

static void server_read_cb(EV_P_ ev_io *w, int revents) {
    printf("Got something on the socket to read\n");
    uint8_t buf[4096];
    union sockaddr_union su;
    struct iovec msg_iov;
    msg_iov.iov_base = buf;
    msg_iov.iov_len = sizeof(buf);
    
    ssize_t bytes_received;
    struct msghdr msg = {0};
    msg.msg_name = &su;
    msg.msg_iov = &msg_iov;
    msg.msg_iovlen = 1;

    uint32_t version;
    const uint8_t *dcid, *scid;
    size_t dcidlen, scidlen;
    struct ngtcp2_conn *conn = NULL;
    struct qperf_conn_wrapper *conn_wrapper = NULL;
    ngtcp2_pkt_hd hd;

    ngtcp2_callbacks cb;
    ngtcp2_settings settings;
    ngtcp2_transport_params params;
    ngtcp2_cid dcid_n, scid_n;
    dcid_init(&dcid_n);
    scid_init(&scid_n);
    static ngtcp2_path_storage path;
    struct ngtcp2_pkt_info pi;

    int rv;

    while ((bytes_received = recvmsg(w->fd, &msg, 0)) != -1) {
        printf("Bytes received = %ld\n", bytes_received);

        /*TBD: Decoding might not be needed as we don't care about the data?*/
        rv = ngtcp2_pkt_decode_version_cid(&version, &dcid, &dcidlen, 
                                            &scid, &scidlen, buf,
                                            bytes_received, NGTCP2_SV_SCIDLEN);
        switch (rv) {
            case 0:
                break;
            case NGTCP2_ERR_VERSION_NEGOTIATION:
                printf("Version negotiation needed\n");
                continue;
            default:
                printf("Could not decode version and CID from QUIC packet header\n");
                continue;
        }

        conn_wrapper    = find_conn(dcid, dcidlen);
        if (!conn_wrapper) {
            printf("New conn found\n");
            rv = ngtcp2_accept(&hd, buf, bytes_received);
            switch (rv) {
                case 0:
                    break;
                case NGTCP2_ERR_RETRY:
                    printf("Retry needed\n");
                    continue;
                default:
                    printf("Unexpected packet received\n");
                    continue;
            }
            /* Get the conn and then append it to conns */
            path_init(&path, 0, 0, 0, 0);
            ngtcp2_settings_default(&settings);
            ngtcp2_transport_params_default(&params);
            server_default_callbacks(&cb);
            rv = ngtcp2_conn_server_new(&conn, &dcid_n, &scid_n, &path, version, &cb, 
                                        &settings, &params, NULL, NULL);
            conn_wrapper = new_conn_wrapper(conn, dcid, dcidlen);
            append_conn(conn_wrapper);
            server_tls_session_init(conn_wrapper);
        }
        /* Decrypt the pkt */
        conn = conn_wrapper->conn;
        rv = ngtcp2_conn_read_pkt(conn, &path, &pi, buf, bytes_received, NULL);
        if (rv) {
            printf("Error %d while decrypting pkt\n", rv);
            switch (rv) {
                case NGTCP2_ERR_DRAINING:
                    printf("NGTCP2_ERR_DRAINING\n");
                    return;
                case NGTCP2_ERR_RETRY:
                    printf("NGTCP2_ERR_RETRY\n");
                    return;
                case NGTCP2_ERR_DROP_CONN:
                    printf("NGTCP2_ERR_DROP_CONN\n");
                    return;
                case NGTCP2_ERR_CRYPTO:
                    printf("NGTCP2_ERR_CRYPTO\n");
                    return;
            }
        }
    }
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
