/* qperf server for ngtcp2 which is similar to qperf server for quicly */

#include "qperfserver.h"
#include <time.h>
#include <assert.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_openssl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <netinet/in.h>

struct qperf_conn_wrapper {
    struct ngtcp2_conn *conn;
    struct ngtcp2_crypto_conn_ref *conn_ref;
    SSL *ssl;
    size_t dcidlen;
    const uint8_t *dcid;
    struct {
        int64_t stream_id;
        const uint8_t *data;
        size_t datalen;                    
        size_t nwrite;                     
    } stream;
    ngtcp2_connection_close_error last_error;
};

static int server_socket;
struct Address s_addr;
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

static uint64_t timestamp(void) {
    struct timespec tp;
    if (clock_gettime(CLOCK_MONOTONIC, &tp) != 0) {
        fprintf(stderr, "clock_gettime: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }       
    return (uint64_t)tp.tv_sec * NGTCP2_SECONDS + (uint64_t)tp.tv_nsec;
}

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
    int s = -1;
    const struct addrinfo *rp;
    for(rp = addr; rp != NULL; rp = rp->ai_next) {
        s = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if(s == -1) {
            continue;
        }

        int on = 1;
        if (setsockopt(s, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on)) != 0) {
            close(s);
            printf("setsockopt(IP_PKTINFO) failed");
            return -1;
        }
        if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) != 0) {
            close(s);
            printf("setsockopt(SO_REUSEADDR) failed");
            return -1;
        }
        if (setsockopt(s, IPPROTO_IP, IP_RECVTOS, &on, sizeof(on)) != 0) {
            close(s);
            printf("setsockopt(IP_RECVTOS) failed");
            return -1;
        }
        on = IP_PMTUDISC_DO;
        if (setsockopt(s, IPPROTO_IP, IP_MTU_DISCOVER, &on, sizeof(on)) != 0) {
            close(s);
            printf("setsockopt(IP_MTU_DISCOVER) failed");
            return -1;
        }

        if(bind(s, rp->ai_addr, rp->ai_addrlen) != -1) {
            break; // success
        }

        // fail -> close socket and try with next addr
        close(s);
    }
    if (!rp) {
        printf("Could not bind\n");
        return -1;
    }
    socklen_t len = sizeof(s_addr.su.storage);
    if (getsockname(s, &s_addr.su.sa, &len) == -1) {
        printf("getsockname: \n", strerror(errno));
        close(s);
        return -1;
    }
    s_addr.len = len;
    s_addr.ifindex = 0;
    return s;
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

    /*TBD: should we call SSL_CTX_set_alpn_select_cb ?*/

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

int generate_secure_random(uint8_t *data, size_t datalen) {
    if (RAND_bytes(data, (int)datalen) != 1) {
        return -1;
    }

    return 0;
}

void server_tls_session_init(struct qperf_conn_wrapper *conn_wrapper) {
    SSL *ssl;

    ssl = SSL_new(server_ctx);
    if (!ssl) {
        printf("Error while creating SSL_new\n");
        return;
    }
    SSL_set_app_data(ssl, conn_wrapper->conn_ref); /* Link ssl <-> conn_ref */
    SSL_set_accept_state(ssl);
    SSL_set_quic_early_data_enabled(ssl, 1);
    ngtcp2_conn_set_tls_native_handle(conn_wrapper->conn, ssl); /* Link conn <-> ssl */
}

static ngtcp2_conn *get_conn(ngtcp2_crypto_conn_ref *conn_ref) {
    struct qperf_conn_wrapper *conn_wrapper = (struct qperf_conn_wrapper *)conn_ref->user_data;

    return conn_wrapper->conn;
}

void server_conn_ref_setup(struct qperf_conn_wrapper *conn_wrapper) {
    struct ngtcp2_crypto_conn_ref *conn_ref = conn_wrapper->conn_ref;
    conn_ref->user_data = conn_wrapper; /* Will be used to get back conn */
    conn_ref->get_conn  = get_conn;
}

unsigned int msghdr_get_ecn(struct msghdr *msg, int family) {
    struct cmsghdr *cmsg;
    switch (family) {  
        case AF_INET:
            for (cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
                if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_TOS && cmsg->cmsg_len) {
                    return *(uint8_t *)(CMSG_DATA(cmsg));
                }
            }
            break;
    }
    return 0;
}

int msghdr_get_local_addr(struct Address *local_addr, struct msghdr *msg, int family) {
    struct cmsghdr *cmsg;
    switch (family) {
    case AF_INET:
        cmsg = CMSG_FIRSTHDR(msg);
        for (; cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
            if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO) {
                struct in_pktinfo *pktinfo = (struct in_pktinfo *)(CMSG_DATA(cmsg));
                local_addr->ifindex = pktinfo->ipi_ifindex;
                local_addr->len = sizeof(local_addr->su.in);
                struct sockaddr_in *sa = &local_addr->su.in;
                sa->sin_family = AF_INET;
                sa->sin_addr = pktinfo->ipi_addr;
                return 0;
            }
        }
        return 1;
    }
    return 1;
}

int server_send_packet(ev_io *w, struct qperf_conn_wrapper *conn_wrapper,
        uint32_t ecn, uint8_t *data, size_t datalen, 
        const ngtcp2_addr *local_addr, const ngtcp2_addr *remote_addr) {

    struct iovec iov = {(uint8_t *)data, datalen};
    struct msghdr msg = {0};
    ssize_t nwrite, controllen = 0;
    uint8_t msg_ctrl[64];
    struct cmsghdr *cm;

    msg.msg_name = (struct sockaddr *)(remote_addr->addr);
    msg.msg_namelen = remote_addr->addrlen;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    memset(msg_ctrl, 0, sizeof(msg_ctrl));
    msg.msg_control = msg_ctrl;
    msg.msg_controllen = sizeof(msg_ctrl);
    cm = CMSG_FIRSTHDR(&msg);
  
    switch (local_addr->addr->sa_family) {
        case AF_INET: {
            controllen += CMSG_SPACE(sizeof(struct in_pktinfo));
            cm->cmsg_level = IPPROTO_IP;
            cm->cmsg_type = IP_PKTINFO;
            cm->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
            struct in_pktinfo *pktinfo = (struct in_pktinfo *)(CMSG_DATA(cm));
            memset(pktinfo, 0, sizeof(struct in_pktinfo));
            struct sockaddr_in *addrin = (struct sockaddr_in *)(local_addr->addr);
            pktinfo->ipi_spec_dst = addrin->sin_addr;
            break;
        }
        default:
            assert(0);
    }
    msg.msg_controllen = controllen;
    switch (local_addr->addr->sa_family) {
        case AF_INET:
            if (setsockopt(w->fd, IPPROTO_IP, IP_TOS, &ecn, sizeof(ecn)) == -1) {
                printf("setsockopt: %s\n", strerror(errno));
                return -1;
            }
            break;
        default:
            assert(0);
    }
    do {
        nwrite = sendmsg(w->fd, &msg, 0);
    } while (nwrite == -1 && errno == EINTR);

    if (nwrite == -1) {
        printf("sendmsg: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

void server_send_response(ev_io *w, struct qperf_conn_wrapper *conn_wrapper, 
        uint32_t ecn, uint8_t *rx_buf, ssize_t bytes_received) {
    
    ngtcp2_tstamp ts = timestamp();
    ngtcp2_conn *conn = conn_wrapper->conn;
    ngtcp2_pkt_info pi;
    ngtcp2_ssize nwrite;
    ngtcp2_ssize ndatalen;
    ngtcp2_path_storage ps;
    ngtcp2_vec datav;
    size_t datavcnt;
    uint8_t tx_buf[1280];
    uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_MORE;
    int64_t stream_id = -1;

    printf("Preparing response\n");
    datav.base  = rx_buf;
    datav.len   = bytes_received;
    ngtcp2_path_storage_zero(&ps);

    /* Create QUIC response packet */
    while (true) {
        nwrite = ngtcp2_conn_writev_stream(conn, &ps.path, &pi, tx_buf, sizeof(tx_buf), 
                                    &ndatalen, flags, stream_id, &datav, datavcnt, ts);
        if (nwrite < 0) {
            switch (nwrite) {
                case NGTCP2_ERR_WRITE_MORE:
                    conn_wrapper->stream.nwrite += (size_t)ndatalen;
                    continue;
                default:
                    printf("ngtcp2_conn_writev_stream: %s\n",
                            ngtcp2_strerror((int)nwrite));
                    ngtcp2_connection_close_error_set_transport_error_liberr(
                            &conn_wrapper->last_error, (int)nwrite, NULL, 0);
                    return -1;
            }
        }
        if (nwrite == 0) {
            return 0;
        }
        if (ndatalen > 0) {
            conn_wrapper->stream.nwrite += (size_t)ndatalen;
        }
        /* Send the response on the wire */
        if (server_send_packet(w, conn_wrapper, ecn, tx_buf, (size_t)nwrite, &ps.path.local, &ps.path.remote) != 0)
            break;
    }
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
    
    uint8_t msg_ctrl[64];
    //uint8_t msg_ctrl[CMSG_SPACE(sizeof(uint8_t))];
    msg.msg_control = msg_ctrl;

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
    //static ngtcp2_path_storage path;
    struct ngtcp2_path path;
    struct ngtcp2_pkt_info pi;

    struct Address local_addr = {0};

    int rv;
    msg.msg_namelen = sizeof(su);
    msg.msg_controllen = sizeof(msg_ctrl);
    while ((bytes_received = recvmsg(w->fd, &msg, 0)) != -1) {
        printf("Bytes received = %ld\n", bytes_received);
        pi.ecn = msghdr_get_ecn(&msg, su.storage.ss_family);
        rv = msghdr_get_local_addr(&local_addr, &msg, su.storage.ss_family);
        if (rv) {
            printf("Unable to obtain local address\n");
            continue;
        }
        switch (local_addr.su.storage.ss_family) {
            case AF_INET:
                assert(AF_INET == s_addr.su.storage.ss_family);
                local_addr.su.in.sin_port = s_addr.su.in.sin_port;
                break;
            default:
                assert(0);
        }

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
            scid_n.datalen = NGTCP2_SV_SCIDLEN;
            if (generate_secure_random(scid_n.data, scid_n.datalen) != 0) {
                printf("Could not generate connection ID\n");
                return;
            }
            //path_init(&path, 0, 0, 0, 0);
            path.local.addr     = &local_addr.su.sa;
            path.local.addrlen  = local_addr.len;
            path.remote.addr    = &su.sa;
            path.remote.addrlen = msg.msg_namelen;

            ngtcp2_settings_default(&settings);
            settings.token.base = (uint8_t *)(hd.token.base);
            settings.token.len = hd.token.len;
            ngtcp2_transport_params_default(&params);
            params.initial_max_stream_data_bidi_local = 256*1024;
            params.initial_max_stream_data_bidi_remote = 256*1024;
            params.initial_max_stream_data_uni = 256*1024;
            params.initial_max_data = 1*1024*1024;
            params.initial_max_streams_bidi = 100;
            params.initial_max_streams_uni = 3;
            params.max_idle_timeout = 30 * NGTCP2_SECONDS;
            params.stateless_reset_token_present = 1;
            params.active_connection_id_limit = 7;
            params.original_dcid = hd.scid;
            if (generate_secure_random(params.stateless_reset_token, sizeof(params.stateless_reset_token)) != 0) {
                printf("Could not generate stateless reset token\n");
                return;
            }
            server_default_callbacks(&cb);
            rv = ngtcp2_conn_server_new(&conn, &hd.scid, &scid_n, &path, hd.version, &cb, 
                                        &settings, &params, NULL, NULL);
            conn_wrapper = new_conn_wrapper(conn, dcid, dcidlen);
            append_conn(conn_wrapper);
            server_conn_ref_setup(conn_wrapper);
            server_tls_session_init(conn_wrapper);
        }
        /* Decrypt the pkt */
        conn = conn_wrapper->conn;
        printf("Invoking ngtcp2_conn_read_pkt\n");
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
        server_send_response(w, conn_wrapper, pi.ecn, buf, bytes_received);
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
