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
#include <net/if.h>
#include <getopt.h>
#include <netdb.h>
#include <sys/mman.h>

#define NGTCP2_SV_SCIDLEN 18
enum network_error {
    NETWORK_ERR_OK = 0,
    NETWORK_ERR_FATAL = -10,
    NETWORK_ERR_SEND_BLOCKED = -11,
    NETWORK_ERR_CLOSE_WAIT = -12,
    NETWORK_ERR_RETRY = -13,
    NETWORK_ERR_DROP_CONN = -14,
};

union in_addr_union {
    struct in_addr in;
    struct in6_addr in6;
};

union sockaddr_union {
    struct sockaddr_storage storage;
    struct sockaddr sa;
    struct sockaddr_in6 in6;
    struct sockaddr_in in;
};

struct Address {
    socklen_t len;
    union sockaddr_union su;
    uint32_t ifindex;
};
