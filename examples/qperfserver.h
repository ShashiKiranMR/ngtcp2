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

#define NGTCP2_SV_SCIDLEN 18
union sockaddr_union {
    struct sockaddr_storage storage;
    struct sockaddr sa;
    struct sockaddr_in6 in6;
    struct sockaddr_in in;
};
