/*
 * ESP Platform Compatibility Header for Picoquic
 *
 * This header provides lwIP socket API compatibility for ESP32 platforms.
 * It maps lwIP's BSD-like socket API to the POSIX socket API expected by picoquic.
 *
 * Use ESP_PLATFORM define to enable this header.
 */

#ifndef ESP_PLATFORM_H
#define ESP_PLATFORM_H

#ifdef ESP_PLATFORM

/* lwIP socket API headers */
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "lwip/inet.h"
#include "lwip/ip_addr.h"
#include "lwip/err.h"
#include "lwip/sys.h"

/* Standard headers available on ESP-IDF and ESP-HAL with newlib */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/time.h>

/*
 * lwIP socket API is largely BSD-compatible, but we need some adjustments.
 * These are provided by lwip/sockets.h:
 * - socket(), bind(), connect(), listen(), accept()
 * - send(), recv(), sendto(), recvfrom()
 * - setsockopt(), getsockopt()
 * - select(), FD_SET, FD_CLR, FD_ISSET, FD_ZERO
 * - close() for sockets
 * - htons(), htonl(), ntohs(), ntohl()
 * - struct sockaddr, sockaddr_in, sockaddr_in6
 * - AF_INET, AF_INET6, SOCK_DGRAM, SOCK_STREAM
 */

/*
 * Some POSIX socket options may not be available in lwIP.
 * Define fallbacks for missing options.
 */

/* IP_PKTINFO for receiving destination address */
#ifndef IP_PKTINFO
#define IP_PKTINFO 8
#endif

/* IPV6_PKTINFO */
#ifndef IPV6_PKTINFO
#define IPV6_PKTINFO 50
#endif

/* IPV6_RECVPKTINFO */
#ifndef IPV6_RECVPKTINFO
#define IPV6_RECVPKTINFO IPV6_PKTINFO
#endif

/* IPV6_RECVTCLASS for receiving traffic class (ECN) */
#ifndef IPV6_RECVTCLASS
#define IPV6_RECVTCLASS 66
#endif

/* IP_RECVTOS for receiving TOS/ECN bits */
#ifndef IP_RECVTOS
#define IP_RECVTOS 13
#endif

/* Path MTU discovery options */
#ifndef IP_MTU_DISCOVER
#define IP_MTU_DISCOVER 10
#endif

#ifndef IP_PMTUDISC_DO
#define IP_PMTUDISC_DO 2
#endif

#ifndef IPV6_MTU_DISCOVER
#define IPV6_MTU_DISCOVER 23
#endif

/* UDP segment size for GSO (not available on ESP, define as no-op) */
#ifndef UDP_SEGMENT
#define UDP_SEGMENT 103
#endif

#ifndef UDP_GRO
#define UDP_GRO 104
#endif

/*
 * Control message (cmsg) structures for ancillary data.
 * lwIP may not fully support recvmsg/sendmsg with control messages.
 * We provide simplified definitions here.
 */

#ifndef CMSG_SPACE
#define CMSG_ALIGN(len) (((len) + sizeof(long) - 1) & ~(sizeof(long) - 1))
#define CMSG_SPACE(len) (CMSG_ALIGN(sizeof(struct cmsghdr)) + CMSG_ALIGN(len))
#define CMSG_LEN(len)   (CMSG_ALIGN(sizeof(struct cmsghdr)) + (len))
#endif

#ifndef CMSG_DATA
#define CMSG_DATA(cmsg) ((unsigned char *)((struct cmsghdr *)(cmsg) + 1))
#endif

#ifndef CMSG_FIRSTHDR
#define CMSG_FIRSTHDR(mhdr) \
    ((size_t)(mhdr)->msg_controllen >= sizeof(struct cmsghdr) ? \
     (struct cmsghdr *)(mhdr)->msg_control : (struct cmsghdr *)NULL)
#endif

#ifndef CMSG_NXTHDR
#define CMSG_NXTHDR(mhdr, cmsg) \
    (((char *)(cmsg) + CMSG_ALIGN((cmsg)->cmsg_len) + \
      CMSG_ALIGN(sizeof(struct cmsghdr)) > \
      (char *)(mhdr)->msg_control + (mhdr)->msg_controllen) ? \
     (struct cmsghdr *)NULL : \
     (struct cmsghdr *)((char *)(cmsg) + CMSG_ALIGN((cmsg)->cmsg_len)))
#endif

/* msghdr structure if not defined by lwIP */
#ifndef HAVE_STRUCT_MSGHDR
struct msghdr {
    void         *msg_name;       /* Optional address */
    socklen_t     msg_namelen;    /* Size of address */
    struct iovec *msg_iov;        /* Scatter/gather array */
    size_t        msg_iovlen;     /* # elements in msg_iov */
    void         *msg_control;    /* Ancillary data */
    size_t        msg_controllen; /* Ancillary data buffer len */
    int           msg_flags;      /* Flags on received message */
};
#endif

/* iovec structure if not defined */
#ifndef HAVE_STRUCT_IOVEC
struct iovec {
    void  *iov_base;    /* Starting address */
    size_t iov_len;     /* Number of bytes to transfer */
};
#endif

/* cmsghdr structure if not defined */
#ifndef HAVE_STRUCT_CMSGHDR
struct cmsghdr {
    size_t cmsg_len;    /* Data byte count, including header */
    int    cmsg_level;  /* Originating protocol */
    int    cmsg_type;   /* Protocol-specific type */
};
#endif

/* in_pktinfo structure for IP_PKTINFO */
#ifndef HAVE_STRUCT_IN_PKTINFO
struct in_pktinfo {
    int             ipi_ifindex;  /* Interface index */
    struct in_addr  ipi_spec_dst; /* Local address */
    struct in_addr  ipi_addr;     /* Header destination address */
};
#endif

/* in6_pktinfo structure for IPV6_PKTINFO */
#ifndef HAVE_STRUCT_IN6_PKTINFO
struct in6_pktinfo {
    struct in6_addr ipi6_addr;    /* src/dst IPv6 address */
    unsigned int    ipi6_ifindex; /* send/recv interface index */
};
#endif

/*
 * sendmsg/recvmsg may not be available in lwIP.
 * We provide wrapper functions that fall back to sendto/recvfrom.
 */
#ifndef LWIP_SOCKET_HAVE_SENDMSG
static inline ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
    /* Simplified implementation without control message support */
    if (msg->msg_iovlen != 1) {
        errno = EOPNOTSUPP;
        return -1;
    }

    return sendto(sockfd,
                  msg->msg_iov[0].iov_base,
                  msg->msg_iov[0].iov_len,
                  flags,
                  (struct sockaddr *)msg->msg_name,
                  msg->msg_namelen);
}
#endif

#ifndef LWIP_SOCKET_HAVE_RECVMSG
static inline ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags)
{
    /* Simplified implementation without control message support */
    if (msg->msg_iovlen != 1) {
        errno = EOPNOTSUPP;
        return -1;
    }

    socklen_t addrlen = msg->msg_namelen;
    ssize_t ret = recvfrom(sockfd,
                           msg->msg_iov[0].iov_base,
                           msg->msg_iov[0].iov_len,
                           flags,
                           (struct sockaddr *)msg->msg_name,
                           &addrlen);

    if (ret >= 0) {
        msg->msg_namelen = addrlen;
        msg->msg_controllen = 0;  /* No control data available */
        msg->msg_flags = 0;
    }

    return ret;
}
#endif

/* Compatibility for missing socket functions */
#ifndef HAVE_SOCKETPAIR
static inline int socketpair(int domain, int type, int protocol, int sv[2])
{
    (void)domain;
    (void)type;
    (void)protocol;
    (void)sv;
    errno = EOPNOTSUPP;
    return -1;
}
#endif

/* Additional platform-specific defines */
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#ifndef MSG_DONTWAIT
#define MSG_DONTWAIT 0x40
#endif

/* ESP32 uses FreeRTOS ticks for timing */
#ifndef CLOCKS_PER_SEC
#define CLOCKS_PER_SEC 1000
#endif

/* Disable features not available on ESP32 */
#define PICOQUIC_NO_GSO 1
#define PICOQUIC_NO_GRO 1
#define PICOQUIC_NO_PMTUD 1

/* Thread-safe random - use ESP hardware RNG if available */
#ifdef CONFIG_IDF_TARGET
#include "esp_random.h"
#define picoquic_crypto_random_bytes(buf, len) esp_fill_random(buf, len)
#else
/* For bare-metal esp-hal, provide a stub or use hw RNG directly */
extern void esp_fill_random(void* buf, size_t len);
#define picoquic_crypto_random_bytes(buf, len) esp_fill_random(buf, len)
#endif

#endif /* ESP_PLATFORM */

#endif /* ESP_PLATFORM_H */
