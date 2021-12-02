#define _DEFAULT_SOURCE

#include <asm/types.h>
#include <stdio.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netdb.h>
#include <arpa/inet.h>

#include "lmdnsd.h"
#include "lmdnsd_mdns_parser.h"
#include "lmdnsd_packet.h"
#include "lmdnsd_fnv1a32.h"


void * get_in_addr (
    struct sockaddr *sa
)
{
    if (AF_INET == sa->sa_family) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }
    if (AF_INET6 == sa->sa_family) {
        return &(((struct sockaddr_in6*)sa)->sin6_addr);
    }
        
    else {
        syslog(LOG_ERR, "%s:%d:%s: what is this family: %d", __FILE__, __LINE__, __func__, sa->sa_family);
        return 0;
    }
}


void print_qname (
    uint8_t ** buf
)
{

    uint8_t len = (*buf)[0];


    while (0 != len) {

        if (0b11000000 <= len) {
            printf("<\n");
            (*buf) += 2;
            return;
        }

        // go to value
        (*buf)++;

        printf("%.*s . ", len, (*buf));

        (*buf) += len;
        len = (*buf)[0];
    }

    (*buf)+=1;

    printf("\n");

}


int lmdnsd_packet_cb (
    const struct lmdnsd_packet_s * const packet,
    void * user_data
)
{

    int ret = 0;

//    syslog(LOG_DEBUG, "%s:%d:%s: hi! id=%d, flags=%d, question count=%d, answer count=%d, nscount=%d, additional count=%d",
//            __FILE__, __LINE__, __func__,
//            packet->id, packet->flags_raw,
//            packet->questions_len, 
//            packet->answers_len,
//            packet->ns_len,
//            packet->ar_len
//    );

    return 0;
}


int lmdnsd_create_packet (
    struct lmdnsd_s * lmdnsd,
    uint8_t * buf,
    uint32_t buf_len,
    struct lmdnsd_packet_s * packet
)
{

    int ret = 0;

    return 0;
}


int lmdnsd_send_packet (
    struct lmdnsd_s * lmdnsd
)
{

    int ret = 0;
    int bytes_written = 0;

    uint8_t buf[] = {
        // transaction id
        0x00, 0x00,

        // flags
        0x00, 0x00,

        // questions
        0x00, 0x01,

        // answers
        0x00, 0x00,

        // authoritative
        0x00, 0x00,

        // additional rrs
        0x00, 0x00,

        // first question name length
        0x04,

        // and it's bytes
        '_', 'h', 'a', 'p',

        0x04,
        '_', 't', 'c', 'p',


        0x05,
        'l', 'o', 'c', 'a', 'l',

        // length
        //0xc0, 0x0c,

        // length
        0x00,

        // type
        0x00, 0x0c,

        // class
        0x00, 0x01
    };
    uint32_t buf_len = sizeof(buf);


    struct sockaddr_in broadcast = {
        .sin_family = AF_INET,
        .sin_port = htons(5353)
    };
    inet_pton(AF_INET, "224.0.0.251", &broadcast.sin_addr);

    struct sockaddr_in6 broadcast6 = {
        .sin6_family = AF_INET6,
        .sin6_port = htons(5353)
    };
    inet_pton(AF_INET, "ff02::fb", &broadcast.sin_addr);


    struct sockaddr_in src = {
        .sin_family = AF_INET,
        .sin_port = htons(5353)
    };
    inet_pton(AF_INET, "10.10.110.1", &src.sin_addr);


    struct addrinfo *servinfo, *p;
    ret = getaddrinfo(
        /* host = */ NULL, 
        /* port = */ "5353",
        /* hints = */ &(struct addrinfo) {
            .ai_family = AF_INET,
            .ai_socktype = SOCK_DGRAM,
            .ai_flags = AI_PASSIVE
        },
        /* servinfo = */ &servinfo
    );
    if (-1 == ret) {
        syslog(LOG_WARNING, "%s:%d:%s: getaddrinfo: %s", __FILE__, __LINE__, __func__, gai_strerror(ret));
        return -1;
    }
    if (NULL == servinfo) {
        syslog(LOG_WARNING, "%s:%d:%s: no results from getaddrinfo", __FILE__, __LINE__, __func__);
        return -1;
    }

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (-1 == fd) {
        syslog(LOG_ERR, "%s:%d:%s: socket: %s", __FILE__, __LINE__, __func__, strerror(errno));
        return -1;
    }

    ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));
    if (-1 == ret) {
        syslog(LOG_ERR, "%s:%d:%s: setsockopt: %s", __FILE__, __LINE__, __func__, strerror(errno));
        return -1;
    }

    ret = setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &(int){1}, sizeof(int));
    if (-1 == ret) {
        syslog(LOG_ERR, "%s:%d:%s: setsockopt: %s", __FILE__, __LINE__, __func__, strerror(errno));
        return -1;
    }

//    struct ifreq ifr = {
//        .ifr_name = "peer0"
//    };
//
//    ret = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr));
//    if (-1 == ret) {
//        syslog(LOG_ERR, "%s:%d:%s: setsockopt: %s", __FILE__, __LINE__, __func__, strerror(errno));
//        return -1;
//    }


    for (p = servinfo; p != NULL; p = p->ai_next) {
        ret = bind(fd, p->ai_addr, p->ai_addrlen);
        if (-1 == ret) {
            syslog(LOG_ERR, "%s:%d:%s: bind: %s", __FILE__, __LINE__, __func__, strerror(errno));
            return -1;
        }
        bytes_written = sendto(fd, buf, buf_len, 0, (struct sockaddr*)&broadcast, sizeof(broadcast));
        if (-1 == bytes_written) {
            syslog(LOG_ERR, "%s:%d:%s: sendto: %s", __FILE__, __LINE__, __func__, strerror(errno));
            return -1;
        }
        printf("%s:%d:%s: ok\n", __FILE__, __LINE__, __func__);
    }

    ret = bind(fd, (struct sockaddr*)&src, sizeof(src));
    if (-1 == ret) {
        syslog(LOG_ERR, "%s:%d:%s: bind: %s", __FILE__, __LINE__, __func__, strerror(errno));
        return -1;
    }
        

    bytes_written = sendto(fd, buf, buf_len, 0, (struct sockaddr*)&broadcast, sizeof(broadcast));
    if (-1 == bytes_written) {
        syslog(LOG_ERR, "%s:%d:%s: sendto: %s", __FILE__, __LINE__, __func__, strerror(errno));
        return -1;
    }

    printf("%s:%d:%s: ok\n", __FILE__, __LINE__, __func__);


    // next, maybe call lmdnsd_connect_with_servinfo() or something...
    // app->servinfo_p = app->servinfo;
    

    return 0;
}


int lmdnsd_epoll_event_listen (
    struct lmdnsd_s * lmdnsd,
    struct epoll_event * event,
    struct lmdnsd_epollfd_s * lmdnsd_epollfd
)
{

    int ret = 0;
    int bytes_read = 0;
    uint8_t buf[1024];
    uint8_t rbuf[1024];
    char addr[512];
    char dst_addr[512];
    struct sockaddr_storage their_addr = {0};
    uint32_t their_addr_len = sizeof(their_addr);
    struct iovec iov[1] = {
        {
            .iov_base = rbuf,
            .iov_len = 1024
        }
    };
    struct msghdr msghdr = {
        .msg_name = &their_addr,
        .msg_namelen = sizeof(their_addr),
        .msg_control = buf,
        .msg_controllen = sizeof(buf),
        .msg_iov = iov,
        .msg_iovlen = 1,
    };

    bytes_read = recvmsg(
        /* fd = */ lmdnsd_epollfd->fd,
        /* msghdr = */ &msghdr,
        /* flags = */ 0
    );
    if (-1 == bytes_read) {
        syslog(LOG_ERR, "%s:%d:%s: recvmsg: %s", __FILE__, __LINE__, __func__, strerror(errno));
        return -1;
    }

    struct cmsghdr * cmsg = CMSG_FIRSTHDR(&msghdr);
    if (NULL == cmsg) {
        // this can happen, what do?
        syslog(LOG_ERR, "%s:%d:%s: CMSG_FIRSTHDR returned NULL", __FILE__, __LINE__, __func__);
        return 0;
    }

    int i = 0;
    while (1) {
        if (IPPROTO_IP != cmsg->cmsg_level || IP_PKTINFO != cmsg->cmsg_type) {
            cmsg = CMSG_NXTHDR(&msghdr, cmsg);
            if (1024 < ++i) {
                syslog(LOG_ERR, "%s:%d:%s: infinite loop", __FILE__, __LINE__, __func__);
                return -1;
            }
            continue;
        }

        struct in_pktinfo * pi = (void*)CMSG_DATA(cmsg);

        // their_addr is the source sockaddr
        // pi->ipi_spec_dst is the destination in_addr
        // pi->ipi_addr is the receiving interface in_addr

        const char * res = inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr*)&their_addr), addr, sizeof(addr));
        if (NULL == res) {
            syslog(LOG_ERR, "%s:%d:%s: inet_ntop: %s", __FILE__, __LINE__, __func__, strerror(errno));
            return -1;
        }

        const char * res2 = inet_ntop(their_addr.ss_family, &pi->ipi_addr, dst_addr, sizeof(dst_addr));
        if (NULL == res) {
            syslog(LOG_ERR, "%s:%d:%s: inet_ntop: %s", __FILE__, __LINE__, __func__, strerror(errno));
            return -1;
        }

//        printf("%s:%d:%s: %s -> %s, %d bytes\n", 
//                __FILE__, __LINE__, __func__,
//                res, res2, bytes_read);
        

        cmsg = CMSG_NXTHDR(&msghdr, cmsg);
        if (NULL == cmsg) {
            break;
        }

        if (1024 < ++i) {
            syslog(LOG_ERR, "%s:%d:%s: infinite loop", __FILE__, __LINE__, __func__);
            return -1;
        }
    }


    struct lmdnsd_mdns_parser_s parser = {0};
    ret = lmdnsd_mdns_parser_init(&parser, lmdnsd_packet_cb, lmdnsd);
    if (-1 == ret) {
        syslog(LOG_ERR, "%s:%d:%s: lmdnsd_mdns_parser_init returned -1", __FILE__, __LINE__, __func__);
        return -1;
    }

    ret = lmdnsd_mdns_parser_parse(&parser, rbuf, bytes_read);
    if (-1 == ret) {
        syslog(LOG_ERR, "%s:%d:%s: lmdnsd_mdns_parser_parse returned -1", __FILE__, __LINE__, __func__);
        return -1;
    }

    
//    struct __attribute__((packed)) {
//        uint16_t id;
//        union {
//            uint16_t flags;
//            struct {
//                uint8_t is_query : 1;
//                uint8_t opcode : 4;
//                uint8_t authoriative : 1;
//            };
//        };
//        uint16_t num_questions;
//        uint16_t num_answers;
//        uint16_t num_records;
//        uint16_t num_additional_records;
//
//    } * data;
//
//    data = (void*)&rbuf;
//
//    printf("%s:%d:%s: id=%d, flags=%d, is_query=%d, question count=%d, answer count=%d, record count=%d, additional=%d\n",
//        __FILE__, __LINE__, __func__,
//        ntohs(data->id), 
//        data->flags,
//        data->is_query,
//        ntohs(data->num_questions),
//        ntohs(data->num_answers),
//        ntohs(data->num_records),
//        ntohs(data->num_additional_records)
//    );
//
//    int num_questions = ntohs(data->num_questions);
//    uint8_t * ptr = &((uint8_t*)&rbuf)[sizeof(*data)];
//    uint8_t qu = 0;
//    for (; 0 < num_questions; num_questions--) {
//        printf("%s:%d:%s question: \n", __FILE__, __LINE__, __func__);
//        print_qname(&ptr);
//        uint16_t qtype = ntohs(*(uint16_t*)ptr);
//        ptr += 2;
//        uint16_t qclass = ntohs(*(uint16_t*)ptr) & 0b0111111111111111;
//        qu = (ntohs(*(uint16_t*)ptr) & 0b1000000000000000) == 0b1000000000000000;
//        ptr += 2;
//    }
//
//
//    int num_answers = ntohs(data->num_answers);
//    for (; 0 < num_answers; num_answers--) {
//        printf("%s:%d:%s answer: \n", __FILE__, __LINE__, __func__);
//        print_qname(&ptr);
//        uint16_t type = ntohs(*(uint16_t*)ptr);
//        ptr += 2;
//        uint16_t class = ntohs(*(uint16_t*)ptr) & 0b1111111111111111;
//        uint8_t cache_flush = (ntohs(*(uint16_t*)ptr) & 0b1000000000000000) == 0b1000000000000000;
//        ptr += 2;
//        uint32_t ttl = ntohl(*(uint32_t*)ptr);
//        ptr += 4;
//        uint16_t rdlength = ntohs(*(uint16_t*)ptr);
//        ptr += 2;
//        printf("%s:%d:%s: type=%d, class=%d, len=%d\n", __FILE__, __LINE__, __func__, type, class, rdlength);
//        ptr += rdlength;
//    }
//
//    int num_records = ntohs(data->num_records);
//    for (; 0 < num_records; num_records--) {
//        printf("%s:%d:%s record: \n", __FILE__, __LINE__, __func__);
//        print_qname(&ptr);
//        uint16_t type = ntohs(*(uint16_t*)ptr);
//        ptr += 2;
//        uint16_t class = ntohs(*(uint16_t*)ptr) & 0b1111111111111111;
//        uint8_t cache_flush = (ntohs(*(uint16_t*)ptr) & 0b1000000000000000) == 0b1000000000000000;
//        ptr += 2;
//        uint32_t ttl = ntohl(*(uint32_t*)ptr);
//        ptr += 4;
//        uint16_t rdlength = ntohs(*(uint16_t*)ptr);
//        ptr += 2;
//        printf("%s:%d:%s: type=%d, class=%d, len=%d\n", __FILE__, __LINE__, __func__, type, class, rdlength);
//        ptr += rdlength;
//    }
//
//    int num_additional_records = ntohs(data->num_additional_records);
//    for (; 0 < num_additional_records; num_additional_records--) {
//        printf("%s:%d:%s: additional record: \n", __FILE__, __LINE__, __func__);
//        print_qname(&ptr);
//        uint16_t type = ntohs(*(uint16_t*)ptr);
//        ptr += 2;
//        uint16_t class = ntohs(*(uint16_t*)ptr) & 0b1111111111111111;
//        uint8_t cache_flush = (ntohs(*(uint16_t*)ptr) & 0b1000000000000000) == 0b1000000000000000;
//        ptr += 2;
//        uint32_t ttl = ntohl(*(uint32_t*)ptr);
//        ptr += 4;
//        uint16_t rdlength = ntohs(*(uint16_t*)ptr);
//        ptr += 2;
//        printf("%s:%d:%s: type=%d, class=%d, len=%d\n", __FILE__, __LINE__, __func__, type, class, rdlength);
//        ptr += rdlength;
//    }
//
//    printf("\n\n\n");


    ret = epoll_ctl(
        lmdnsd->epollfd,
        EPOLL_CTL_MOD,
        lmdnsd_epollfd->fd,
        &(struct epoll_event){
            .events = EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLONESHOT,
            .data = event->data
        }
    );
    if (-1 == ret) {
        syslog(LOG_ERR, "%s:%d:%s: epoll_ctl: %s", __FILE__, __LINE__, __func__, strerror(errno));
        return -1;
    }

    return 0;
}


int lmdnsd_epoll_event_netlink_newlink (
    struct lmdnsd_s * lmdnsd,
    struct epoll_event * event,
    struct lmdnsd_epollfd_s * lmdnsd_epollfd,
    struct ifinfomsg * ifi,
    uint32_t ifi_len
)
{

    // this is called when an interface gets link info, but its also called
    // when link is removed from an interface. You need to check the flags to
    // see what state it's in.

    //struct rtattr * rt = IFA_RTA(

    syslog(LOG_INFO, "%s:%d:%s: interface %d just got link, type=%d, flags=%d, family=%d",
            __FILE__, __LINE__, __func__, ifi->ifi_index, ifi->ifi_type, ifi->ifi_flags, ifi->ifi_family);

    if (IFF_UP == (IFF_UP & ifi->ifi_flags)) {
        syslog(LOG_INFO, "%s:%d:%s: its up", __FILE__, __LINE__, __func__);
    }

    if (IFF_BROADCAST == (IFF_BROADCAST & ifi->ifi_flags)) {
        syslog(LOG_INFO, "%s:%d:%s: broadcast", __FILE__, __LINE__, __func__);
    }

    if (IFF_DEBUG == (IFF_DEBUG & ifi->ifi_flags)) {
        syslog(LOG_INFO, "%s:%d:%s: debug", __FILE__, __LINE__, __func__);
    }

    if (IFF_LOOPBACK == (IFF_LOOPBACK & ifi->ifi_flags)) {
        syslog(LOG_INFO, "%s:%d:%s: loopback", __FILE__, __LINE__, __func__);
    }

    if (IFF_POINTOPOINT == (IFF_POINTOPOINT & ifi->ifi_flags)) {
        syslog(LOG_INFO, "%s:%d:%s: point-to-point", __FILE__, __LINE__, __func__);
    }

    if (IFF_RUNNING == (IFF_RUNNING & ifi->ifi_flags)) {
        syslog(LOG_INFO, "%s:%d:%s: running", __FILE__, __LINE__, __func__);
    }

    if (IFF_NOARP == (IFF_NOARP & ifi->ifi_flags)) {
        syslog(LOG_INFO, "%s:%d:%s: no arp", __FILE__, __LINE__, __func__);
    }

    if (IFF_PROMISC == (IFF_PROMISC & ifi->ifi_flags)) {
        syslog(LOG_INFO, "%s:%d:%s: no arp", __FILE__, __LINE__, __func__);
    }

    if (IFF_ALLMULTI == (IFF_ALLMULTI & ifi->ifi_flags)) {
        syslog(LOG_INFO, "%s:%d:%s: allmulti", __FILE__, __LINE__, __func__);
    }

    if (IFF_MULTICAST == (IFF_MULTICAST & ifi->ifi_flags)) {
        syslog(LOG_INFO, "%s:%d:%s: multicast", __FILE__, __LINE__, __func__);
    }


    return 0;
}


int lmdnsd_epoll_event_netlink_dellink (
    struct lmdnsd_s * lmdnsd,
    struct epoll_event * event,
    struct lmdnsd_epollfd_s * lmdnsd_epollfd,
    struct ifinfomsg * ifi,
    uint32_t ifi_len
)
{
    // This is called when link is removed from a device; this probably means
    // the device was removed entirely from the device (e.g. unplugged a USB
    // ethernet device, or called 'ip link del veth').

    int ret = 0;

    syslog(LOG_INFO, "%s:%d:%s: interface %d just got removed, type=%d, flags=%d, family=%d",
            __FILE__, __LINE__, __func__, ifi->ifi_index, ifi->ifi_type, ifi->ifi_flags, ifi->ifi_family);

    if (IFF_UP == (IFF_UP & ifi->ifi_flags)) {
        syslog(LOG_INFO, "%s:%d:%s: its up", __FILE__, __LINE__, __func__);
    }

    if (IFF_BROADCAST == (IFF_BROADCAST & ifi->ifi_flags)) {
        syslog(LOG_INFO, "%s:%d:%s: broadcast", __FILE__, __LINE__, __func__);
    }

    if (IFF_DEBUG == (IFF_DEBUG & ifi->ifi_flags)) {
        syslog(LOG_INFO, "%s:%d:%s: debug", __FILE__, __LINE__, __func__);
    }

    if (IFF_LOOPBACK == (IFF_LOOPBACK & ifi->ifi_flags)) {
        syslog(LOG_INFO, "%s:%d:%s: loopback", __FILE__, __LINE__, __func__);
    }

    if (IFF_POINTOPOINT == (IFF_POINTOPOINT & ifi->ifi_flags)) {
        syslog(LOG_INFO, "%s:%d:%s: point-to-point", __FILE__, __LINE__, __func__);
    }

    if (IFF_RUNNING == (IFF_RUNNING & ifi->ifi_flags)) {
        syslog(LOG_INFO, "%s:%d:%s: running", __FILE__, __LINE__, __func__);
    }

    if (IFF_NOARP == (IFF_NOARP & ifi->ifi_flags)) {
        syslog(LOG_INFO, "%s:%d:%s: no arp", __FILE__, __LINE__, __func__);
    }

    if (IFF_PROMISC == (IFF_PROMISC & ifi->ifi_flags)) {
        syslog(LOG_INFO, "%s:%d:%s: no arp", __FILE__, __LINE__, __func__);
    }

    if (IFF_ALLMULTI == (IFF_ALLMULTI & ifi->ifi_flags)) {
        syslog(LOG_INFO, "%s:%d:%s: allmulti", __FILE__, __LINE__, __func__);
    }

    if (IFF_MULTICAST == (IFF_MULTICAST & ifi->ifi_flags)) {
        syslog(LOG_INFO, "%s:%d:%s: multicast", __FILE__, __LINE__, __func__);
    }

    return 0;
}


int lmdnsd_epoll_event_netlink_deladdr_ipv6 (
    struct lmdnsd_s * lmdnsd,
    struct epoll_event * event,
    struct lmdnsd_epollfd_s * lmdnsd_epollfd,
    const struct nlmsghdr * const nlmsghdr,
    const struct ifaddrmsg * const ifa,
    const uint32_t ifa_len,
    struct in6_addr * in6_addr
)
{
    char addr[INET6_ADDRSTRLEN];
    char name[IFNAMSIZ];

    // get the name of the interface
    if (NULL == if_indextoname(ifa->ifa_index, name)) {
        syslog(LOG_ERR, "%s:%d:%s: if_indextoname: %s", __FILE__, __LINE__, __func__, strerror(errno));
        return -1;
    }

    // get ip as a printable string
    if (NULL == inet_ntop(AF_INET6, in6_addr, addr, INET6_ADDRSTRLEN)) {
        syslog(LOG_ERR, "%s:%d:%s: inet_ntop: %s", __FILE__, __LINE__, __func__, strerror(errno));
        return -1;
    }

    syslog(LOG_INFO, "%s:%d:%s: interface %d (%s) just lost addr %s",
            __FILE__, __LINE__, __func__, ifa->ifa_index, name, addr);

    if (IFA_F_TEMPORARY == (IFA_F_TEMPORARY & ifa->ifa_flags)) {
        syslog(LOG_INFO, "%s:%d:%s: temporary", __FILE__, __LINE__, __func__);
    }
    if (IFA_F_PERMANENT == (IFA_F_PERMANENT & ifa->ifa_flags)) {
        syslog(LOG_INFO, "%s:%d:%s: permanent", __FILE__, __LINE__, __func__);
    }
    if (IFA_F_TENTATIVE == (IFA_F_TENTATIVE & ifa->ifa_flags)) {
        syslog(LOG_INFO, "%s:%d:%s: tentative", __FILE__, __LINE__, __func__);
    }


    if (RT_SCOPE_UNIVERSE == (RT_SCOPE_UNIVERSE & ifa->ifa_scope)) {
        syslog(LOG_INFO, "%s:%d:%s: global scope", __FILE__, __LINE__, __func__);
    }
    else if (RT_SCOPE_LINK == (RT_SCOPE_LINK & ifa->ifa_scope)) {
        syslog(LOG_INFO, "%s:%d:%s: link scope", __FILE__, __LINE__, __func__);
    }

    return 0;
}


int lmdnsd_epoll_event_netlink_newaddr_ipv6 (
    struct lmdnsd_s * lmdnsd,
    struct epoll_event * event,
    struct lmdnsd_epollfd_s * lmdnsd_epollfd,
    const struct nlmsghdr * const nlmsghdr,
    const struct ifaddrmsg * const ifa,
    const uint32_t ifa_len,
    struct in6_addr * in6_addr
)
{
    char addr[INET6_ADDRSTRLEN];
    char name[IFNAMSIZ];

    // get the name of the interface
    if (NULL == if_indextoname(ifa->ifa_index, name)) {
        syslog(LOG_ERR, "%s:%d:%s: if_indextoname: %s", __FILE__, __LINE__, __func__, strerror(errno));
        return -1;
    }

    // get ip as a printable string
    if (NULL == inet_ntop(AF_INET6, in6_addr, addr, INET6_ADDRSTRLEN)) {
        syslog(LOG_ERR, "%s:%d:%s: inet_ntop: %s", __FILE__, __LINE__, __func__, strerror(errno));
        return -1;
    }

    syslog(LOG_INFO, "%s:%d:%s: interface %d (%s) just got addr %s",
            __FILE__, __LINE__, __func__, ifa->ifa_index, name, addr);

    if (IFA_F_TEMPORARY == (IFA_F_TEMPORARY & ifa->ifa_flags)) {
        syslog(LOG_INFO, "%s:%d:%s: temporary", __FILE__, __LINE__, __func__);
    }
    if (IFA_F_PERMANENT == (IFA_F_PERMANENT & ifa->ifa_flags)) {
        syslog(LOG_INFO, "%s:%d:%s: permanent", __FILE__, __LINE__, __func__);
    }
    if (IFA_F_TENTATIVE == (IFA_F_TENTATIVE & ifa->ifa_flags)) {
        syslog(LOG_INFO, "%s:%d:%s: tentative", __FILE__, __LINE__, __func__);
    }


    if (RT_SCOPE_UNIVERSE == (RT_SCOPE_UNIVERSE & ifa->ifa_scope)) {
        syslog(LOG_INFO, "%s:%d:%s: global scope", __FILE__, __LINE__, __func__);
    }
    else if (RT_SCOPE_LINK == (RT_SCOPE_LINK & ifa->ifa_scope)) {
        syslog(LOG_INFO, "%s:%d:%s: link scope", __FILE__, __LINE__, __func__);
    }

    return 0;
}


int lmdnsd_epoll_event_netlink_newaddr_ipv4 (
    struct lmdnsd_s * lmdnsd,
    struct epoll_event * event,
    struct lmdnsd_epollfd_s * lmdnsd_epollfd,
    const struct nlmsghdr * const nlmsghdr,
    const struct ifaddrmsg * const ifa,
    const uint32_t ifa_len,
    struct in_addr * in_addr
)
{
    char addr[INET_ADDRSTRLEN];
    char name[IFNAMSIZ];

    if (NULL == if_indextoname(ifa->ifa_index, name)) {
        syslog(LOG_ERR, "%s:%d:%s: if_indextoname: %s", __FILE__, __LINE__, __func__, strerror(errno));
        return -1;
    }
    if (NULL == inet_ntop(AF_INET6, in_addr, addr, INET_ADDRSTRLEN)) {
        syslog(LOG_ERR, "%s:%d:%s: inet_ntop: %s", __FILE__, __LINE__, __func__, strerror(errno));
        return -1;
    }

    syslog(LOG_INFO, "%s:%d:%s: interface %d (%s) just got addr %s",
            __FILE__, __LINE__, __func__, ifa->ifa_index, name, addr);

    return 0;
}


int lmdnsd_epoll_event_netlink_deladdr_ipv4 (
    struct lmdnsd_s * lmdnsd,
    struct epoll_event * event,
    struct lmdnsd_epollfd_s * lmdnsd_epollfd,
    const struct nlmsghdr * const nlmsghdr,
    const struct ifaddrmsg * const ifa,
    const uint32_t ifa_len,
    struct in_addr * in_addr
)
{
    char addr[INET_ADDRSTRLEN];
    char name[IFNAMSIZ];

    if (NULL == if_indextoname(ifa->ifa_index, name)) {
        syslog(LOG_ERR, "%s:%d:%s: if_indextoname: %s", __FILE__, __LINE__, __func__, strerror(errno));
        return -1;
    }
    if (NULL == inet_ntop(AF_INET6, in_addr, addr, INET_ADDRSTRLEN)) {
        syslog(LOG_ERR, "%s:%d:%s: inet_ntop: %s", __FILE__, __LINE__, __func__, strerror(errno));
        return -1;
    }

    syslog(LOG_INFO, "%s:%d:%s: interface %d (%s) just lost addr %s",
            __FILE__, __LINE__, __func__, ifa->ifa_index, name, addr);

    return 0;
}


int lmdnsd_epoll_event_netlink_newaddr (
    struct lmdnsd_s * lmdnsd,
    struct epoll_event * event,
    struct lmdnsd_epollfd_s * lmdnsd_epollfd,
    const struct nlmsghdr * const nlmsghdr,
    const struct ifaddrmsg * const ifa,
    uint32_t ifa_len
)
{
    int ret = 0;

    const struct rtattr * rtattr = IFA_RTA(ifa);
    if (!RTA_OK(rtattr, ifa_len)) {
        syslog(LOG_ERR, "%s:%d:%s: RTA_OK(rtattr, rtattr_len) returned false", __FILE__, __LINE__, __func__);
        return -1;
    }


    int i = 0;
    while (1) {

        // Dispatch on rta_type

        if (IFA_LOCAL == rtattr->rta_type) {
            syslog(LOG_INFO, "%s:%d:%s: local", __FILE__, __LINE__, __func__);
        }

        else if (IFA_ADDRESS == rtattr->rta_type && AF_INET6 == ifa->ifa_family) {
            ret = lmdnsd_epoll_event_netlink_newaddr_ipv6(
                /* lmdnsd = */ lmdnsd,
                /* epoll event = */ event,
                /* epollfd = */ lmdnsd_epollfd,
                /* nlmsghdr = */ nlmsghdr,
                /* ifaddrmsg = */ ifa,
                /* ifaddrmsg_len = */ ifa_len,
                /* in6_addr = */ RTA_DATA(rtattr)
            );
            if (-1 == ret) {
                syslog(LOG_ERR, "%s:%d:%s: lmdnsd_epoll_event_netlink_newaddr_ipv6 returned -1", __FILE__, __LINE__, __func__);
                return -1;
            }
        }

        else if (IFA_ADDRESS == rtattr->rta_type && AF_INET == ifa->ifa_family) {
            ret = lmdnsd_epoll_event_netlink_newaddr_ipv4(
                /* lmdnsd = */ lmdnsd,
                /* epoll event = */ event,
                /* epollfd = */ lmdnsd_epollfd,
                /* nlmsghdr = */ nlmsghdr,
                /* ifaddrmsg = */ ifa,
                /* ifaddrmsg_len = */ ifa_len,
                /* in6_addr = */ RTA_DATA(rtattr)
            );
            if (-1 == ret) {
                syslog(LOG_ERR, "%s:%d:%s: lmdnsd_epoll_event_netlink_newaddr_ipv6 returned -1", __FILE__, __LINE__, __func__);
                return -1;
            }
        }

        else if (IFA_LABEL == rtattr->rta_type) {
            syslog(LOG_INFO, "%s:%d:%s: label", __FILE__, __LINE__, __func__);
        }

        else if (IFA_BROADCAST == rtattr->rta_type) {
            syslog(LOG_INFO, "%s:%d:%s: broadcast addr", __FILE__, __LINE__, __func__);
        }

        else if (IFA_ANYCAST == rtattr->rta_type) {
            syslog(LOG_INFO, "%s:%d:%s: anycast addr", __FILE__, __LINE__, __func__);
        }


        // ok fetch the next rt attribute
        rtattr = RTA_NEXT(rtattr, ifa_len);
        if (!RTA_OK(rtattr, ifa_len)) {
            break;
        }

        if (1024 < ++i) {
            syslog(LOG_ERR, "%s:%d:%s: infinite loop", __FILE__, __LINE__, __func__);
            return -1;
        }
    }

    return 0;
}


int lmdnsd_epoll_event_netlink_deladdr (
    struct lmdnsd_s * lmdnsd,
    struct epoll_event * event,
    struct lmdnsd_epollfd_s * lmdnsd_epollfd,
    struct nlmsghdr * nlmsghdr,
    const struct ifaddrmsg * const ifa,
    uint32_t ifa_len
)
{
    int ret = 0;

    const struct rtattr * rtattr = IFA_RTA(ifa);
    if (!RTA_OK(rtattr, ifa_len)) {
        syslog(LOG_ERR, "%s:%d:%s: RTA_OK(rtattr, rtattr_len) returned false", __FILE__, __LINE__, __func__);
        return -1;
    }


    int i = 0;
    while (1) {

        if (IFA_LOCAL == rtattr->rta_type) {
            syslog(LOG_INFO, "%s:%d:%s: local", __FILE__, __LINE__, __func__);
        }

        else if (IFA_ADDRESS == rtattr->rta_type && AF_INET6 == ifa->ifa_family) {

            ret = lmdnsd_epoll_event_netlink_deladdr_ipv6(
                /* lmdnsd = */ lmdnsd,
                /* epoll event = */ event,
                /* epollfd = */ lmdnsd_epollfd,
                /* nlmsghdr = */ nlmsghdr,
                /* ifaddrmsg = */ ifa,
                /* ifaddrmsg_len = */ ifa_len,
                /* in6_addr = */ RTA_DATA(rtattr)
            );
            if (-1 == ret) {
                syslog(LOG_ERR, "%s:%d:%s: lmdnsd_epoll_event_netlink_deladdr_ipv6 returned -1", __FILE__, __LINE__, __func__);
                return -1;
            }
        }

        else if (IFA_ADDRESS == rtattr->rta_type && AF_INET == ifa->ifa_family) {
            ret = lmdnsd_epoll_event_netlink_deladdr_ipv4(
                /* lmdnsd = */ lmdnsd,
                /* epoll event = */ event,
                /* epollfd = */ lmdnsd_epollfd,
                /* nlmsghdr = */ nlmsghdr,
                /* ifaddrmsg = */ ifa,
                /* ifaddrmsg_len = */ ifa_len,
                /* in6_addr = */ RTA_DATA(rtattr)
            );
            if (-1 == ret) {
                syslog(LOG_ERR, "%s:%d:%s: lmdnsd_epoll_event_netlink_newaddr_ipv6 returned -1", __FILE__, __LINE__, __func__);
                return -1;
            }
        }

        else if (IFA_LABEL == rtattr->rta_type) {
            syslog(LOG_INFO, "%s:%d:%s: label", __FILE__, __LINE__, __func__);
        }

        else if (IFA_BROADCAST == rtattr->rta_type) {
            syslog(LOG_INFO, "%s:%d:%s: broadcast addr", __FILE__, __LINE__, __func__);
        }

        else if (IFA_ANYCAST == rtattr->rta_type) {
            syslog(LOG_INFO, "%s:%d:%s: anycast addr", __FILE__, __LINE__, __func__);
        }


        // ok fetch the next rt attribute
        rtattr = RTA_NEXT(rtattr, ifa_len);
        if (!RTA_OK(rtattr, ifa_len)) {
            break;
        }

        if (1024 < ++i) {
            syslog(LOG_ERR, "%s:%d:%s: infinite loop", __FILE__, __LINE__, __func__);
            return -1;
        }
    }

    return 0;
}


int lmdnsd_epoll_event_netlink (
    struct lmdnsd_s * lmdnsd,
    struct epoll_event * event,
    struct lmdnsd_epollfd_s * lmdnsd_epollfd
)
{
    int ret = 0;
    uint8_t buf[4096];
    int bytes_read = 0;
    struct nlmsghdr * nlmsghdr;


    bytes_read = read(lmdnsd_epollfd->fd, buf, sizeof(buf));
    if (-1 == bytes_read) {
        syslog(LOG_ERR, "%s:%d:%s: read: %s", __FILE__, __LINE__, __func__, strerror(errno));
        return -1;
    }
    if (0 == bytes_read) {
        syslog(LOG_ERR, "%s:%d:%s: read 0 bytes", __FILE__, __LINE__, __func__);
        return -1;
    }

    nlmsghdr = (struct nlmsghdr *)buf;
    if (!NLMSG_OK(nlmsghdr, bytes_read)) {
        syslog(LOG_ERR, "%s:%d:%s: NLMSG_OK(nlmsghdr) returned false", __FILE__, __LINE__, __func__);
        return -1;
    }


    int i = 0;
    while (1) {

        // dispatch on netlink message type
        switch (nlmsghdr->nlmsg_type) {
            case RTM_NEWLINK:
                ret = lmdnsd_epoll_event_netlink_newlink(
                    lmdnsd,
                    event,
                    lmdnsd_epollfd,
                    (struct ifinfomsg*)NLMSG_DATA(nlmsghdr),
                    NLMSG_PAYLOAD(nlmsghdr, sizeof(struct ifinfomsg))
                );
                if (-1 == ret) {
                    syslog(LOG_ERR, "%s:%d:%s: lmdnsd_epoll_event_netlink_newlink returned -1",
                            __FILE__, __LINE__, __func__);
                    return -1;
                }
                break;


            case RTM_DELLINK:
                ret = lmdnsd_epoll_event_netlink_dellink(
                    lmdnsd,
                    event,
                    lmdnsd_epollfd,
                    (struct ifinfomsg*)NLMSG_DATA(nlmsghdr),
                    NLMSG_PAYLOAD(nlmsghdr, sizeof(struct ifinfomsg))
                );
                if (-1 == ret) {
                    syslog(LOG_ERR, "%s:%d:%s: lmdnsd_epoll_event_netlink_dellink returned -1", __FILE__, __LINE__, __func__);
                    return -1;
                }
                break;

            case RTM_NEWADDR:
                ret = lmdnsd_epoll_event_netlink_newaddr(
                    /* lmdnsd = */ lmdnsd,
                    /* epoll event = */ event,
                    /* epoll data = */ lmdnsd_epollfd,
                    /* nlmsghdr = */ nlmsghdr,
                    /* ifaddrmsg = */ (const struct ifaddrmsg * const)NLMSG_DATA(nlmsghdr),
                    /* ifaddrmsg_len = */ NLMSG_PAYLOAD(nlmsghdr, sizeof(struct ifaddrmsg))
                );
                if (-1 == ret) {
                    syslog(LOG_ERR, "%s:%d:%s: lmdnsd_epoll_event_netlink_newaddr returned -1", __FILE__, __LINE__, __func__);
                    return -1;
                }
                break;

            case RTM_DELADDR:
                ret = lmdnsd_epoll_event_netlink_deladdr(
                    /* lmdnsd = */ lmdnsd,
                    /* epoll event = */ event,
                    /* epoll data = */ lmdnsd_epollfd,
                    /* nlmsghdr = */ nlmsghdr,
                    /* ifaddrmsg = */ (const struct ifaddrmsg * const)NLMSG_DATA(nlmsghdr),
                    /* ifaddrmsg_len = */ NLMSG_PAYLOAD(nlmsghdr, sizeof(struct ifaddrmsg))
                );
                if (-1 == ret) {
                    syslog(LOG_ERR, "%s:%d:%s: lmdnsd_epoll_event_netlink_deladdr returned -1", __FILE__, __LINE__, __func__);
                    return -1;
                }
                break;


            default:
                syslog(LOG_ERR, "%s:%d:%s: no match on netlink message type %d", __FILE__, __LINE__, __func__, nlmsghdr->nlmsg_type);
                return -1;
        }


        // get the next nlmsghdr packet
        nlmsghdr = NLMSG_NEXT(nlmsghdr, bytes_read);
        if (!NLMSG_OK(nlmsghdr, bytes_read)) {
            break;
        }
        if (NLMSG_DONE == nlmsghdr->nlmsg_type) {
            break;
        }
        if (NLMSG_ERROR == nlmsghdr->nlmsg_type) {
            syslog(LOG_ERR, "%s:%d:%s: NLMSG_ERROR == nlmsghdr->nlmsg_type", __FILE__, __LINE__, __func__);
            return -1;
        }

        // loop around, but check for infinite loops.
        if (1024 < ++i) {
            syslog(LOG_ERR, "%s:%d:%s: infinite loop", __FILE__, __LINE__, __func__);
            return -1;
        }
    }


    // Ok, we've read all messages from the netlink now; let's rearm the fd on epoll.
    ret = epoll_ctl(
        lmdnsd->epollfd,
        EPOLL_CTL_MOD,
        lmdnsd_epollfd->fd,
        &(struct epoll_event){
            .events = EPOLLIN | EPOLLONESHOT,
            .data = event->data
        }
    );
    if (-1 == ret) {
        syslog(LOG_ERR, "%s:%d:%s: epoll_ctl: %s", __FILE__, __LINE__, __func__, strerror(errno));
        return -1;
    }

    return 0;
}


static int lmdnsd_epoll_event_dispatch (
    struct lmdnsd_s * lmdnsd,
    struct epoll_event * event
)
{
    int ret = 0;
    struct lmdnsd_epollfd_s * lmdnsd_epollfd = event->data.ptr;
    if (LMDNSD_EPOLLFD_SENTINEL != lmdnsd_epollfd->sentinel) {
        syslog(LOG_ERR, "%s:%d:%s: sentinel is wrong", __FILE__, __LINE__, __func__);
        return -1;
    }

    if (LMDNSD_EPOLLFD_TYPE_LISTEN == lmdnsd_epollfd->type) {
        ret = lmdnsd_epoll_event_listen(lmdnsd, event, lmdnsd_epollfd);
        if (-1 == ret) {
            syslog(LOG_ERR, "%s:%d:%s: lmdnsd_epoll_event_listen returned -1", __FILE__, __LINE__, __func__);
            return -1;
        }

        return 0;
    }

    if (LMDNSD_EPOLLFD_TYPE_NETLINK == lmdnsd_epollfd->type) {
        ret = lmdnsd_epoll_event_netlink(lmdnsd, event, lmdnsd_epollfd);
        if (-1 == ret) {
            syslog(LOG_ERR, "%s:%d:%s: lmdnsd_epoll_event_netlink returned -1", __FILE__, __LINE__, __func__);
            return -1;
        }
        return 0;
    }

    syslog(LOG_ERR, "%s:%d:%s: No match on epoll event.", __FILE__, __LINE__, __func__);
    return -1;
}


static int lmdnsd_epoll_handle_events (
    struct lmdnsd_s * lmdnsd,
    struct epoll_event epoll_events[EPOLL_NUM_EVENTS],
    int ep_events_len
)
{
    int ret = 0;
    for (int i = 0; i < ep_events_len; i++) {
        ret = lmdnsd_epoll_event_dispatch(lmdnsd, &epoll_events[i]);
        if (0 != ret) {
            return ret;
        }
    }
    return 0;
}


int lmdnsd_loop (
    struct lmdnsd_s * lmdnsd
)
{

    int ret = 0;

    if (LMDNSD_SENTINEL != lmdnsd->sentinel) {
        syslog(LOG_ERR, "%s:%d:%s: sentinel is wrong", __FILE__, __LINE__, __func__);
        return -1;
    }

    int ep_events_len = 0;
    struct epoll_event ep_events[EPOLL_NUM_EVENTS];
    while (1) {
        ep_events_len = epoll_wait(lmdnsd->epollfd, ep_events, EPOLL_NUM_EVENTS, -1);
        if (-1 == ret && EINTR == errno) {
            continue;
        }
        if (-1 == ep_events_len) {
            syslog(LOG_ERR, "%s:%d:%s: epoll_wait returned -1", __FILE__, __LINE__, __func__);
            return -1;
        }

        ret = lmdnsd_epoll_handle_events(lmdnsd, ep_events, ep_events_len);
        if (-1 == ret) {
            syslog(LOG_ERR, "%s:%d:%s: lmdnsd_epoll_handle_events returned -1", __FILE__, __LINE__, __func__);
            return -1;
        }
    }

    return 0;
}


int lmdnsd_listen (
    struct lmdnsd_s * lmdnsd
)
{

    int ret = 0;
    int sockfd = 0;
    struct addrinfo *servinfo, *p;

    if (NULL == lmdnsd) {
        syslog(LOG_ERR, "%s:%d:%s: lmdnsd is NULL", __FILE__, __LINE__, __func__);
        return -1;
    }
    if (LMDNSD_SENTINEL != lmdnsd->sentinel) {
        syslog(LOG_ERR, "%s:%d:%s: sentinel is wrong", __FILE__, __LINE__, __func__);
        return -1;
    }


    ret = getaddrinfo(
        /* host = */ NULL, 
        /* port = */ "5353",
        /* hints = */ &(struct addrinfo) {
            .ai_family = AF_UNSPEC,
            .ai_socktype = SOCK_DGRAM,
            .ai_flags = AI_PASSIVE
        },
        /* servinfo = */ &servinfo
    );
    if (-1 == ret) {
        syslog(LOG_WARNING, "%s:%d:%s: getaddrinfo: %s", __FILE__, __LINE__, __func__, gai_strerror(ret));
        return -1;
    }
    if (NULL == servinfo) {
        syslog(LOG_WARNING, "%s:%d:%s: no results from getaddrinfo", __FILE__, __LINE__, __func__);
        return -1;
    }


    for (p = servinfo; p != NULL; p = p->ai_next) {
        sockfd = socket(
            p->ai_family,
            p->ai_socktype,
            p->ai_protocol
        );
        if (-1 == sockfd) {
            syslog(LOG_WARNING, "%s:%d:%s: socket: %s", __FILE__, __LINE__, __func__, strerror(errno));
            return -1;
        }

        ret = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));
        if (-1 == ret) {
            syslog(LOG_ERR, "%s:%d:%s: setsockopt: %s", __FILE__, __LINE__, __func__, strerror(errno));
            return -1;
        }

        ret = setsockopt(sockfd, IPPROTO_IP, IP_PKTINFO, &(int){1}, sizeof(int));
        if (-1 == ret) {
            syslog(LOG_ERR, "%s:%d:%s: setsockopt: %s", __FILE__, __LINE__, __func__, strerror(errno));
            return -1;
        }

        ret = bind(sockfd, p->ai_addr, p->ai_addrlen);
        if (-1 == ret) {
            close(sockfd);
            syslog(LOG_WARNING, "%s:%d:%s: bind: %s", __FILE__, __LINE__, __func__, strerror(errno));
            continue;
        }

        lmdnsd->epollfds[sockfd] = (struct lmdnsd_epollfd_s) {
            .sentinel = LMDNSD_EPOLLFD_SENTINEL,
            .type = LMDNSD_EPOLLFD_TYPE_LISTEN,
            .fd = sockfd
        };

        ret = epoll_ctl(
            lmdnsd->epollfd,
            EPOLL_CTL_ADD,
            sockfd,
            &(struct epoll_event){
                .events = EPOLLIN | EPOLLONESHOT,
                .data = {
                    .ptr = &lmdnsd->epollfds[sockfd]
                }
            }
        );
        if (-1 == ret) {
            syslog(LOG_ERR, "%s:%d:%s: epoll_ctl: %s", __FILE__, __LINE__, __func__, strerror(errno));
            return -1;
        }
        
        
        if (AF_INET == p->ai_family) {
            printf("%s:%d:%s: ipv4 socket bound\n", __FILE__, __LINE__, __func__);
        }
        else if (AF_INET6 == p->ai_family) {
            printf("%s:%d:%s: ipv6 socket bound\n", __FILE__, __LINE__, __func__);
        }
        else {
            printf("%s:%d:%s: unknown ai_family %d bound\n", __FILE__, __LINE__, __func__, p->ai_family);
        }
        
    }


    freeaddrinfo(servinfo);
    

    return 0;
}


int lmdnsd_start_netlink (
    struct lmdnsd_s * lmdnsd
)
{

    int ret = 0;
    int fd = 0;


    // Open a netlink socket to receive link, ip address event notifications
    fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (-1 == fd) {
        syslog(LOG_ERR, "%s:%d:%s: socket: %s", __FILE__, __LINE__, __func__, strerror(errno));
        return -1;
    }

    // bind source address to socket
    struct sockaddr_nl sa = {
        .nl_family = AF_NETLINK,
        .nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR
    };

    ret = bind(fd, (struct sockaddr *)&sa, sizeof(sa));
    if (-1 == ret) {
        syslog(LOG_ERR, "%s:%d:%s: bind: %s", __FILE__, __LINE__, __func__, strerror(errno));
        return -1;
    }

    lmdnsd->epollfds[fd] = (struct lmdnsd_epollfd_s) {
        .sentinel = LMDNSD_EPOLLFD_SENTINEL,
        .type = LMDNSD_EPOLLFD_TYPE_NETLINK,
        .fd = fd
    };

    // add it to epoll
    ret = epoll_ctl(
        lmdnsd->epollfd,
        EPOLL_CTL_ADD,
        fd,
        &(struct epoll_event){
            .events = EPOLLIN | EPOLLONESHOT,
            .data = {
                .ptr = &lmdnsd->epollfds[fd]
            }
        }
    );
    if (-1 == ret) {
        syslog(LOG_ERR, "%s:%d:%s: epoll_ctl: %s", __FILE__, __LINE__, __func__, strerror(errno));
        return -1;
    }

    return 0;
}


int lmdnsd_init (
    struct lmdnsd_s * lmdnsd
)
{

    int ret = 0;

    // Create the epoll instance
    lmdnsd->epollfd = epoll_create1(EPOLL_CLOEXEC);
    if (-1 == lmdnsd->epollfd) {
        syslog(LOG_ERR, "%s:%d:%s: epoll_create1: %s", __FILE__, __LINE__, __func__, strerror(errno));
        return -1;
    }

    lmdnsd->sentinel = LMDNSD_SENTINEL;

    return 0;
}


int main (
    int argc,
    char const* argv[]
)
{
    int ret = 0;
    struct lmdnsd_s lmdnsd = {0};

    openlog("lmdnsd", LOG_CONS | LOG_PID, LOG_USER);

    ret = lmdnsd_init(&lmdnsd);
    if (-1 == ret) {
        syslog(LOG_ERR, "%s:%d:%s: lmdnsd_init returned -1", __FILE__, __LINE__, __func__);
        return -1;
    }

    ret = lmdnsd_listen(&lmdnsd);
    if (-1 == ret) {
        syslog(LOG_ERR, "%s:%d:%s: lmdnsd_listen returned -1", __FILE__, __LINE__, __func__);
        return -1;
    }

    ret = lmdnsd_start_netlink(&lmdnsd);
    if (-1 == ret) {
        syslog(LOG_ERR, "%s:%d:%s: lmdnsd_start_netlink returned -1", __FILE__, __LINE__, __func__);
        return -1;
    }

//    ret = lmdnsd_send_packet(&lmdnsd);
//    if (-1 == ret) {
//        syslog(LOG_ERR, "%s:%d:%s: lmdnsd_send_packet", __FILE__, __LINE__, __func__);
//        return -1;
//    }

    ret = lmdnsd_loop(&lmdnsd);
    if (-1 == ret) {
        syslog(LOG_ERR, "%s:%d:%s: lmdnsd_loop returned -1", __FILE__, __LINE__, __func__);
        return -1;
    }

    return 0;
    (void)argc;
    (void)argv;
}
