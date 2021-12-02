#pragma once

#include <stdint.h>
#include <stdbool.h>

#define EPOLL_NUM_EVENTS 8

#define LMDNSD_SENTINEL 8081
#define LMDNSD_EPOLLFD_SENTINEL 8082
#define LMDNSD_EPOLLFDS_LEN (1<<7)

struct lmdnsd_epollfd_s {
    int sentinel;
    enum lmdnsd_epollfd_type_s {
        LMDNSD_EPOLLFD_TYPE_LISTEN,
        LMDNSD_EPOLLFD_TYPE_NETLINK
    } type;
    int fd;
};

struct lmdnsd_s {
    int sentinel;
    int epollfd;
    struct lmdnsd_epollfd_s epollfds[LMDNSD_EPOLLFDS_LEN];
};
