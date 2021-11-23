#pragma once

#define EPOLL_NUM_EVENTS 8

#define LMDNSD_SENTINEL 8081
#define LMDNSD_EPOLLFD_SENTINEL 8082

struct lmdnsd_epollfd_s {
    int sentinel;
    enum lmdnsd_epollfd_type_s {
        LMDNSD_EPOLLFD_TYPE_LISTEN = 0
    } type;
    int fd;
};

struct lmdnsd_s {
    int sentinel;
    int epollfd;
    struct lmdnsd_epollfd_s epollfds[128];
};
