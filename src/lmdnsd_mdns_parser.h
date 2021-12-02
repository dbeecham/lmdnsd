#pragma once

#include <stdint.h>

#include "lmdnsd_packet.h"

#define LMDNSD_MDNS_PARSER_SENTINEL 8081

struct lmdnsd_mdns_parser_s {
    int sentinel;
    int cs;

    int (*packet_cb)(
        const struct lmdnsd_packet_s * const packet,
        void * user_data
    );
    void * user_data;

    struct lmdnsd_packet_s packet;

    union {
        uint16_t id;
        uint8_t nid[2];
    };

    uint16_t flags;

    union {
        uint16_t qdcount;
        uint8_t nqdcount[2];
    };

    uint16_t qd_i;
    uint16_t ancount;
    uint16_t an_i;
    uint16_t nscount;
    uint16_t ns_i;
    uint16_t arcount;
    uint16_t ar_i;
};

int lmdnsd_mdns_parser_init (
    struct lmdnsd_mdns_parser_s * parser,
    int (*packet_cb)(
        const struct lmdnsd_packet_s * const packet,
        void * user_data
    ),
    void * user_data
);

int lmdnsd_mdns_parser_parse (
    struct lmdnsd_mdns_parser_s * parser,
    const uint8_t * const buf,
    const uint32_t buf_len
);
