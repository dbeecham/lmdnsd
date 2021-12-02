#pragma once

#include <stdint.h>
#include <stdbool.h>

struct lmdnsd_packet_s {
    uint16_t id;
    struct {
        bool is_query;
        enum {

            // standard query
            LMDNSD_PACKET_OPCODE_QUERY,

            // inverse query
            LMDNSD_PACKET_OPCODE_IQUERY,

            // server status request
            LMDNSD_PACKET_OPCODE_STATUS
        } opcode;
        bool authoritative_answer;
        bool truncated;
        bool recursion_desired;
        bool recursion_available;

        // response error codes
        enum {

            // no error
            LMDNSD_PACKET_RCODE_OK,

            // name server was unanable to interpret the query
            LMDNSD_PACKET_RCODE_FORMAT_ERROR,

            // unable to process query due to internal server error
            LMDNSD_PACKET_RCODE_SERVER_FAILURE,

            // meaningful only for responses from authoritative name server,
            // means the referenced name does not exist
            LMDNSD_PACKET_RCODE_NAME_ERROR,

            // name server does not support this query
            LMDNSD_PACKET_RCODE_NOT_IMPLEMENTED,

            // name server refuses to do this
            LMDNSD_PACKET_RCODE_REFUSED
        } rcode;
    } flags;
    uint16_t flags_raw;

    uint16_t questions_len;
    struct {
        uint8_t name[512];
        uint16_t type;
        uint16_t qclass;
    } questions[32];

    uint16_t answers_len;
    struct {
        uint8_t name[512];
        uint16_t type;
        uint16_t aclass;
        uint32_t ttl;
        uint16_t data_len;
        uint8_t data[512];
    } answers[32];

    uint16_t ns_len;
    uint16_t ar_len;
};
