#define _DEFAULT_SOURCE

#include <stdio.h>
#include <syslog.h>
#include <arpa/inet.h>

#include "lmdnsd.h"
#include "lmdnsd_mdns_parser.h"
#include "lmdnsd_packet.h"

%%{

    machine mdns;

    access parser->;


    action id0_copy {
        parser->nid[0] = *(uint8_t*)p;
    }
    action id1_copy {
        parser->nid[1] = *(uint8_t*)p;
        parser->packet.id = ntohs(parser->id);
    }
    id = any @id0_copy any @id1_copy;


    action flags_init {
        parser->flags = 0;
    }
    action flags_copy {
        parser->flags <<= 8;
        parser->flags |= *(uint8_t*)p;
    }
    action flags_fin {
        parser->packet.flags_raw = parser->flags;
    }
    flags = any{2} >(flags_init) $flags_copy @flags_fin;


    action qdcount0_copy {
        parser->nqdcount[0] = *(uint8_t*)p;
    }
    action qdcount1_copy {
        parser->nqdcount[1] = *(uint8_t*)p;
        parser->packet.questions_len = ntohs(parser->qdcount);
    }
    qdcount = any @qdcount0_copy any @qdcount1_copy;


    action ancount_init {
        parser->ancount = 0;
    }
    action ancount_copy {
        parser->ancount <<= 8;
        parser->ancount |= *(uint8_t*)p;
    }
    action ancount_fin {
        parser->packet.answers_len = parser->ancount;
    }
    ancount = any{2} >(ancount_init) $ancount_copy @ancount_fin;



    action nscount_init {
        parser->nscount = 0;
    }
    action nscount_copy {
        parser->nscount <<= 8;
        parser->nscount |= *(uint8_t*)p;
    }
    action nscount_fin {
        parser->packet.ns_len = parser->nscount;
    }
    nscount = any{2} >(nscount_init) $nscount_copy @nscount_fin;


    action arcount_init {
        parser->arcount = 0;
    }
    action arcount_copy {
        parser->arcount <<= 8;
        parser->arcount |= *(uint8_t*)p;
    }
    action arcount_fin {
        parser->packet.ar_len = parser->arcount;
    }
    arcount = any{2} >(arcount_init) $arcount_copy @arcount_fin;


    header = (
        id
        flags
        qdcount
        ancount
        nscount
        arcount
    ) @{ 
        ret = parser->packet_cb(&parser->packet, parser->user_data);
        if (-1 == ret) {
            return -1;
        }
    }
    any*;


    main := (
        header
    ) $err{ 
        syslog(LOG_ERR, "%s:%d:%s: parse failed at 0x%02x (index %ld)", __FILE__, __LINE__, __func__, fc, (const uint8_t*)fpc - buf); 
        return -1;
    };

    write data;

}%%


int lmdnsd_mdns_parser_parse (
    struct lmdnsd_mdns_parser_s * parser,
    const uint8_t * const buf,
    const uint32_t buf_len
)
{
    int ret = 0;
    const char * p = (const char *)buf;
    const char * pe = (const char *)(buf + buf_len);
    const char * eof = 0;

    %% write exec;

    if (%%{ write error; }%% == parser->cs) {
        return -1;
    }
    return 0;
}


int lmdnsd_mdns_parser_init (
    struct lmdnsd_mdns_parser_s * parser,
    int (*packet_cb)(
        const struct lmdnsd_packet_s * const packet,
        void * user_data
    ),
    void * user_data
)
{

    parser->sentinel = LMDNSD_MDNS_PARSER_SENTINEL;
    parser->packet_cb = packet_cb;
    parser->user_data = user_data;

    %% write init;

    return 0;
}
