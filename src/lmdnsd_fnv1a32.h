#pragma once

#include <stdint.h>


uint32_t lmdnsd_fnv1a32_init (
    void
);


uint32_t lmdnsd_fnv1a32_hash_step (
    uint32_t hash,
    uint32_t byte
);


uint32_t fnv1a32_hash (
    const uint8_t * const buf,
    const uint32_t buf_len
);
