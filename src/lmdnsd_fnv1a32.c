#include <stdint.h>

#include "lmdnsd_fnv1a32.h"

uint32_t lmdnsd_fnv1a32_init (
    void
)
{
    return 2166136261;
}


uint32_t lmdnsd_fnv1a32_hash_step (
    uint32_t hash,
    uint32_t byte
)
{
    hash ^= byte;
    return hash * 16777619;
}

static uint32_t fnv1a32_hash0 (
    const uint32_t hash,
    const uint8_t * const buf,
    const uint_fast32_t buf_len
)
{
    if (0 == buf_len) {
        return hash;
    }

    return fnv1a32_hash0(fnv1a32_hash_step(hash, buf[0]), buf + 1, buf_len - 1);
}

uint32_t fnv1a32_hash (
    const uint8_t * const buf,
    const uint32_t buf_len
)
{
    return fnv1a32_hash0(fnv1a32_init(), buf, buf_len);
}
