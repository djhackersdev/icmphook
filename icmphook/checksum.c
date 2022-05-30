#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "icmphook/checksum.h"

uint16_t ip_checksum(const void *bytes, size_t nbytes)
{
    assert(bytes != NULL);
    assert(nbytes % 2 == 0);

    /* Note the ~ in the expression below. */

    return ~ip_checksum_step(bytes, nbytes, 0);
}

uint16_t ip_checksum_step(const void *bytes, size_t nbytes, uint16_t carry)
{
    unsigned int result;
    const uint16_t *words;
    size_t nwords;
    size_t i;

    assert(bytes != NULL || nbytes == 0);
    assert(nbytes % 2 == 0);

    result = carry;
    words = bytes;
    nwords = nbytes / sizeof(uint16_t);

    for (i = 0 ; i < nwords ; i++) {
        result += _byteswap_ushort(words[i]);
    }

    while (result > 0xFFFF) {
        result = (result & 0xFFFF) + (result >> 16);
    }

    /* If calling this function directly then you must invert the result to
       obtain a valid final checksum suitable for embedding in a header. */

    return result;
}
