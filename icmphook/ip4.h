#pragma once

#include <windows.h>

#include <stddef.h>
#include <stdint.h>

#include "iohook/iobuf.h"

struct ip4_header {
    uint8_t dscp;
    uint8_t ecn;
    uint16_t identification;
    uint8_t flags;
    uint16_t fragment_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint32_t src;
    uint32_t dest;
};

HRESULT ip4_encode(
        struct iobuf *dest,
        const struct ip4_header *header,
        const void *options,
        size_t options_nbytes,
        const void *payload,
        size_t payload_nbytes
);
