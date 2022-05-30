#pragma once

#include <windows.h>

#include <stdint.h>

#include "iohook/iobuf.h"

enum {
    IP_PROTO_ICMP = 1,
};

/* (Supported fields of) an exploded IPv4 header */
struct ip4_header {
    uint16_t payload_size; /* Automatically converted to total size */
    uint8_t ttl;
    uint8_t protocol;
    uint32_t src;
    uint32_t dest;
};

HRESULT ip4_decode(struct const_iobuf *src, struct ip4_header *header);
HRESULT ip4_encode(struct iobuf *dest, const struct ip4_header *header);
