#pragma once

#include <windows.h>

#include <stddef.h>
#include <stdint.h>

#include "iohook/iobuf.h"

enum {
    ICMP_TYPE_ECHO_REPLY = 0,
    ICMP_TYPE_ECHO_REQUEST = 8,
    ICMP_TYPE_TIME_EXCEEDED = 11,
};

enum {
    ICMP_CODE_TTL_EXPIRED = 0,
};

struct icmp_header {
    uint8_t type;
    uint8_t code;
};

HRESULT icmp_decode(struct const_iobuf *src, struct icmp_header *header);
HRESULT icmp_encode(
        struct iobuf *dest,
        const struct icmp_header *header,
        const void *payload,
        size_t nbytes);
