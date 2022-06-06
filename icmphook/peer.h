#pragma once

#include <windows.h>

#include <stdbool.h>
#include <stdint.h>

#include "icmphook/icmp.h"

void peer_init(void);

void peer_send(
        uint32_t addr,
        const struct icmp_header *icmp,
        struct const_iobuf *payload);

bool peer_recv(
        uint32_t *addr,
        struct icmp_header *icmp,
        struct iobuf *payload);
