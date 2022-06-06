#include <windows.h>
#include <winsock2.h>

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>

#include "icmphook/dprintf.h"
#include "icmphook/icmp.h"

#include "iohook/iobuf.h"

static void peer_handle_ping(struct const_iobuf *payload);

static uint8_t peer_ping_buf[0xffff];
static struct iobuf peer_ping_iobuf;

void peer_init(void)
{
    peer_ping_iobuf.bytes = peer_ping_buf;
    peer_ping_iobuf.nbytes = sizeof(peer_ping_buf);
    peer_ping_iobuf.pos = 0;
}

void peer_send(
        uint32_t addr,
        const struct icmp_header *icmp,
        struct const_iobuf *payload)
{
    assert(icmp != NULL);
    assert(payload != NULL);

    if (addr != 0x7f000001) {
        dprintf("%s: Destination is not loopback, blackhole it\n", __func__);

        return;
    }

    switch (icmp->type) {
    case 8:
        switch (icmp->code) {
        case 0:
            peer_handle_ping(payload);

            break;

        default:
            dprintf("%s: Unsupported ping code: %i\n", __func__, icmp->code);
        }

        break;

    default:
        dprintf("%s: Unsupported ICMP type: %i\n", __func__, icmp->type);

        break;
    }
}

static void peer_handle_ping(struct const_iobuf *payload)
{
    assert(payload != NULL);

    if (peer_ping_iobuf.pos != 0) {
        dprintf("%s: A ping response is already queued\n", __func__);

        return;
    }

    iobuf_move(&peer_ping_iobuf, payload);
}

bool peer_recv(
        uint32_t *addr,
        struct icmp_header *icmp,
        struct iobuf *payload)
{
    assert(addr != NULL);
    assert(icmp != NULL);
    assert(payload != NULL);

    if (peer_ping_iobuf.pos == 0) {
        return false;
    }

    *addr = 0x7f000001; /* 127.0.0.1 */
    icmp->type = 0; /* Echo reply */
    icmp->code = 0;

    iobuf_shift(payload, &peer_ping_iobuf);

    return true;
}