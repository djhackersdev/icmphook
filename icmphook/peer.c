#include <windows.h>
#include <winsock2.h>

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>

#include "icmphook/dprintf.h"
#include "icmphook/icmp.h"

#include "iohook/iobuf.h"

static bool peer_handle_ping(struct const_iobuf *payload, struct iobuf *res);

bool peer_transact(struct const_iobuf *req, struct iobuf *res)
{
    struct icmp_header icmp;
    HRESULT hr;

    assert(req != NULL);
    assert(res != NULL);

    hr = icmp_decode(req, &icmp);

    if (FAILED(hr)) {
        dprintf("%s: icmp_decode failed: %x\n", __func__, (int) hr);

        return false;
    }

    switch (icmp.type) {
    case 8:
        switch (icmp.code) {
        case 0:
            return peer_handle_ping(req, res);

        default:
            dprintf("%s: Unsupported ping code: %i\n", __func__, icmp.code);

            return false;
        }

    default:
        dprintf("%s: Unsupported ICMP type: %i\n", __func__, icmp.type);

        return false;
    }
}

static bool peer_handle_ping(struct const_iobuf *payload, struct iobuf *res)
{
    struct icmp_header icmp;
    HRESULT hr;

    assert(payload != NULL);
    assert(res != NULL);

    icmp.type = 0;
    icmp.code = 0;

    hr = icmp_encode(
            res,
            &icmp,
            &payload->bytes[payload->pos],
            payload->nbytes - payload->pos);

    if (FAILED(hr)) {
        dprintf("%s: icmp_encode failed: %x\n", __func__, (int) hr);

        return false;
    }

    payload->pos = payload->nbytes;

    return true;
}
