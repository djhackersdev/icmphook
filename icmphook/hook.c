#include <windows.h>
#include <winsock2.h>

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>

#include "icmphook/dprintf.h"
#include "icmphook/dump.h"
#include "icmphook/hook.h"
#include "icmphook/icmp.h"
#include "icmphook/peer.h"

#include "iohook/iobuf.h"
#include "iohook/iohook.h"

static HRESULT hook_handle_irp(struct irp *irp);
static HRESULT hook_handle_socket(struct irp *irp);
static HRESULT hook_handle_closesocket(struct irp *irp);
static HRESULT hook_handle_bind(struct irp *irp);
static HRESULT hook_handle_ioctlsocket(struct irp *irp);
static HRESULT hook_handle_setsockopt(struct irp *irp);
static HRESULT hook_handle_recvfrom(struct irp *irp);
static HRESULT hook_handle_sendto(struct irp *irp);

static HANDLE hook_fd;

HRESULT hook_init(void)
{
    HRESULT hr;

    peer_init();
    hr = iohook_open_nul_fd(&hook_fd);

    if (FAILED(hr)) {
        return hr;
    }

    return iohook_push_handler(hook_handle_irp);
}

static HRESULT hook_handle_irp(struct irp *irp)
{
    assert(irp != NULL);

    if (irp->op != IRP_OP_SOCKET && irp->fd != hook_fd) {
        return iohook_invoke_next(irp);
    }

    switch (irp->op) {
    case IRP_OP_SOCKET:         return hook_handle_socket(irp);
    case IRP_OP_CLOSESOCKET:    return hook_handle_closesocket(irp);
    case IRP_OP_BIND:           return hook_handle_bind(irp);
    case IRP_OP_IOCTLSOCKET:    return hook_handle_ioctlsocket(irp);
    case IRP_OP_SETSOCKOPT:     return hook_handle_setsockopt(irp);
    case IRP_OP_RECVFROM:       return hook_handle_recvfrom(irp);
    case IRP_OP_SENDTO:         return hook_handle_sendto(irp);
    default:
        dprintf("Unhandled IRP op: %i\n", irp->op);

        return HRESULT_FROM_WIN32(ERROR_INVALID_FUNCTION);
    }
}

static HRESULT hook_handle_socket(struct irp *irp)
{
    assert(irp != NULL);

    if (irp->sock_af != AF_INET || irp->sock_type != SOCK_RAW) {
        return iohook_invoke_next(irp);
    }

    if (irp->sock_protocol != IPPROTO_ICMP) {
        dprintf("Attempted to open non-ICMP packet socket\n");

        return E_NOTIMPL;
    }

    dprintf("%s\n", __func__);
    irp->fd = hook_fd;

    return S_OK;
}

static HRESULT hook_handle_closesocket(struct irp *irp)
{
    assert(irp != NULL);

    dprintf("%s\n", __func__);

    return S_OK;
}

static HRESULT hook_handle_bind(struct irp *irp)
{
    const struct sockaddr_in *addr_obj;
    uint32_t addr;

    assert(irp != NULL);

    dprintf("%s\n", __func__);

    if (irp->addr_out_len != sizeof(*addr_obj)) {
        dprintf("Invalid addr len\n");

        return E_INVALIDARG;
    }

    addr_obj = (const struct sockaddr_in *) irp->addr_out;

    if (addr_obj->sin_family != AF_INET) {
        dprintf("Invalid addr family\n");

        return E_INVALIDARG;
    }

    addr = _byteswap_ulong(addr_obj->sin_addr.s_addr);
    dprintf("Bind to addr %08x\n", addr);

    return S_OK;
}

static HRESULT hook_handle_ioctlsocket(struct irp *irp)
{
    assert(irp != NULL);

    dprintf("%s(%x)\n", __func__, irp->sock_ioctl);

    switch (irp->sock_ioctl) {
    case FIONBIO:
        if (irp->sock_ioctl_param == NULL) {
            return E_INVALIDARG;
        }

        dprintf("Set nonblocking param: %i\n", (int) *irp->sock_ioctl_param);

        return S_OK;

    default:
        dprintf("Unsupported socket ioctl\n");

        return E_NOTIMPL;
    }
}

static HRESULT hook_handle_setsockopt(struct irp *irp)
{
    uint32_t param;
    HRESULT hr;

    assert(irp != NULL);

    dprintf("%s(%i, %i)\n", __func__, irp->sockopt_level, irp->sockopt_name);

    switch (irp->sockopt_level) {
    case SOL_SOCKET:
        switch(irp->sockopt_name) {
        case SO_SNDTIMEO:
            hr = iobuf_read_le32(&irp->write, &param);

            if (FAILED(hr)) {
                return hr;
            }

            dprintf("Set send timeout: %i ms\n", (int) param);

            return S_OK;

        case SO_RCVTIMEO:
            hr = iobuf_read_le32(&irp->write, &param);

            if (FAILED(hr)) {
                return hr;
            }

            dprintf("Set recv timeout: %i ms\n", (int) param);
            sock->rx_timeout_ms = param;

            return S_OK;

        default:
            dprintf("Unsupported SOL_SOCKET option\n");

            return E_NOTIMPL;
        }

    default:
        dprintf("Unsupported socket param level\n");

        return E_NOTIMPL;
    }
}

static HRESULT hook_handle_sendto(struct irp *irp)
{
    const struct sockaddr_in *addr_obj;
    struct icmp_header icmp;
    uint32_t addr;
    HRESULT hr;

    assert(irp != NULL);

    if (irp->addr_out == NULL) {
        dprintf("%s: No destination addr\n", __func__);

        return E_INVALIDARG;
    }

    if (irp->addr_out_len != sizeof(*addr_obj)) {
        dprintf("%s: addr size %i != %i\n",
                __func__,
                irp->addr_out_len,
                sizeof(*addr_obj));

        return E_INVALIDARG;
    }

    addr_obj = (const struct sockaddr_in *) irp->addr_out;

    if (addr_obj->sin_family != AF_INET) {
        dprintf("%s: addr family %i != AF_INET\n",
                __func__,
                addr_obj->sin_family);

        return E_INVALIDARG;
    }

    addr = _byteswap_ulong(addr_obj->sin_addr.s_addr);

#if 1
    dprintf("sendto(%08x):\n", addr);
    dump_const_iobuf(&irp->write);
#endif

    /* Unconditionally swallow the entire packet from here on */

    hr = icmp_decode(&irp->write, &icmp);
    irp->write.pos = irp->write.nbytes;

    if (FAILED(hr)) {
        dprintf("%s: icmp_decode failed: %x\n", __func__, (int) hr);

        return S_OK;
    }

    peer_send(addr, &icmp, &irp->write);

    return S_OK;
}

static HRESULT hook_handle_recvfrom(struct irp *irp)
{
    struct icmp_header icmp;
    uint8_t tmp_bytes[0xffff];
    struct iobuf tmp_iobuf;
    struct sockaddr_in *addr_obj;
    uint32_t addr;
    bool recved;
    HRESULT hr;

    assert(irp != NULL);

    if (irp->addr_in != NULL) {
        assert(irp->addr_in_len != NULL);

        if (*irp->addr_in_len != sizeof(*addr_obj)) {
            dprintf("%s: addr size %i != %i\n",
                    __func__,
                    *irp->addr_in_len,
                    sizeof(*addr_obj));

            return E_INVALIDARG;
        }

        addr_obj = (struct sockaddr_in *) irp->addr_in;
    } else {
        addr_obj = NULL;
    }

    tmp_iobuf.bytes = tmp_bytes;
    tmp_iobuf.nbytes = sizeof(tmp_bytes);
    tmp_iobuf.pos = 0;

    recved = peer_recv(&addr, &icmp, &tmp_iobuf);

    if (!recved) {
        dprintf("%s: No packet\n", __func__);

        return HRESULT_FROM_WIN32(WSAETIMEDOUT);
    }

    hr = icmp_encode(&irp->read, &icmp, tmp_iobuf.bytes, tmp_iobuf.pos);

    if (FAILED(hr)) {
        return hr;
    }

    if (addr_obj != NULL) {
        addr_obj->sin_family = AF_INET;
        addr_obj->sin_port = 0;
        addr_obj->sin_addr.s_addr = _byteswap_ulong(addr);
    }

    dprintf("%s: From %08x\n", __func__, addr);
    dump_iobuf(&irp->read);

    return S_OK;
}
