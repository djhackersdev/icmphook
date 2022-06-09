#include <windows.h>
#include <winsock2.h>

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "icmphook/dprintf.h"
#include "icmphook/dump.h"
#include "icmphook/hook.h"
#include "icmphook/icmp.h"
#include "icmphook/peer.h"

#include "iohook/iobuf.h"
#include "iohook/iohook.h"

struct hook_socket {
    struct hook_socket *next;
    HANDLE fd;
    CONDITION_VARIABLE cond;
    uint32_t tx_timeout_ms;
    uint32_t rx_timeout_ms;
    struct const_iobuf recv;
    uint8_t bytes[0xffff];
};

static struct hook_socket *hook_find_socket(HANDLE fd);
static void hook_distribute_response(const void *bytes, size_t nbytes);
static HRESULT hook_handle_irp(struct irp *irp);
static HRESULT hook_handle_irp_locked(
        struct irp *irp,
        struct hook_socket *sock);
static HRESULT hook_handle_socket(struct irp *irp);
static HRESULT hook_handle_closesocket(
        struct irp *irp,
        struct hook_socket *sock);
static HRESULT hook_handle_bind(struct irp *irp, struct hook_socket *sock);
static HRESULT hook_handle_ioctlsocket(
        struct irp *irp,
        struct hook_socket *sock);
static HRESULT hook_handle_setsockopt(
        struct irp *irp,
        struct hook_socket *sock);
static HRESULT hook_handle_recvfrom(struct irp *irp, struct hook_socket *sock);
static HRESULT hook_handle_sendto(struct irp *irp, struct hook_socket *sock);

static CRITICAL_SECTION hook_lock;
static struct hook_socket *hook_sockets;
static uint8_t hook_tmp_bytes[0xffff];

HRESULT hook_init(void)
{
    InitializeCriticalSection(&hook_lock);

    return iohook_push_handler(hook_handle_irp);
}

static struct hook_socket *hook_find_socket(HANDLE fd)
{
    struct hook_socket *sock;

    for (sock = hook_sockets ; sock != NULL ; sock = sock->next) {
        if (sock->fd == fd) {
            return sock;
        }
    }

    return NULL;
}

static void hook_distribute_response(const void *bytes, size_t nbytes)
{
    struct iobuf tmp_iobuf;
    struct hook_socket *sock;

    assert(bytes != NULL);

    for (sock = hook_sockets ; sock != NULL ; sock = sock->next) {
        if (sock->recv.pos == 0) {
            tmp_iobuf.bytes = sock->bytes;
            tmp_iobuf.nbytes = sizeof(sock->bytes);
            tmp_iobuf.pos = 0;

            iobuf_write(&tmp_iobuf, bytes, nbytes);
            iobuf_flip(&sock->recv, &tmp_iobuf);

            WakeAllConditionVariable(&sock->cond);
        } else {
            dprintf("%s: %p: RX buffer overflow\n", __func__, sock->fd);
        }
    }
}

static HRESULT hook_handle_irp(struct irp *irp)
{
    struct hook_socket *sock;
    HRESULT hr;

    assert(irp != NULL);

    EnterCriticalSection(&hook_lock);

    if (irp->op == IRP_OP_SOCKET) {
        sock = NULL;

        if (irp->sock_af != AF_INET || irp->sock_type != SOCK_RAW) {
            goto pass;
        }
    } else {
        sock = hook_find_socket(irp->fd);

        if (sock == NULL) {
            goto pass;
        }
    }

    hr = hook_handle_irp_locked(irp, sock);
    LeaveCriticalSection(&hook_lock);

    return hr;

pass:
    LeaveCriticalSection(&hook_lock);

    return iohook_invoke_next(irp);
}

static HRESULT hook_handle_irp_locked(
        struct irp *irp,
        struct hook_socket *sock)
{
    assert(irp != NULL);

    switch (irp->op) {
    case IRP_OP_SOCKET:         return hook_handle_socket(irp);
    case IRP_OP_CLOSESOCKET:    return hook_handle_closesocket(irp, sock);
    case IRP_OP_BIND:           return hook_handle_bind(irp, sock);
    case IRP_OP_IOCTLSOCKET:    return hook_handle_ioctlsocket(irp, sock);
    case IRP_OP_SETSOCKOPT:     return hook_handle_setsockopt(irp, sock);
    case IRP_OP_RECVFROM:       return hook_handle_recvfrom(irp, sock);
    case IRP_OP_SENDTO:         return hook_handle_sendto(irp, sock);
    default:
        dprintf("Unhandled IRP op: %i\n", irp->op);

        return HRESULT_FROM_WIN32(ERROR_INVALID_FUNCTION);
    }
}

static HRESULT hook_handle_socket(struct irp *irp)
{
    struct hook_socket *sock;
    HRESULT hr;

    assert(irp != NULL);

    /* Outer IRP handler specifically checks that a packet socket is what's
       being created. This design is a bit messy though. */

    if (irp->sock_protocol != IPPROTO_ICMP) {
        dprintf("Attempted to open non-ICMP packet socket\n");

        return E_NOTIMPL;
    }

    sock = calloc(1, sizeof(*sock));

    if (sock == NULL) {
        hr = E_OUTOFMEMORY;

        goto end;
    }

    hr = iohook_open_nul_fd(&sock->fd);

    if (FAILED(hr)) {
        goto end;
    }

    InitializeConditionVariable(&sock->cond);
    sock->rx_timeout_ms = INFINITE;
    sock->tx_timeout_ms = INFINITE;

    irp->fd = sock->fd;

    dprintf("%s -> %p\n", __func__, sock->fd);

    sock->next = hook_sockets;
    hook_sockets = sock;
    sock = NULL;

    hr = S_OK;

end:
    free(sock);

    return hr;
}

static HRESULT hook_handle_closesocket(
        struct irp *irp,
        struct hook_socket *sock)
{
    struct hook_socket *prev;
    HRESULT hr;

    assert(irp != NULL);
    assert(sock != NULL);

    if (hook_sockets == sock) {
        hook_sockets = sock->next;
    } else {
        for (prev = hook_sockets ; prev != NULL ; prev = prev->next) {
            if (prev->next == sock) {
                prev->next = sock->next;

                break;
            }
        }
    }

    free(sock);

    /* Close our straw FD, releasing the lock as we do so (we'll need to
       reacquire the lock so that the common dispatch code can unlock it). */

    irp->op = IRP_OP_CLOSE;

    LeaveCriticalSection(&hook_lock);
    hr = iohook_invoke_next(irp);
    EnterCriticalSection(&hook_lock);

    dprintf("%s(%p) -> %x\n", __func__, irp->fd, (int) hr);

    return hr;
}

static HRESULT hook_handle_bind(struct irp *irp, struct hook_socket *sock)
{
    const struct sockaddr_in *addr_obj;
    uint32_t addr;

    assert(irp != NULL);
    assert(sock != NULL);

    dprintf("%s(%p)\n", __func__, irp->fd);

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

static HRESULT hook_handle_ioctlsocket(
        struct irp *irp,
        struct hook_socket *sock)
{
    assert(irp != NULL);
    assert(sock != NULL);

    dprintf("%s(%p, %x)\n", __func__, irp->fd, irp->sock_ioctl);

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

static HRESULT hook_handle_setsockopt(
        struct irp *irp,
        struct hook_socket *sock)
{
    uint32_t param;
    HRESULT hr;

    assert(irp != NULL);
    assert(sock != NULL);

    dprintf("%s(%p, %i, %i)\n",
            __func__,
            irp->fd,
            irp->sockopt_level,
            irp->sockopt_name);

    switch (irp->sockopt_level) {
    case SOL_SOCKET:
        switch(irp->sockopt_name) {
        case SO_SNDTIMEO:
            hr = iobuf_read_le32(&irp->write, &param);

            if (FAILED(hr)) {
                return hr;
            }

            dprintf("Set send timeout: %i ms\n", (int) param);
            sock->tx_timeout_ms = param;

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

static HRESULT hook_handle_sendto(struct irp *irp, struct hook_socket *sock)
{
    struct iobuf tmp_iobuf;
    const struct sockaddr_in *addr_obj;
    uint32_t addr;
    bool rx;

    assert(irp != NULL);
    assert(sock != NULL);

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
    dprintf("sendto(%p, %08x):\n", irp->fd, addr);
    dump_const_iobuf(&irp->write);
#endif

    /* Unconditionally swallow the entire packet from here on */

    if (addr == 0x7f000001) {
        /* We only respond to 127.0.0.1 for now */
        tmp_iobuf.bytes = hook_tmp_bytes;
        tmp_iobuf.nbytes = sizeof(hook_tmp_bytes);
        tmp_iobuf.pos = 0;

        rx = peer_transact(&irp->write, &tmp_iobuf);

        if (rx) {
            hook_distribute_response(tmp_iobuf.bytes, tmp_iobuf.pos);
        }
    }

    return S_OK;
}

static HRESULT hook_handle_recvfrom(
        struct irp *irp,
        struct hook_socket *sock)
{
    struct sockaddr_in *addr_obj;
    size_t ncopied;
    BOOL ok;

    assert(irp != NULL);
    assert(sock != NULL);

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

    ncopied = iobuf_move(&irp->read, &sock->recv);

    if (ncopied == 0) {
        ok = SleepConditionVariableCS(
                &sock->cond,
                &hook_lock,
                sock->rx_timeout_ms);

        if (!ok) {
            dprintf("recvfrom(%p) -> Timed out\n", irp->fd);

            return HRESULT_FROM_WIN32(WSAETIMEDOUT);
        }

        iobuf_move(&irp->read, &sock->recv);
    }

    if (addr_obj != NULL) {
        addr_obj->sin_family = AF_INET;
        addr_obj->sin_port = 0;
        addr_obj->sin_addr.s_addr = _byteswap_ulong(0x7f000001);
    }

#if 1
    dprintf("recvfrom(%p)\n", irp->fd);
    dump_iobuf(&irp->read);
#endif

    return S_OK;
}
