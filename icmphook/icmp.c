#include <windows.h>

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

#include "icmphook/checksum.h"
#include "icmphook/icmp.h"

enum {
    HEADER_NBYTES = 4,
};

static HRESULT icmp_encode_header_only(
        struct iobuf *dest,
        const struct icmp_header *header,
        uint16_t checksum)
{
    HRESULT hr;

    hr = iobuf_write_8(dest, header->type);

    if (FAILED(hr)) {
        return hr;
    }

    hr = iobuf_write_8(dest, header->code);

    if (FAILED(hr)) {
        return hr;
    }

    hr = iobuf_write_be16(dest, checksum);

    if (FAILED(hr)) {
        return hr;
    }

    return S_OK;
}

HRESULT icmp_decode(struct const_iobuf *src, struct icmp_header *header)
{
    uint8_t tmp_header[HEADER_NBYTES];
    struct const_iobuf tmp_iobuf;
    uint16_t checksum;
    HRESULT hr;

    assert(src != NULL);
    assert(header != NULL);

    hr = iobuf_read(src, tmp_header, sizeof(tmp_header));

    if (FAILED(hr)) {
        return hr;
    }

    tmp_iobuf.bytes = tmp_header;
    tmp_iobuf.nbytes = sizeof(tmp_header);
    tmp_iobuf.pos = 0;

    iobuf_read_8(&tmp_iobuf, &header->type);
    iobuf_read_8(&tmp_iobuf, &header->code);

    checksum = ip_checksum_step(tmp_header, sizeof(tmp_header), 0);
    checksum = ip_checksum_step(
            &src->bytes[src->pos],
            src->nbytes - src->pos,
            checksum);

    if (checksum != 0xFFFF) {
        return HRESULT_FROM_WIN32(ERROR_CRC);
    }

    return S_OK;
}

HRESULT icmp_encode(
        struct iobuf *dest,
        const struct icmp_header *header,
        const void *payload,
        size_t nbytes)
{
    uint8_t tmp_header[HEADER_NBYTES];
    struct iobuf tmp_iobuf;
    uint16_t checksum;
    HRESULT hr;

    assert(dest != NULL);
    assert(header != NULL);
    assert(payload != NULL || nbytes == 0);

    tmp_iobuf.bytes = tmp_header;
    tmp_iobuf.nbytes = sizeof(tmp_header);
    tmp_iobuf.pos = 0;

    icmp_encode_header_only(&tmp_iobuf, header, 0);

    checksum = ip_checksum_step(tmp_header, sizeof(tmp_header), 0);
    checksum = ip_checksum_step(payload, nbytes, checksum);

    hr = icmp_encode_header_only(dest, header, ~checksum); /* Inversion! */

    if (FAILED(hr)) {
        return hr;
    }

    hr = iobuf_write(dest, payload, nbytes);

    if (FAILED(hr)) {
        return hr;
    }

    return S_OK;
}
