#include <windows.h>

#include <assert.h>
#include <stddef.h>
#include <stdlib.h>

#include "icmphook/checksum.h"
#include "icmphook/ip4.h"

#include "iohook/iobuf.h"

HRESULT ip4_encode(
        struct iobuf *dest,
        const struct ip4_header *header,
        const void *options,
        size_t options_nbytes,
        const void *payload,
        size_t payload_nbytes
)
{
    struct iobuf checksum_buf;
    size_t header_len;
    size_t total_len;
    size_t start_pos;
    uint16_t checksum;
    HRESULT hr;

    assert(dest != NULL);
    assert(header != NULL);
    assert(!(header->dscp & ~0x3F));
    assert(!(header->ecn & ~0x03));
    assert(!(header->flags & ~0x07));
    assert(!(header->fragment_offset & ~0x1FFF));
    assert(options != NULL || options_nbytes == 0);
    assert(options_nbytes % 4 == 0 && options_nbytes <= 40);
    assert(payload != NULL);

    start_pos = dest->pos;
    header_len = 20 + options_nbytes;
    total_len = header_len + payload_nbytes;

    if (total_len > 0xFFFF) {
        return HRESULT_FROM_WIN32(ERROR_MESSAGE_EXCEEDS_MAX_SIZE);
    }

    hr = iobuf_write_8(dest, 0x40 | (header_len / 4));

    if (FAILED(hr)) {
        return hr;
    }

    hr = iobuf_write_8(dest, (header->dscp << 2) | header->ecn);

    if (FAILED(hr)) {
        return hr;
    }

    hr = iobuf_write_be16(dest, total_len);

    if (FAILED(hr)) {
        return hr;
    }

    hr = iobuf_write_be16(dest, header->identification);

    if (FAILED(hr)) {
        return hr;
    }

    hr = iobuf_write_be16(
            dest,
            (header->flags << 13) | header->fragment_offset);

    if (FAILED(hr)) {
        return hr;
    }

    hr = iobuf_write_8(dest, header->ttl);

    if (FAILED(hr)) {
        return hr;
    }

    hr = iobuf_write_8(dest, header->protocol);

    if (FAILED(hr)) {
        return hr;
    }

    checksum_buf.bytes = &dest->bytes[dest->pos];
    checksum_buf.nbytes = 2;
    checksum_buf.pos = 0;

    hr = iobuf_write_be16(dest, 0); /* Checksum placeholder */

    if (FAILED(hr)) {
        return hr;
    }

    hr = iobuf_write_be32(dest, header->src);

    if (FAILED(hr)) {
        return hr;
    }

    hr = iobuf_write_be32(dest, header->dest);

    if (FAILED(hr)) {
        return hr;
    }

    hr = iobuf_write(dest, options, options_nbytes);

    if (FAILED(hr)) {
        return hr;
    }

    checksum = ip_checksum(&dest->bytes[start_pos], dest->pos - start_pos);
    hr = iobuf_write_be16(&checksum_buf, checksum);

    if (FAILED(hr)) {
        abort();
    }

    return iobuf_write(dest, payload, payload_nbytes);
}
