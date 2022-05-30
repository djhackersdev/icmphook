#include <windows.h>

#include <windows.h>

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>

#include "icmphook/checksum.h"
#include "icmphook/ip4.h"

#include "iohook/iobuf.h"

enum {
    HEADER_NWORDS = 5,
    HEADER_NBYTES = HEADER_NWORDS * sizeof(uint32_t)
};

static HRESULT ip4_encode_with_checksum(
        struct iobuf *dest,
        const struct ip4_header *header,
        uint16_t checksum)
{
    uint16_t total_len;
    HRESULT hr;

    assert(dest != NULL);
    assert(header != NULL);
    assert(header->payload_size <= 0xFFFF - HEADER_NBYTES);

    total_len = HEADER_NBYTES + header->payload_size;

    /*
        IP: version 4
        IHL: 5 32-bit words
        DSCP, ECN: None
        Total Length: As given

        Identification: None
        Flags, Fragment Offset: None (fragmentation currently unsupported)

        TTL: As given
        Protocol: As given
        Checksum: As given

        Source address: As given

        Destination address: As given
     */

    iobuf_write_be32(dest, 0x45 | (total_len << 16));
    iobuf_write_be32(dest, 0);
    iobuf_write_be32(
            dest,
            header->ttl | (header->protocol << 8) | (checksum << 16));
    iobuf_write_be32(dest, header->src);
    hr = iobuf_write_be32(dest, header->dest);

    return hr;
}

HRESULT ip4_decode(
        struct const_iobuf *src,
        struct ip4_header *header)
{
    uint8_t tmp_header[HEADER_NBYTES];
    struct const_iobuf tmp_iobuf;
    uint32_t word;
    uint16_t total_len;
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

    iobuf_read_be32(&tmp_iobuf, &word);

    if ((word & 0xFF) != 0x45) {
        return E_NOTIMPL;
    }

    total_len = word >> 16;

    if (total_len < HEADER_NBYTES) {
        return E_INVALIDARG;
    }

    header->payload_size = total_len - HEADER_NBYTES;

    iobuf_read_be32(&tmp_iobuf, &word);

    header->ttl = word;
    header->protocol = word >> 8;

    iobuf_read_be32(&tmp_iobuf, &header->src);
    iobuf_read_be32(&tmp_iobuf, &header->dest);

    checksum = ip_checksum(tmp_header, sizeof(tmp_header));

    if (checksum != 0) {
        return HRESULT_FROM_WIN32(ERROR_CRC);
    }

    return S_OK;
}

HRESULT ip4_encode(struct iobuf *dest, const struct ip4_header *header)
{
    struct iobuf tmp_iobuf;
    uint8_t tmp_header[HEADER_NBYTES];
    uint16_t checksum;
    HRESULT hr;

    assert(dest != NULL);
    assert(header != NULL);

    tmp_iobuf.bytes = tmp_header;
    tmp_iobuf.nbytes = sizeof(tmp_header);
    tmp_iobuf.pos = 0;

    ip4_encode_with_checksum(&tmp_iobuf, header, 0);
    checksum = ip_checksum(tmp_header, sizeof(tmp_header));
    hr = ip4_encode_with_checksum(dest, header, checksum);

    return hr;
}
