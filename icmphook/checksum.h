#pragma once

#include <stddef.h>
#include <stdint.h>

uint16_t ip_checksum(const void *bytes, size_t nbytes);
uint16_t ip_checksum_step(const void *bytes, size_t nbytes, uint16_t carry);