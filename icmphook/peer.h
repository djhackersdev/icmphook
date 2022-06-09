#pragma once

#include <windows.h>

#include <stdbool.h>

#include "iohook/iobuf.h"

bool peer_transact(struct const_iobuf *req, struct iobuf *res);