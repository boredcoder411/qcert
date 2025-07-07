#pragma once

#include "../util/util.h"
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

void parse_certificate(const uint8_t *der_data, size_t der_len);