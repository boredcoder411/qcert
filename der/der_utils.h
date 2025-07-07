#pragma once

#include "der.h"
#include <stdio.h>

void der_print_hex(const uint8_t *data, size_t length);

der_error_t der_print_structure(const uint8_t *data, size_t length,
                                int indent_level);

const char *der_tag_to_string(uint8_t tag);

const char *der_error_to_string(der_error_t error);

size_t der_calculate_sequence_size(size_t content_length);

size_t der_calculate_integer_size(uint32_t value);

der_error_t der_encode_sequence_complete(der_ctx_t *ctx, const uint8_t *content,
                                         size_t content_length);

der_error_t der_validate_structure(const uint8_t *data, size_t length);