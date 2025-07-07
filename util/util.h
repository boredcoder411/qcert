#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

const char *get_oid_name(const uint32_t *oid, size_t oid_len);
void print_oid(const uint32_t *oid, size_t oid_len);
void print_oid_with_name(const uint32_t *oid, size_t oid_len);
void print_hex(const uint8_t *data, size_t len);