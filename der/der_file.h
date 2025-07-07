#pragma once

#include "der.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DER_MAX_FILE_SIZE (10 * 1024 * 1024)

typedef struct {
  uint8_t *data;
  size_t size;
  der_ctx_t ctx;
  bool owns_data;
} der_file_t;

der_error_t der_file_read(const char *filename, der_file_t *file);
der_error_t der_file_read_buffer(const uint8_t *buffer, size_t size,
                                 der_file_t *file);
void der_file_free(der_file_t *file);

der_error_t der_file_parse_structure(der_file_t *file);
der_error_t der_file_validate(der_file_t *file);
der_error_t der_file_print_info(der_file_t *file);

der_error_t der_file_write(const char *filename, const uint8_t *data,
                           size_t size);
der_error_t der_file_write_context(const char *filename, der_ctx_t *ctx);

der_error_t der_file_is_certificate(der_file_t *file, bool *is_cert);
der_error_t der_file_is_private_key(der_file_t *file, bool *is_key);

typedef struct {
  char *subject;
  char *issuer;
  uint32_t serial_number;
  char *not_before;
  char *not_after;
  uint32_t *public_key_oid;
  size_t public_key_oid_len;
  uint8_t *public_key_data;
  size_t public_key_data_len;
} der_cert_info_t;

der_error_t der_file_extract_cert_info(der_file_t *file, der_cert_info_t *info);
void der_cert_info_free(der_cert_info_t *info);