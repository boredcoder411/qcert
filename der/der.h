#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define DER_TAG_BOOLEAN 0x01
#define DER_TAG_INTEGER 0x02
#define DER_TAG_BIT_STRING 0x03
#define DER_TAG_OCTET_STRING 0x04
#define DER_TAG_NULL 0x05
#define DER_TAG_OID 0x06
#define DER_TAG_UTF8_STRING 0x0C
#define DER_TAG_SEQUENCE 0x30
#define DER_TAG_SET 0x31
#define DER_TAG_PRINTABLE_STRING 0x13
#define DER_TAG_T61_STRING 0x14
#define DER_TAG_IA5_STRING 0x16
#define DER_TAG_UTC_TIME 0x17
#define DER_TAG_GENERALIZED_TIME 0x18

#define DER_CLASS_UNIVERSAL 0x00
#define DER_CLASS_APPLICATION 0x40
#define DER_CLASS_CONTEXT 0x80
#define DER_CLASS_PRIVATE 0xC0

#define DER_PRIMITIVE 0x00
#define DER_CONSTRUCTED 0x20

typedef enum {
  DER_OK = 0,
  DER_ERROR_INVALID_DATA = -1,
  DER_ERROR_BUFFER_TOO_SMALL = -2,
  DER_ERROR_INVALID_LENGTH = -3,
  DER_ERROR_INVALID_TAG = -4,
  DER_ERROR_NULL_POINTER = -5,
  DER_ERROR_OVERFLOW = -6
} der_error_t;

typedef struct {
  uint8_t *data;
  size_t size;
  size_t pos;
} der_ctx_t;

typedef struct {
  uint8_t tag;
  size_t length;
  const uint8_t *value;
} der_tlv_t;

der_error_t der_init(der_ctx_t *ctx, uint8_t *buffer, size_t size);
der_error_t der_reset(der_ctx_t *ctx);
size_t der_get_remaining(const der_ctx_t *ctx);
size_t der_get_position(const der_ctx_t *ctx);

der_error_t der_encode_length(der_ctx_t *ctx, size_t length);
der_error_t der_decode_length(der_ctx_t *ctx, size_t *length);
size_t der_length_size(size_t length);

der_error_t der_encode_tag(der_ctx_t *ctx, uint8_t tag);
der_error_t der_decode_tag(der_ctx_t *ctx, uint8_t *tag);

der_error_t der_decode_tlv(der_ctx_t *ctx, der_tlv_t *tlv);
der_error_t der_encode_tlv_header(der_ctx_t *ctx, uint8_t tag, size_t length);

der_error_t der_encode_boolean(der_ctx_t *ctx, bool value);
der_error_t der_decode_boolean(der_ctx_t *ctx, bool *value);

der_error_t der_encode_integer(der_ctx_t *ctx, const uint8_t *value,
                               size_t value_len);
der_error_t der_decode_integer(der_ctx_t *ctx, uint8_t *value,
                               size_t *value_len, size_t max_len);

der_error_t der_encode_octet_string(der_ctx_t *ctx, const uint8_t *value,
                                    size_t value_len);
der_error_t der_decode_octet_string(der_ctx_t *ctx, uint8_t *value,
                                    size_t *value_len, size_t max_len);

der_error_t der_encode_null(der_ctx_t *ctx);
der_error_t der_decode_null(der_ctx_t *ctx);

der_error_t der_encode_oid(der_ctx_t *ctx, const uint32_t *oid, size_t oid_len);
der_error_t der_decode_oid(der_ctx_t *ctx, uint32_t *oid, size_t *oid_len,
                           size_t max_len);

der_error_t der_encode_sequence_header(der_ctx_t *ctx, size_t content_length);
der_error_t der_decode_sequence_header(der_ctx_t *ctx, size_t *content_length);

der_error_t der_encode_set_header(der_ctx_t *ctx, size_t content_length);
der_error_t der_decode_set_header(der_ctx_t *ctx, size_t *content_length);

der_error_t der_encode_utf8_string(der_ctx_t *ctx, const char *str);
der_error_t der_decode_utf8_string(der_ctx_t *ctx, char *str, size_t *str_len,
                                   size_t max_len);

der_error_t der_encode_printable_string(der_ctx_t *ctx, const char *str);
der_error_t der_decode_printable_string(der_ctx_t *ctx, char *str,
                                        size_t *str_len, size_t max_len);

der_error_t der_skip_element(der_ctx_t *ctx);
der_error_t der_peek_tag(der_ctx_t *ctx, uint8_t *tag);
bool der_is_constructed(uint8_t tag);
bool der_is_context_specific(uint8_t tag);

der_error_t der_encode_integer_uint32(der_ctx_t *ctx, uint32_t value);
der_error_t der_decode_integer_uint32(der_ctx_t *ctx, uint32_t *value);

der_error_t der_encode_integer_int32(der_ctx_t *ctx, int32_t value);
der_error_t der_decode_integer_int32(der_ctx_t *ctx, int32_t *value);