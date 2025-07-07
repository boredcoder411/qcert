#include "der.h"
#include <string.h>

der_error_t der_init(der_ctx_t *ctx, uint8_t *buffer, size_t size) {
  if (!ctx || !buffer) {
    return DER_ERROR_NULL_POINTER;
  }

  ctx->data = buffer;
  ctx->size = size;
  ctx->pos = 0;

  return DER_OK;
}

der_error_t der_reset(der_ctx_t *ctx) {
  if (!ctx) {
    return DER_ERROR_NULL_POINTER;
  }

  ctx->pos = 0;
  return DER_OK;
}

size_t der_get_remaining(const der_ctx_t *ctx) {
  if (!ctx || ctx->pos > ctx->size) {
    return 0;
  }
  return ctx->size - ctx->pos;
}

size_t der_get_position(const der_ctx_t *ctx) {
  if (!ctx) {
    return 0;
  }
  return ctx->pos;
}

size_t der_length_size(size_t length) {
  if (length < 0x80) {
    return 1;
  }

  size_t size = 1;
  while (length > 0) {
    length >>= 8;
    size++;
  }

  return size;
}

der_error_t der_encode_length(der_ctx_t *ctx, size_t length) {
  if (!ctx) {
    return DER_ERROR_NULL_POINTER;
  }

  if (length < 0x80) {

    if (der_get_remaining(ctx) < 1) {
      return DER_ERROR_BUFFER_TOO_SMALL;
    }
    ctx->data[ctx->pos++] = (uint8_t)length;
  } else {

    size_t len_bytes = 0;
    size_t temp_length = length;

    while (temp_length > 0) {
      temp_length >>= 8;
      len_bytes++;
    }

    if (len_bytes > 127) {
      return DER_ERROR_INVALID_LENGTH;
    }

    if (der_get_remaining(ctx) < len_bytes + 1) {
      return DER_ERROR_BUFFER_TOO_SMALL;
    }

    ctx->data[ctx->pos++] = 0x80 | (uint8_t)len_bytes;

    for (int i = len_bytes - 1; i >= 0; i--) {
      ctx->data[ctx->pos++] = (uint8_t)(length >> (i * 8));
    }
  }

  return DER_OK;
}

der_error_t der_decode_length(der_ctx_t *ctx, size_t *length) {
  if (!ctx || !length) {
    return DER_ERROR_NULL_POINTER;
  }

  if (der_get_remaining(ctx) < 1) {
    return DER_ERROR_BUFFER_TOO_SMALL;
  }

  uint8_t first_byte = ctx->data[ctx->pos++];

  if ((first_byte & 0x80) == 0) {

    *length = first_byte;
  } else {

    size_t len_bytes = first_byte & 0x7F;

    if (len_bytes == 0) {

      return DER_ERROR_INVALID_LENGTH;
    }

    if (len_bytes > sizeof(size_t)) {
      return DER_ERROR_INVALID_LENGTH;
    }

    if (der_get_remaining(ctx) < len_bytes) {
      return DER_ERROR_BUFFER_TOO_SMALL;
    }

    *length = 0;
    for (size_t i = 0; i < len_bytes; i++) {
      *length = (*length << 8) | ctx->data[ctx->pos++];
    }

    if (len_bytes > 1 && ctx->data[ctx->pos - len_bytes] == 0) {
      return DER_ERROR_INVALID_LENGTH;
    }
  }

  return DER_OK;
}

der_error_t der_encode_tag(der_ctx_t *ctx, uint8_t tag) {
  if (!ctx) {
    return DER_ERROR_NULL_POINTER;
  }

  if (der_get_remaining(ctx) < 1) {
    return DER_ERROR_BUFFER_TOO_SMALL;
  }

  ctx->data[ctx->pos++] = tag;
  return DER_OK;
}

der_error_t der_decode_tag(der_ctx_t *ctx, uint8_t *tag) {
  if (!ctx || !tag) {
    return DER_ERROR_NULL_POINTER;
  }

  if (der_get_remaining(ctx) < 1) {
    return DER_ERROR_BUFFER_TOO_SMALL;
  }

  *tag = ctx->data[ctx->pos++];
  return DER_OK;
}

der_error_t der_decode_tlv(der_ctx_t *ctx, der_tlv_t *tlv) {
  if (!ctx || !tlv) {
    return DER_ERROR_NULL_POINTER;
  }

  der_error_t err;

  err = der_decode_tag(ctx, &tlv->tag);
  if (err != DER_OK) {
    return err;
  }

  err = der_decode_length(ctx, &tlv->length);
  if (err != DER_OK) {
    return err;
  }

  if (der_get_remaining(ctx) < tlv->length) {
    return DER_ERROR_BUFFER_TOO_SMALL;
  }

  tlv->value = &ctx->data[ctx->pos];
  ctx->pos += tlv->length;

  return DER_OK;
}

der_error_t der_encode_tlv_header(der_ctx_t *ctx, uint8_t tag, size_t length) {
  der_error_t err;

  err = der_encode_tag(ctx, tag);
  if (err != DER_OK) {
    return err;
  }

  err = der_encode_length(ctx, length);
  if (err != DER_OK) {
    return err;
  }

  return DER_OK;
}

der_error_t der_encode_boolean(der_ctx_t *ctx, bool value) {
  der_error_t err;

  err = der_encode_tlv_header(ctx, DER_TAG_BOOLEAN, 1);
  if (err != DER_OK) {
    return err;
  }

  if (der_get_remaining(ctx) < 1) {
    return DER_ERROR_BUFFER_TOO_SMALL;
  }

  ctx->data[ctx->pos++] = value ? 0xFF : 0x00;
  return DER_OK;
}

der_error_t der_decode_boolean(der_ctx_t *ctx, bool *value) {
  if (!ctx || !value) {
    return DER_ERROR_NULL_POINTER;
  }

  der_tlv_t tlv;
  der_error_t err = der_decode_tlv(ctx, &tlv);
  if (err != DER_OK) {
    return err;
  }

  if (tlv.tag != DER_TAG_BOOLEAN) {
    return DER_ERROR_INVALID_TAG;
  }

  if (tlv.length != 1) {
    return DER_ERROR_INVALID_LENGTH;
  }

  *value = (tlv.value[0] != 0);
  return DER_OK;
}

der_error_t der_encode_integer(der_ctx_t *ctx, const uint8_t *value,
                               size_t value_len) {
  if (!ctx || !value || value_len == 0) {
    return DER_ERROR_NULL_POINTER;
  }

  size_t start = 0;
  while (start < value_len - 1 && value[start] == 0x00) {
    start++;
  }

  size_t encoded_len = value_len - start;
  bool need_padding = (value[start] & 0x80) != 0;
  if (need_padding) {
    encoded_len++;
  }

  der_error_t err = der_encode_tlv_header(ctx, DER_TAG_INTEGER, encoded_len);
  if (err != DER_OK) {
    return err;
  }

  if (der_get_remaining(ctx) < encoded_len) {
    return DER_ERROR_BUFFER_TOO_SMALL;
  }

  if (need_padding) {
    ctx->data[ctx->pos++] = 0x00;
  }

  memcpy(&ctx->data[ctx->pos], &value[start], value_len - start);
  ctx->pos += value_len - start;

  return DER_OK;
}

der_error_t der_decode_integer(der_ctx_t *ctx, uint8_t *value,
                               size_t *value_len, size_t max_len) {
  if (!ctx || !value || !value_len) {
    return DER_ERROR_NULL_POINTER;
  }

  der_tlv_t tlv;
  der_error_t err = der_decode_tlv(ctx, &tlv);
  if (err != DER_OK) {
    return err;
  }

  if (tlv.tag != DER_TAG_INTEGER) {
    return DER_ERROR_INVALID_TAG;
  }

  if (tlv.length == 0) {
    return DER_ERROR_INVALID_LENGTH;
  }

  if (tlv.length > max_len) {
    return DER_ERROR_BUFFER_TOO_SMALL;
  }

  memcpy(value, tlv.value, tlv.length);
  *value_len = tlv.length;

  return DER_OK;
}

der_error_t der_encode_octet_string(der_ctx_t *ctx, const uint8_t *value,
                                    size_t value_len) {
  if (!ctx || (value_len > 0 && !value)) {
    return DER_ERROR_NULL_POINTER;
  }

  der_error_t err = der_encode_tlv_header(ctx, DER_TAG_OCTET_STRING, value_len);
  if (err != DER_OK) {
    return err;
  }

  if (value_len > 0) {
    if (der_get_remaining(ctx) < value_len) {
      return DER_ERROR_BUFFER_TOO_SMALL;
    }

    memcpy(&ctx->data[ctx->pos], value, value_len);
    ctx->pos += value_len;
  }

  return DER_OK;
}

der_error_t der_decode_octet_string(der_ctx_t *ctx, uint8_t *value,
                                    size_t *value_len, size_t max_len) {
  if (!ctx || !value || !value_len) {
    return DER_ERROR_NULL_POINTER;
  }

  der_tlv_t tlv;
  der_error_t err = der_decode_tlv(ctx, &tlv);
  if (err != DER_OK) {
    return err;
  }

  if (tlv.tag != DER_TAG_OCTET_STRING) {
    return DER_ERROR_INVALID_TAG;
  }

  if (tlv.length > max_len) {
    return DER_ERROR_BUFFER_TOO_SMALL;
  }

  if (tlv.length > 0) {
    memcpy(value, tlv.value, tlv.length);
  }
  *value_len = tlv.length;

  return DER_OK;
}

der_error_t der_encode_null(der_ctx_t *ctx) {
  return der_encode_tlv_header(ctx, DER_TAG_NULL, 0);
}

der_error_t der_decode_null(der_ctx_t *ctx) {
  if (!ctx) {
    return DER_ERROR_NULL_POINTER;
  }

  der_tlv_t tlv;
  der_error_t err = der_decode_tlv(ctx, &tlv);
  if (err != DER_OK) {
    return err;
  }

  if (tlv.tag != DER_TAG_NULL) {
    return DER_ERROR_INVALID_TAG;
  }

  if (tlv.length != 0) {
    return DER_ERROR_INVALID_LENGTH;
  }

  return DER_OK;
}

der_error_t der_encode_sequence_header(der_ctx_t *ctx, size_t content_length) {
  return der_encode_tlv_header(ctx, DER_TAG_SEQUENCE, content_length);
}

der_error_t der_decode_sequence_header(der_ctx_t *ctx, size_t *content_length) {
  if (!ctx || !content_length) {
    return DER_ERROR_NULL_POINTER;
  }

  uint8_t tag;
  der_error_t err = der_decode_tag(ctx, &tag);
  if (err != DER_OK) {
    return err;
  }

  if (tag != DER_TAG_SEQUENCE) {
    return DER_ERROR_INVALID_TAG;
  }

  return der_decode_length(ctx, content_length);
}

der_error_t der_encode_set_header(der_ctx_t *ctx, size_t content_length) {
  return der_encode_tlv_header(ctx, DER_TAG_SET, content_length);
}

der_error_t der_decode_set_header(der_ctx_t *ctx, size_t *content_length) {
  if (!ctx || !content_length) {
    return DER_ERROR_NULL_POINTER;
  }

  uint8_t tag;
  der_error_t err = der_decode_tag(ctx, &tag);
  if (err != DER_OK) {
    return err;
  }

  if (tag != DER_TAG_SET) {
    return DER_ERROR_INVALID_TAG;
  }

  return der_decode_length(ctx, content_length);
}

der_error_t der_skip_element(der_ctx_t *ctx) {
  if (!ctx) {
    return DER_ERROR_NULL_POINTER;
  }

  der_tlv_t tlv;
  return der_decode_tlv(ctx, &tlv);
}

der_error_t der_peek_tag(der_ctx_t *ctx, uint8_t *tag) {
  if (!ctx || !tag) {
    return DER_ERROR_NULL_POINTER;
  }

  if (der_get_remaining(ctx) < 1) {
    return DER_ERROR_BUFFER_TOO_SMALL;
  }

  *tag = ctx->data[ctx->pos];
  return DER_OK;
}

bool der_is_constructed(uint8_t tag) { return (tag & DER_CONSTRUCTED) != 0; }

bool der_is_context_specific(uint8_t tag) {
  return (tag & 0xC0) == DER_CLASS_CONTEXT;
}

der_error_t der_encode_integer_uint32(der_ctx_t *ctx, uint32_t value) {
  uint8_t bytes[5];
  size_t len = 0;

  if (value == 0) {
    bytes[0] = 0;
    len = 1;
  } else {

    uint32_t temp = value;
    while (temp > 0) {
      bytes[len++] = temp & 0xFF;
      temp >>= 8;
    }

    for (size_t i = 0; i < len / 2; i++) {
      uint8_t t = bytes[i];
      bytes[i] = bytes[len - 1 - i];
      bytes[len - 1 - i] = t;
    }
  }

  return der_encode_integer(ctx, bytes, len);
}

der_error_t der_decode_integer_uint32(der_ctx_t *ctx, uint32_t *value) {
  if (!value) {
    return DER_ERROR_NULL_POINTER;
  }

  uint8_t bytes[5];
  size_t len;

  der_error_t err = der_decode_integer(ctx, bytes, &len, sizeof(bytes));
  if (err != DER_OK) {
    return err;
  }

  if (len > 5 || (len == 5 && bytes[0] != 0)) {
    return DER_ERROR_OVERFLOW;
  }

  *value = 0;
  for (size_t i = 0; i < len; i++) {
    *value = (*value << 8) | bytes[i];
  }

  return DER_OK;
}

der_error_t der_encode_integer_int32(der_ctx_t *ctx, int32_t value) {
  uint8_t bytes[4];

  bytes[0] = (value >> 24) & 0xFF;
  bytes[1] = (value >> 16) & 0xFF;
  bytes[2] = (value >> 8) & 0xFF;
  bytes[3] = value & 0xFF;

  return der_encode_integer(ctx, bytes, 4);
}

der_error_t der_decode_integer_int32(der_ctx_t *ctx, int32_t *value) {
  if (!value) {
    return DER_ERROR_NULL_POINTER;
  }

  uint8_t bytes[5];
  size_t len;

  der_error_t err = der_decode_integer(ctx, bytes, &len, sizeof(bytes));
  if (err != DER_OK) {
    return err;
  }

  if (len > 5) {
    return DER_ERROR_OVERFLOW;
  }

  *value = 0;
  if (len > 0 && (bytes[0] & 0x80)) {

    *value = -1;
  }

  for (size_t i = 0; i < len; i++) {
    *value = (*value << 8) | bytes[i];
  }

  return DER_OK;
}
