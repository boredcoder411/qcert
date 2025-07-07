#include "der.h"
#include <string.h>

der_error_t der_encode_utf8_string(der_ctx_t *ctx, const char *str) {
  if (!ctx || !str) {
    return DER_ERROR_NULL_POINTER;
  }

  size_t len = strlen(str);
  der_error_t err = der_encode_tlv_header(ctx, DER_TAG_UTF8_STRING, len);
  if (err != DER_OK) {
    return err;
  }

  if (len > 0) {
    if (der_get_remaining(ctx) < len) {
      return DER_ERROR_BUFFER_TOO_SMALL;
    }

    memcpy(&ctx->data[ctx->pos], str, len);
    ctx->pos += len;
  }

  return DER_OK;
}

der_error_t der_decode_utf8_string(der_ctx_t *ctx, char *str, size_t *str_len,
                                   size_t max_len) {
  if (!ctx || !str || !str_len) {
    return DER_ERROR_NULL_POINTER;
  }

  der_tlv_t tlv;
  der_error_t err = der_decode_tlv(ctx, &tlv);
  if (err != DER_OK) {
    return err;
  }

  if (tlv.tag != DER_TAG_UTF8_STRING) {
    return DER_ERROR_INVALID_TAG;
  }

  if (tlv.length >= max_len) {
    return DER_ERROR_BUFFER_TOO_SMALL;
  }

  if (tlv.length > 0) {
    memcpy(str, tlv.value, tlv.length);
  }
  str[tlv.length] = '\0';
  *str_len = tlv.length;

  return DER_OK;
}

der_error_t der_encode_printable_string(der_ctx_t *ctx, const char *str) {
  if (!ctx || !str) {
    return DER_ERROR_NULL_POINTER;
  }

  size_t len = strlen(str);
  der_error_t err = der_encode_tlv_header(ctx, DER_TAG_PRINTABLE_STRING, len);
  if (err != DER_OK) {
    return err;
  }

  if (len > 0) {
    if (der_get_remaining(ctx) < len) {
      return DER_ERROR_BUFFER_TOO_SMALL;
    }

    memcpy(&ctx->data[ctx->pos], str, len);
    ctx->pos += len;
  }

  return DER_OK;
}

der_error_t der_decode_printable_string(der_ctx_t *ctx, char *str,
                                        size_t *str_len, size_t max_len) {
  if (!ctx || !str || !str_len) {
    return DER_ERROR_NULL_POINTER;
  }

  der_tlv_t tlv;
  der_error_t err = der_decode_tlv(ctx, &tlv);
  if (err != DER_OK) {
    return err;
  }

  if (tlv.tag != DER_TAG_PRINTABLE_STRING) {
    return DER_ERROR_INVALID_TAG;
  }

  if (tlv.length >= max_len) {
    return DER_ERROR_BUFFER_TOO_SMALL;
  }

  if (tlv.length > 0) {
    memcpy(str, tlv.value, tlv.length);
  }
  str[tlv.length] = '\0';
  *str_len = tlv.length;

  return DER_OK;
}

static size_t encode_subid(uint32_t subid, uint8_t *out) {
  if (subid < 0x80) {
    out[0] = (uint8_t)subid;
    return 1;
  }

  size_t len = 0;
  uint32_t temp = subid;

  while (temp > 0) {
    temp >>= 7;
    len++;
  }

  for (int i = len - 1; i >= 0; i--) {
    uint8_t byte = (subid >> (i * 7)) & 0x7F;
    if (i > 0) {
      byte |= 0x80;
    }
    out[len - 1 - i] = byte;
  }

  return len;
}

static der_error_t decode_subid(const uint8_t *data, size_t data_len,
                                size_t *pos, uint32_t *subid) {
  *subid = 0;
  size_t bytes_read = 0;

  while (*pos < data_len) {
    uint8_t byte = data[*pos];
    (*pos)++;
    bytes_read++;

    if (bytes_read > 5) {

      return DER_ERROR_OVERFLOW;
    }

    *subid = (*subid << 7) | (byte & 0x7F);

    if ((byte & 0x80) == 0) {

      return DER_OK;
    }
  }

  return DER_ERROR_INVALID_DATA;
}

der_error_t der_encode_oid(der_ctx_t *ctx, const uint32_t *oid,
                           size_t oid_len) {
  if (!ctx || !oid || oid_len < 2) {
    return DER_ERROR_NULL_POINTER;
  }

  if (oid[0] > 2 || (oid[0] < 2 && oid[1] >= 40) ||
      (oid[0] == 2 && oid[1] > 175)) {
    return DER_ERROR_INVALID_DATA;
  }

  uint8_t temp_buffer[1024];
  size_t temp_pos = 0;

  uint32_t first_subid = oid[0] * 40 + oid[1];
  temp_pos += encode_subid(first_subid, &temp_buffer[temp_pos]);

  for (size_t i = 2; i < oid_len; i++) {
    if (temp_pos >= sizeof(temp_buffer) - 5) {
      return DER_ERROR_BUFFER_TOO_SMALL;
    }
    temp_pos += encode_subid(oid[i], &temp_buffer[temp_pos]);
  }

  der_error_t err = der_encode_tlv_header(ctx, DER_TAG_OID, temp_pos);
  if (err != DER_OK) {
    return err;
  }

  if (der_get_remaining(ctx) < temp_pos) {
    return DER_ERROR_BUFFER_TOO_SMALL;
  }

  memcpy(&ctx->data[ctx->pos], temp_buffer, temp_pos);
  ctx->pos += temp_pos;

  return DER_OK;
}

der_error_t der_decode_oid(der_ctx_t *ctx, uint32_t *oid, size_t *oid_len,
                           size_t max_len) {
  if (!ctx || !oid || !oid_len || max_len < 2) {
    return DER_ERROR_NULL_POINTER;
  }

  der_tlv_t tlv;
  der_error_t err = der_decode_tlv(ctx, &tlv);
  if (err != DER_OK) {
    return err;
  }

  if (tlv.tag != DER_TAG_OID) {
    return DER_ERROR_INVALID_TAG;
  }

  if (tlv.length == 0) {
    return DER_ERROR_INVALID_LENGTH;
  }

  size_t pos = 0;
  size_t components = 0;

  uint32_t first_subid;
  err = decode_subid(tlv.value, tlv.length, &pos, &first_subid);
  if (err != DER_OK) {
    return err;
  }

  if (first_subid < 40) {
    oid[0] = 0;
    oid[1] = first_subid;
  } else if (first_subid < 80) {
    oid[0] = 1;
    oid[1] = first_subid - 40;
  } else {
    oid[0] = 2;
    oid[1] = first_subid - 80;
  }
  components = 2;

  while (pos < tlv.length && components < max_len) {
    err = decode_subid(tlv.value, tlv.length, &pos, &oid[components]);
    if (err != DER_OK) {
      return err;
    }
    components++;
  }

  if (pos < tlv.length) {

    return DER_ERROR_BUFFER_TOO_SMALL;
  }

  *oid_len = components;
  return DER_OK;
}
