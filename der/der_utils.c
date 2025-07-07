#include "der_utils.h"
#include <stdio.h>
#include <string.h>

void der_print_hex(const uint8_t *data, size_t length) {
  for (size_t i = 0; i < length; i++) {
    printf("%02X", data[i]);
    if (i < length - 1) {
      printf(" ");
    }
  }
  printf("\n");
}

const char *der_tag_to_string(uint8_t tag) {
  switch (tag) {
  case DER_TAG_BOOLEAN:
    return "BOOLEAN";
  case DER_TAG_INTEGER:
    return "INTEGER";
  case DER_TAG_BIT_STRING:
    return "BIT STRING";
  case DER_TAG_OCTET_STRING:
    return "OCTET STRING";
  case DER_TAG_NULL:
    return "NULL";
  case DER_TAG_OID:
    return "OBJECT IDENTIFIER";
  case DER_TAG_UTF8_STRING:
    return "UTF8String";
  case DER_TAG_SEQUENCE:
    return "SEQUENCE";
  case DER_TAG_SET:
    return "SET";
  case DER_TAG_PRINTABLE_STRING:
    return "PrintableString";
  case DER_TAG_T61_STRING:
    return "T61String";
  case DER_TAG_IA5_STRING:
    return "IA5String";
  case DER_TAG_UTC_TIME:
    return "UTCTime";
  case DER_TAG_GENERALIZED_TIME:
    return "GeneralizedTime";
  default:
    if (der_is_context_specific(tag)) {
      return "CONTEXT SPECIFIC";
    }
    return "UNKNOWN";
  }
}

const char *der_error_to_string(der_error_t error) {
  switch (error) {
  case DER_OK:
    return "Success";
  case DER_ERROR_INVALID_DATA:
    return "Invalid data";
  case DER_ERROR_BUFFER_TOO_SMALL:
    return "Buffer too small";
  case DER_ERROR_INVALID_LENGTH:
    return "Invalid length";
  case DER_ERROR_INVALID_TAG:
    return "Invalid tag";
  case DER_ERROR_NULL_POINTER:
    return "NULL pointer";
  case DER_ERROR_OVERFLOW:
    return "Arithmetic overflow";
  default:
    return "Unknown error";
  }
}

der_error_t der_print_structure(const uint8_t *data, size_t length,
                                int indent_level) {
  if (!data || length == 0) {
    return DER_ERROR_NULL_POINTER;
  }

  der_ctx_t ctx;
  der_init(&ctx, (uint8_t *)data, length);

  while (der_get_remaining(&ctx) > 0) {

    for (int i = 0; i < indent_level; i++) {
      printf("  ");
    }

    der_tlv_t tlv;
    der_error_t err = der_decode_tlv(&ctx, &tlv);
    if (err != DER_OK) {
      printf("Error parsing TLV: %s\n", der_error_to_string(err));
      return err;
    }

    printf("%s (tag 0x%02X) [%zu bytes]: ", der_tag_to_string(tlv.tag), tlv.tag,
           tlv.length);

    if (der_is_constructed(tlv.tag)) {

      printf("\n");
      err = der_print_structure(tlv.value, tlv.length, indent_level + 1);
      if (err != DER_OK) {
        return err;
      }
    } else {

      switch (tlv.tag) {
      case DER_TAG_BOOLEAN:
        if (tlv.length == 1) {
          printf("%s\n", tlv.value[0] ? "TRUE" : "FALSE");
        } else {
          printf("Invalid BOOLEAN length\n");
        }
        break;

      case DER_TAG_INTEGER:
        if (tlv.length <= 4) {
          uint32_t value = 0;
          for (size_t i = 0; i < tlv.length; i++) {
            value = (value << 8) | tlv.value[i];
          }
          printf("%u (0x", value);
          for (size_t i = 0; i < tlv.length; i++) {
            printf("%02X", tlv.value[i]);
          }
          printf(")\n");
        } else {
          printf("0x");
          for (size_t i = 0; i < tlv.length; i++) {
            printf("%02X", tlv.value[i]);
          }
          printf("\n");
        }
        break;

      case DER_TAG_OCTET_STRING:
        printf("0x");
        for (size_t i = 0; i < tlv.length; i++) {
          printf("%02X", tlv.value[i]);
        }
        printf("\n");
        break;

      case DER_TAG_NULL:
        printf("NULL\n");
        break;

      case DER_TAG_OID: {
        der_ctx_t oid_ctx;
        der_init(&oid_ctx, (uint8_t *)tlv.value, tlv.length);
        uint32_t oid[20];
        size_t oid_len;
        if (der_decode_oid(&oid_ctx, oid, &oid_len, 20) == DER_OK) {
          for (size_t i = 0; i < oid_len; i++) {
            printf("%u", oid[i]);
            if (i < oid_len - 1)
              printf(".");
          }
          printf("\n");
        } else {
          printf("Invalid OID\n");
        }
      } break;

      case DER_TAG_UTF8_STRING:
      case DER_TAG_PRINTABLE_STRING:
      case DER_TAG_IA5_STRING:
        printf("\"");
        for (size_t i = 0; i < tlv.length; i++) {
          if (tlv.value[i] >= 32 && tlv.value[i] <= 126) {
            printf("%c", tlv.value[i]);
          } else {
            printf("\\x%02X", tlv.value[i]);
          }
        }
        printf("\"\n");
        break;

      default:
        printf("0x");
        for (size_t i = 0; i < tlv.length; i++) {
          printf("%02X", tlv.value[i]);
        }
        printf("\n");
        break;
      }
    }
  }

  return DER_OK;
}

size_t der_calculate_sequence_size(size_t content_length) {
  return 1 + der_length_size(content_length) + content_length;
}

size_t der_calculate_integer_size(uint32_t value) {
  if (value == 0) {
    return 1 + der_length_size(1) + 1;
  }

  size_t bytes_needed = 0;
  uint32_t temp = value;
  while (temp > 0) {
    temp >>= 8;
    bytes_needed++;
  }

  if ((value >> ((bytes_needed - 1) * 8)) & 0x80) {
    bytes_needed++;
  }

  return 1 + der_length_size(bytes_needed) + bytes_needed;
}

der_error_t der_encode_sequence_complete(der_ctx_t *ctx, const uint8_t *content,
                                         size_t content_length) {
  if (!ctx || !content) {
    return DER_ERROR_NULL_POINTER;
  }

  der_error_t err = der_encode_sequence_header(ctx, content_length);
  if (err != DER_OK) {
    return err;
  }

  if (der_get_remaining(ctx) < content_length) {
    return DER_ERROR_BUFFER_TOO_SMALL;
  }

  memcpy(&ctx->data[ctx->pos], content, content_length);
  ctx->pos += content_length;

  return DER_OK;
}

der_error_t der_validate_structure(const uint8_t *data, size_t length) {
  if (!data || length == 0) {
    return DER_ERROR_NULL_POINTER;
  }

  der_ctx_t ctx;
  der_init(&ctx, (uint8_t *)data, length);

  while (der_get_remaining(&ctx) > 0) {
    size_t start_pos = ctx.pos;

    der_tlv_t tlv;
    der_error_t err = der_decode_tlv(&ctx, &tlv);
    if (err != DER_OK) {
      return err;
    }

    size_t expected_pos =
        start_pos + 1 + der_length_size(tlv.length) + tlv.length;
    if (ctx.pos != expected_pos) {
      return DER_ERROR_INVALID_DATA;
    }

    if (der_is_constructed(tlv.tag)) {
      err = der_validate_structure(tlv.value, tlv.length);
      if (err != DER_OK) {
        return err;
      }
    }
  }

  return DER_OK;
}
