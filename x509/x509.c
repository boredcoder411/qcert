#include "x509.h"
#include "../der/der.h"

void parse_version(der_ctx_t *ctx) {
  uint8_t tag;
  if (der_peek_tag(ctx, &tag) == DER_OK && (tag & 0xE0) == 0xA0) {
    der_tlv_t tlv;
    if (der_decode_tlv(ctx, &tlv) == DER_OK) {
      printf("  Version: ");
      if (tlv.length >= 3 && tlv.value[0] == DER_TAG_INTEGER) {
        size_t int_len = tlv.value[1];
        if (int_len > 0 && int_len <= 4) {
          uint32_t version = 0;
          for (size_t i = 0; i < int_len; i++) {
            version = (version << 8) | tlv.value[2 + i];
          }
          printf("v%u (0x%x)\n", version + 1, version);
        } else {
          printf("(invalid)\n");
        }
      }
    }
  } else {
    printf("  Version: v1 (default)\n");
  }
}

void parse_serial_number(der_ctx_t *ctx) {
  uint8_t serial[64];
  size_t serial_len = sizeof(serial);

  if (der_decode_integer(ctx, serial, &serial_len, sizeof(serial)) == DER_OK) {
    printf("  Serial Number: ");
    print_hex(serial, serial_len);
    printf("\n");
  }
}

void parse_algorithm_identifier(der_ctx_t *ctx, const char *name) {
  size_t seq_len;
  if (der_decode_sequence_header(ctx, &seq_len) == DER_OK) {
    printf("  %s:\n", name);

    uint32_t oid[16];
    size_t oid_len = 16;
    if (der_decode_oid(ctx, oid, &oid_len, 16) == DER_OK) {
      printf("    Algorithm: ");
      print_oid_with_name(oid, oid_len);
      printf("\n");
    }

    uint8_t tag;
    if (der_peek_tag(ctx, &tag) == DER_OK) {
      der_skip_element(ctx);
    }
  }
}

void parse_name(der_ctx_t *ctx, const char *name_type) {
  size_t seq_len;
  if (der_decode_sequence_header(ctx, &seq_len) == DER_OK) {
    printf("  %s:\n", name_type);

    size_t end_pos = der_get_position(ctx) + seq_len;

    while (der_get_position(ctx) < end_pos) {
      size_t set_len;
      if (der_decode_set_header(ctx, &set_len) == DER_OK) {
        size_t seq2_len;
        if (der_decode_sequence_header(ctx, &seq2_len) == DER_OK) {
          uint32_t oid[16];
          size_t oid_len = 16;
          if (der_decode_oid(ctx, oid, &oid_len, 16) == DER_OK) {
            printf("    ");

            if (oid_len == 4 && oid[0] == 2 && oid[1] == 5 && oid[2] == 4) {
              switch (oid[3]) {
              case 3:
                printf("CN=");
                break;
              case 6:
                printf("C=");
                break;
              case 7:
                printf("L=");
                break;
              case 8:
                printf("ST=");
                break;
              case 10:
                printf("O=");
                break;
              case 11:
                printf("OU=");
                break;
              default:
                printf("Unknown=");
                break;
              }
            } else {
              printf("OID(");
              print_oid(oid, oid_len);
              printf(")=");
            }

            uint8_t tag;
            if (der_peek_tag(ctx, &tag) == DER_OK) {
              char value[256];
              size_t value_len = sizeof(value) - 1;

              if (tag == DER_TAG_UTF8_STRING) {
                if (der_decode_utf8_string(ctx, value, &value_len,
                                           sizeof(value) - 1) == DER_OK) {
                  value[value_len] = '\0';
                  printf("%s", value);
                }
              } else if (tag == DER_TAG_PRINTABLE_STRING) {
                if (der_decode_printable_string(ctx, value, &value_len,
                                                sizeof(value) - 1) == DER_OK) {
                  value[value_len] = '\0';
                  printf("%s", value);
                }
              } else {
                der_skip_element(ctx);
                printf("(unparsed)");
              }
            }
            printf("\n");
          }
        }
      }
    }
  }
}

void parse_validity(der_ctx_t *ctx) {
  size_t seq_len;
  if (der_decode_sequence_header(ctx, &seq_len) == DER_OK) {
    printf("  Validity:\n");

    uint8_t tag;
    if (der_peek_tag(ctx, &tag) == DER_OK) {
      char time_str[32];
      size_t time_len = sizeof(time_str) - 1;

      printf("    Not Before: ");
      if (tag == DER_TAG_UTC_TIME || tag == DER_TAG_GENERALIZED_TIME) {
        der_tlv_t tlv;
        if (der_decode_tlv(ctx, &tlv) == DER_OK) {
          size_t copy_len = tlv.length < sizeof(time_str) - 1
                                ? tlv.length
                                : sizeof(time_str) - 1;
          memcpy(time_str, tlv.value, copy_len);
          time_str[copy_len] = '\0';
          printf("%s\n", time_str);
        }
      } else {
        der_skip_element(ctx);
        printf("(unparsed)\n");
      }
    }

    if (der_peek_tag(ctx, &tag) == DER_OK) {
      char time_str[32];
      size_t time_len = sizeof(time_str) - 1;

      printf("    Not After: ");
      if (tag == DER_TAG_UTC_TIME || tag == DER_TAG_GENERALIZED_TIME) {
        der_tlv_t tlv;
        if (der_decode_tlv(ctx, &tlv) == DER_OK) {
          size_t copy_len = tlv.length < sizeof(time_str) - 1
                                ? tlv.length
                                : sizeof(time_str) - 1;
          memcpy(time_str, tlv.value, copy_len);
          time_str[copy_len] = '\0';
          printf("%s\n", time_str);
        }
      } else {
        der_skip_element(ctx);
        printf("(unparsed)\n");
      }
    }
  }
}

void parse_public_key_info(der_ctx_t *ctx) {
  size_t seq_len;
  if (der_decode_sequence_header(ctx, &seq_len) == DER_OK) {
    printf("  Public Key Info:\n");

    parse_algorithm_identifier(ctx, "Public Key Algorithm");

    uint8_t bit_string[512];
    size_t bit_string_len = sizeof(bit_string);

    uint8_t tag;
    if (der_peek_tag(ctx, &tag) == DER_OK && tag == DER_TAG_BIT_STRING) {
      der_tlv_t tlv;
      if (der_decode_tlv(ctx, &tlv) == DER_OK) {
        printf("    Public Key: ");
        if (tlv.length > 0) {
          printf("(%zu bits)\n      ", (tlv.length - 1) * 8);
          print_hex(tlv.value + 1, tlv.length - 1);
        }
        printf("\n");
      }
    }
  }
}

void parse_extensions(der_ctx_t *ctx) {
  uint8_t tag;
  if (der_peek_tag(ctx, &tag) == DER_OK && (tag & 0xE0) == 0xA0) {
    der_tlv_t ext_tlv;
    if (der_decode_tlv(ctx, &ext_tlv) == DER_OK) {
      printf("  Extensions:\n");

      der_ctx_t ext_ctx;
      der_init(&ext_ctx, (uint8_t *)ext_tlv.value, ext_tlv.length);

      size_t ext_seq_len;
      if (der_decode_sequence_header(&ext_ctx, &ext_seq_len) == DER_OK) {
        size_t end_pos = der_get_position(&ext_ctx) + ext_seq_len;

        while (der_get_position(&ext_ctx) < end_pos) {
          size_t ext_len;
          if (der_decode_sequence_header(&ext_ctx, &ext_len) == DER_OK) {
            uint32_t ext_oid[16];
            size_t ext_oid_len = 16;
            if (der_decode_oid(&ext_ctx, ext_oid, &ext_oid_len, 16) == DER_OK) {
              printf("    Extension: ");
              print_oid_with_name(ext_oid, ext_oid_len);
              printf("\n");

              uint8_t next_tag;
              if (der_peek_tag(&ext_ctx, &next_tag) == DER_OK &&
                  next_tag == DER_TAG_BOOLEAN) {
                bool critical;
                if (der_decode_boolean(&ext_ctx, &critical) == DER_OK) {
                  printf("      Critical: %s\n", critical ? "true" : "false");
                }
              }

              if (der_peek_tag(&ext_ctx, &next_tag) == DER_OK &&
                  next_tag == DER_TAG_OCTET_STRING) {
                der_tlv_t val_tlv;
                if (der_decode_tlv(&ext_ctx, &val_tlv) == DER_OK) {
                  printf("      Value: (%zu bytes)\n", val_tlv.length);
                }
              }
            }
          }
        }
      }
    }
  }
}

void parse_certificate(const uint8_t *der_data, size_t der_len) {
  der_ctx_t ctx;
  der_init(&ctx, (uint8_t *)der_data, der_len);

  printf("X.509 Certificate:\n");

  size_t cert_len;
  if (der_decode_sequence_header(&ctx, &cert_len) != DER_OK) {
    printf("Failed to parse certificate SEQUENCE\n");
    return;
  }

  size_t tbs_len;
  if (der_decode_sequence_header(&ctx, &tbs_len) != DER_OK) {
    printf("Failed to parse TBSCertificate SEQUENCE\n");
    return;
  }

  printf("TBSCertificate:\n");

  parse_version(&ctx);

  parse_serial_number(&ctx);

  parse_algorithm_identifier(&ctx, "Signature Algorithm");

  parse_name(&ctx, "Issuer");

  parse_validity(&ctx);

  parse_name(&ctx, "Subject");

  parse_public_key_info(&ctx);

  parse_extensions(&ctx);

  printf("\nCertificate parsed successfully!\n");
}
