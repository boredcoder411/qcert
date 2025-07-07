#include "der_file.h"
#include "der_utils.h"

der_error_t der_file_read(const char *filename, der_file_t *file) {
  if (!filename || !file) {
    return DER_ERROR_NULL_POINTER;
  }

  memset(file, 0, sizeof(der_file_t));

  FILE *fp = fopen(filename, "rb");
  if (!fp) {
    return DER_ERROR_INVALID_DATA;
  }

  if (fseek(fp, 0, SEEK_END) != 0) {
    fclose(fp);
    return DER_ERROR_INVALID_DATA;
  }

  long file_size = ftell(fp);
  if (file_size < 0 || file_size > DER_MAX_FILE_SIZE) {
    fclose(fp);
    return DER_ERROR_INVALID_DATA;
  }

  if (fseek(fp, 0, SEEK_SET) != 0) {
    fclose(fp);
    return DER_ERROR_INVALID_DATA;
  }

  file->data = malloc((size_t)file_size);
  if (!file->data) {
    fclose(fp);
    return DER_ERROR_BUFFER_TOO_SMALL;
  }

  size_t bytes_read = fread(file->data, 1, (size_t)file_size, fp);
  fclose(fp);

  if (bytes_read != (size_t)file_size) {
    free(file->data);
    file->data = NULL;
    return DER_ERROR_INVALID_DATA;
  }

  file->size = (size_t)file_size;
  file->owns_data = true;
  der_init(&file->ctx, file->data, file->size);

  return DER_OK;
}

der_error_t der_file_read_buffer(const uint8_t *buffer, size_t size,
                                 der_file_t *file) {
  if (!buffer || !file || size == 0) {
    return DER_ERROR_NULL_POINTER;
  }

  memset(file, 0, sizeof(der_file_t));

  file->data = (uint8_t *)buffer;
  file->size = size;
  file->owns_data = false;
  der_init(&file->ctx, file->data, file->size);

  return DER_OK;
}

void der_file_free(der_file_t *file) {
  if (!file) {
    return;
  }

  if (file->owns_data && file->data) {
    free(file->data);
  }

  memset(file, 0, sizeof(der_file_t));
}

der_error_t der_file_parse_structure(der_file_t *file) {
  if (!file || !file->data) {
    return DER_ERROR_NULL_POINTER;
  }

  printf("DER File Structure (%zu bytes):\n", file->size);
  printf("================================\n");

  der_error_t err = der_print_structure(file->data, file->size, 0);
  if (err != DER_OK) {
    printf("Error parsing structure: %s\n", der_error_to_string(err));
    return err;
  }

  return DER_OK;
}

der_error_t der_file_validate(der_file_t *file) {
  if (!file || !file->data) {
    return DER_ERROR_NULL_POINTER;
  }

  return der_validate_structure(file->data, file->size);
}

der_error_t der_file_print_info(der_file_t *file) {
  if (!file || !file->data) {
    return DER_ERROR_NULL_POINTER;
  }

  printf("DER File Information:\n");
  printf("====================\n");
  printf("File size: %zu bytes\n", file->size);

  der_error_t validation = der_file_validate(file);
  printf("Structure validation: %s\n",
         validation == DER_OK ? "VALID" : der_error_to_string(validation));

  if (file->size > 0) {
    uint8_t first_tag = file->data[0];
    printf("Root element: %s (0x%02X)\n", der_tag_to_string(first_tag),
           first_tag);

    if (first_tag == DER_TAG_SEQUENCE) {
      printf("Likely contains: Certificate, Key, or other structured data\n");
    }
  }

  bool is_cert, is_key;
  if (der_file_is_certificate(file, &is_cert) == DER_OK && is_cert) {
    printf("File type: X.509 Certificate (likely)\n");
  } else if (der_file_is_private_key(file, &is_key) == DER_OK && is_key) {
    printf("File type: Private Key (likely)\n");
  } else {
    printf("File type: Unknown DER structure\n");
  }

  printf("\n");
  return DER_OK;
}

der_error_t der_file_write(const char *filename, const uint8_t *data,
                           size_t size) {
  if (!filename || !data || size == 0) {
    return DER_ERROR_NULL_POINTER;
  }

  FILE *fp = fopen(filename, "wb");
  if (!fp) {
    return DER_ERROR_INVALID_DATA;
  }

  size_t bytes_written = fwrite(data, 1, size, fp);
  fclose(fp);

  if (bytes_written != size) {
    return DER_ERROR_INVALID_DATA;
  }

  return DER_OK;
}

der_error_t der_file_write_context(const char *filename, der_ctx_t *ctx) {
  if (!filename || !ctx) {
    return DER_ERROR_NULL_POINTER;
  }

  return der_file_write(filename, ctx->data, ctx->pos);
}

der_error_t der_file_is_certificate(der_file_t *file, bool *is_cert) {
  if (!file || !file->data || !is_cert) {
    return DER_ERROR_NULL_POINTER;
  }

  *is_cert = false;

  der_ctx_t ctx = file->ctx;
  ctx.pos = 0;

  uint8_t tag;
  der_error_t err = der_peek_tag(&ctx, &tag);
  if (err != DER_OK || tag != DER_TAG_SEQUENCE) {
    return DER_OK;
  }

  size_t outer_len;
  err = der_decode_sequence_header(&ctx, &outer_len);
  if (err != DER_OK) {
    return DER_OK;
  }

  err = der_peek_tag(&ctx, &tag);
  if (err != DER_OK || tag != DER_TAG_SEQUENCE) {
    return DER_OK;
  }

  err = der_skip_element(&ctx);
  if (err != DER_OK) {
    return DER_OK;
  }

  err = der_peek_tag(&ctx, &tag);
  if (err != DER_OK || tag != DER_TAG_SEQUENCE) {
    return DER_OK;
  }

  err = der_skip_element(&ctx);
  if (err != DER_OK) {
    return DER_OK;
  }

  err = der_peek_tag(&ctx, &tag);
  if (err != DER_OK || tag != DER_TAG_BIT_STRING) {
    return DER_OK;
  }

  *is_cert = true;
  return DER_OK;
}

der_error_t der_file_is_private_key(der_file_t *file, bool *is_key) {
  if (!file || !file->data || !is_key) {
    return DER_ERROR_NULL_POINTER;
  }

  *is_key = false;

  der_ctx_t ctx = file->ctx;
  ctx.pos = 0;

  uint8_t tag;
  der_error_t err = der_peek_tag(&ctx, &tag);
  if (err != DER_OK || tag != DER_TAG_SEQUENCE) {
    return DER_OK;
  }

  size_t seq_len;
  err = der_decode_sequence_header(&ctx, &seq_len);
  if (err != DER_OK) {
    return DER_OK;
  }

  err = der_peek_tag(&ctx, &tag);
  if (err != DER_OK || tag != DER_TAG_INTEGER) {
    return DER_OK;
  }

  err = der_skip_element(&ctx);
  if (err != DER_OK) {
    return DER_OK;
  }

  err = der_peek_tag(&ctx, &tag);
  if (err != DER_OK || tag != DER_TAG_INTEGER) {
    return DER_OK;
  }

  *is_key = true;
  return DER_OK;
}

der_error_t der_file_extract_cert_info(der_file_t *file,
                                       der_cert_info_t *info) {
  if (!file || !file->data || !info) {
    return DER_ERROR_NULL_POINTER;
  }

  memset(info, 0, sizeof(der_cert_info_t));

  der_ctx_t ctx = file->ctx;
  ctx.pos = 0;

  size_t outer_len;
  der_error_t err = der_decode_sequence_header(&ctx, &outer_len);
  if (err != DER_OK) {
    return err;
  }

  size_t tbs_len;
  err = der_decode_sequence_header(&ctx, &tbs_len);
  if (err != DER_OK) {
    return err;
  }

  uint8_t tag;
  err = der_peek_tag(&ctx, &tag);
  if (err == DER_OK && der_is_context_specific(tag)) {
    err = der_skip_element(&ctx);
    if (err != DER_OK) {
      return err;
    }
  }

  err = der_peek_tag(&ctx, &tag);
  if (err == DER_OK && tag == DER_TAG_INTEGER) {
    err = der_decode_integer_uint32(&ctx, &info->serial_number);
    if (err != DER_OK) {
      ctx.pos -= 1;
      err = der_skip_element(&ctx);
      if (err != DER_OK) {
        return err;
      }
    }
  }

  printf("Certificate parsing: Basic structure detected\n");
  printf(
      "Note: Full certificate parsing requires more complex ASN.1 handling\n");

  return DER_OK;
}

void der_cert_info_free(der_cert_info_t *info) {
  if (!info) {
    return;
  }

  free(info->subject);
  free(info->issuer);
  free(info->not_before);
  free(info->not_after);
  free(info->public_key_oid);
  free(info->public_key_data);

  memset(info, 0, sizeof(der_cert_info_t));
}
