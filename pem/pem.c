#include "pem.h"

char *read_pem_file(const char *filename) {
  FILE *file = fopen(filename, "r");
  if (!file) {
    perror("Failed to open file");
    return NULL;
  }

  fseek(file, 0, SEEK_END);
  long file_size = ftell(file);
  fseek(file, 0, SEEK_SET);

  char *buffer = malloc(file_size + 1);
  if (!buffer) {
    fclose(file);
    return NULL;
  }

  size_t read_size = fread(buffer, 1, file_size, file);
  buffer[read_size] = '\0';
  fclose(file);

  char *start = strstr(buffer, "-----BEGIN CERTIFICATE-----");
  if (!start) {
    free(buffer);
    return NULL;
  }
  start += strlen("-----BEGIN CERTIFICATE-----");

  char *end = strstr(start, "-----END CERTIFICATE-----");
  if (!end) {
    free(buffer);
    return NULL;
  }

  size_t b64_len = end - start;
  char *b64_data = malloc(b64_len + 1);
  if (!b64_data) {
    free(buffer);
    return NULL;
  }

  strncpy(b64_data, start, b64_len);
  b64_data[b64_len] = '\0';

  free(buffer);
  return b64_data;
}