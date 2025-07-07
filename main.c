#include "b64/b64.h"
#include "der/der.h"
#include "pem/pem.h"
#include "util/util.h"
#include "x509/x509.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
  const char *filename = "";

  if (argc > 1) {
    filename = argv[1];
  } else {
    fprintf(stderr, "Error: No certificate file provided.\n");
    fprintf(stderr, "Usage: %s [certificate_file]\n", argv[0]);
    return 1;
  }

  if (argc > 1 &&
      (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)) {
    printf("Usage: %s [certificate_file]\n", argv[0]);
    printf("Parse X.509 certificates in PEM format.\n\n");
    return 0;
  }

  printf("X.509 Certificate Parser\n");
  printf("========================\n");
  printf("Parsing certificate file: %s\n\n", filename);

  char *pem_data = read_pem_file(filename);
  if (!pem_data) {
    fprintf(stderr, "Failed to read PEM file: %s\n", filename);
    fprintf(
        stderr,
        "Make sure the file exists and contains a valid PEM certificate.\n");
    return 1;
  }

  uint8_t der_data[8192];
  int der_len = base64_decode(pem_data, der_data, sizeof(der_data));
  free(pem_data);

  if (der_len <= 0) {
    fprintf(stderr, "Failed to decode base64 data from PEM file\n");
    return 1;
  }

  printf("Certificate size: %d bytes\n\n", der_len);

  parse_certificate(der_data, der_len);

  return 0;
}