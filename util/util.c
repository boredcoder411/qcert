#include "util.h"

void print_oid(const uint32_t *oid, size_t oid_len) {
  for (size_t i = 0; i < oid_len; i++) {
    printf("%u", oid[i]);
    if (i < oid_len - 1) {
      printf(".");
    }
  }
}

void print_oid_with_name(const uint32_t *oid, size_t oid_len) {
  print_oid(oid, oid_len);
  const char *name = get_oid_name(oid, oid_len);
  if (name) {
    printf(" (%s)", name);
  }
}
const char *get_oid_name(const uint32_t *oid, size_t oid_len) {
  if (oid_len == 7 && oid[0] == 1 && oid[1] == 2 && oid[2] == 840 &&
      oid[3] == 113549 && oid[4] == 1 && oid[5] == 1) {
    switch (oid[6]) {
    case 1:
      return "RSA";
    case 5:
      return "SHA-1 with RSA";
    case 11:
      return "SHA-256 with RSA";
    case 12:
      return "SHA-384 with RSA";
    case 13:
      return "SHA-512 with RSA";
    }
  }

  if (oid_len == 7 && oid[0] == 1 && oid[1] == 2 && oid[2] == 840 &&
      oid[3] == 10045 && oid[4] == 2 && oid[5] == 1) {
    return "Elliptic Curve Public Key";
  }

  if (oid_len == 8 && oid[0] == 1 && oid[1] == 2 && oid[2] == 840 &&
      oid[3] == 10045 && oid[4] == 4 && oid[5] == 3) {
    switch (oid[6]) {
    case 2:
      return "ECDSA with SHA-256";
    case 3:
      return "ECDSA with SHA-384";
    case 4:
      return "ECDSA with SHA-512";
    }
  }

  if (oid_len == 4 && oid[0] == 2 && oid[1] == 5 && oid[2] == 29) {
    switch (oid[3]) {
    case 14:
      return "Subject Key Identifier";
    case 15:
      return "Key Usage";
    case 17:
      return "Subject Alternative Name";
    case 19:
      return "Basic Constraints";
    case 31:
      return "CRL Distribution Points";
    case 32:
      return "Certificate Policies";
    case 35:
      return "Authority Key Identifier";
    case 37:
      return "Extended Key Usage";
    }
  }

  if (oid_len == 8 && oid[0] == 1 && oid[1] == 3 && oid[2] == 6 &&
      oid[3] == 1 && oid[4] == 5 && oid[5] == 5 && oid[6] == 7 && oid[7] == 1) {
    return "Authority Information Access";
  }

  if (oid_len == 10 && oid[0] == 1 && oid[1] == 3 && oid[2] == 6 &&
      oid[3] == 1 && oid[4] == 4 && oid[5] == 1 && oid[6] == 11129 &&
      oid[7] == 2 && oid[8] == 4 && oid[9] == 2) {
    return "Certificate Transparency SCTs";
  }

  return NULL;
}

void print_hex(const uint8_t *data, size_t len) {
  for (size_t i = 0; i < len; i++) {
    printf("%02x", data[i]);
    if (i > 0 && (i + 1) % 16 == 0) {
      printf("\n");
    } else if (i > 0 && (i + 1) % 8 == 0) {
      printf("  ");
    } else {
      printf(" ");
    }
  }
  if (len % 16 != 0) {
    printf("\n");
  }
}