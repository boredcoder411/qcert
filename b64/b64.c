#include "b64.h"

int base64_decode(const char *input, uint8_t *output, size_t max_output_len) {
  size_t input_len = strlen(input);
  size_t output_len = 0;
  uint32_t buffer = 0;
  int bits = 0;

  for (size_t i = 0; i < input_len; i++) {
    if (input[i] == '=' || input[i] == '\n' || input[i] == '\r' ||
        input[i] == ' ') {
      continue;
    }

    int value = base64_decode_table[(unsigned char)input[i]];
    if (value < 0) {
      continue;
    }

    buffer = (buffer << 6) | value;
    bits += 6;

    if (bits >= 8) {
      if (output_len >= max_output_len) {
        return -1;
      }
      output[output_len++] = (buffer >> (bits - 8)) & 0xFF;
      bits -= 8;
    }
  }

  return output_len;
}
