#include "hexfmt.h"

namespace artemisz {

size_t bytesToHex(const uint8_t* bytes, size_t n, char* out, bool colon) {
  static const char kHex[] = "0123456789abcdef";
  size_t w = 0;
  for (size_t i = 0; i < n; i++) {
    if (colon && i > 0) out[w++] = ':';
    out[w++] = kHex[(bytes[i] >> 4) & 0x0F];
    out[w++] = kHex[bytes[i] & 0x0F];
  }
  out[w] = '\0';
  return w;
}

}  // namespace artemisz
