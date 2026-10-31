#include "hexfmt.h"

#include <cstring>

#include "test_framework.h"

using namespace artemisz;

TEST(hex_with_colons_like_a_mac) {
  uint8_t mac[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x0A};
  char out[32];
  size_t n = bytesToHex(mac, 6, out, /*colon=*/true);
  CHECK_EQ(n, 17);  // 6*2 + 5 separators
  CHECK(strcmp(out, "de:ad:be:ef:01:0a") == 0);
}

TEST(hex_without_colons) {
  uint8_t data[4] = {0x00, 0x0F, 0xA0, 0xFF};
  char out[16];
  size_t n = bytesToHex(data, 4, out, /*colon=*/false);
  CHECK_EQ(n, 8);
  CHECK(strcmp(out, "000fa0ff") == 0);
}

TEST(hex_empty_input) {
  char out[4] = {'x', 'x', 'x', 'x'};
  size_t n = bytesToHex(nullptr, 0, out, true);
  CHECK_EQ(n, 0);
  CHECK_EQ(out[0], '\0');
}
