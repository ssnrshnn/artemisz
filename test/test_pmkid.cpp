#include "eapol.h"

#include "fixtures.h"
#include "test_framework.h"

using namespace artemisz;

// Place an RSN PMKID KDE (DD 14 00 0F AC 04 + 16 bytes) into the Key Data of a
// msg1 frame at `kdePos` (relative to the EAPOL start), and set Key Data Length.
static std::vector<uint8_t> msg1WithPmkid(const uint8_t pmkid[16], int kdePos,
                                          int keyDataLen, int total) {
  auto f = fixtures::eapolKey(0x008A, nullptr, total);  // msg1 key info
  f[97] = (uint8_t)(keyDataLen >> 8);
  f[98] = (uint8_t)(keyDataLen & 0xFF);
  f[kdePos + 0] = 0xDD;
  f[kdePos + 1] = 0x14;  // length 20
  f[kdePos + 2] = 0x00;
  f[kdePos + 3] = 0x0F;
  f[kdePos + 4] = 0xAC;
  f[kdePos + 5] = 0x04;  // type: PMKID
  memcpy(&f[kdePos + 6], pmkid, 16);
  return f;
}

TEST(pmkid_extracted_at_start_of_key_data) {
  uint8_t pmkid[16];
  for (int i = 0; i < 16; i++) pmkid[i] = (uint8_t)(0x10 + i);
  // Key Data starts at offset 99; KDE right there, keyDataLen 22.
  auto f = msg1WithPmkid(pmkid, 99, 22, 99 + 22);

  uint8_t out[16];
  CHECK(extractPmkid(f.data(), (int)f.size(), out));
  CHECK_BYTES(out, pmkid, 16);
}

TEST(pmkid_extracted_after_other_kdes) {
  uint8_t pmkid[16];
  for (int i = 0; i < 16; i++) pmkid[i] = (uint8_t)(0xA0 + i);
  // Pretend 8 bytes of a preceding KDE, then the PMKID KDE -> keyDataLen 30.
  auto f = msg1WithPmkid(pmkid, 99 + 8, 30, 99 + 30);

  uint8_t out[16];
  CHECK(extractPmkid(f.data(), (int)f.size(), out));
  CHECK_BYTES(out, pmkid, 16);
}

TEST(pmkid_absent_returns_false) {
  auto f = fixtures::eapolKey(0x008A, nullptr, 99 + 22);
  f[97] = 0x00; f[98] = 22;  // key data len present but no KDE bytes set
  uint8_t out[16];
  CHECK(!extractPmkid(f.data(), (int)f.size(), out));
}

TEST(pmkid_rejects_truncated_key_data) {
  // Claim keyDataLen 22 in the header but provide a buffer too short to hold
  // it (no KDE bytes written). extractPmkid must bounds-check and bail out.
  auto f = fixtures::eapolKey(0x008A, nullptr, 99 + 10);
  f[97] = 0x00;
  f[98] = 22;  // declared key data length exceeds what the buffer holds
  uint8_t out[16];
  CHECK(!extractPmkid(f.data(), (int)f.size(), out));
}

TEST(pmkid_rejects_short_frame) {
  auto f = fixtures::eapolKey(0x008A, nullptr, 50);
  uint8_t out[16];
  CHECK(!extractPmkid(f.data(), (int)f.size(), out));
}
