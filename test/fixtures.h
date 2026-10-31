// fixtures.h — Builders for synthetic EAPOL-Key frames used across tests.
#pragma once

#include <cstdint>
#include <cstring>
#include <vector>

namespace fixtures {

// Build an EAPOL-Key packet (pointer points at the 802.1X version byte).
// `keyInfo` is the 16-bit Key Information field; `nonce` (optional, 32 bytes)
// is copied into the Key Nonce field. `total` is the overall buffer size.
inline std::vector<uint8_t> eapolKey(uint16_t keyInfo, const uint8_t* nonce,
                                     int total) {
  std::vector<uint8_t> b(total, 0);
  b[0] = 0x02;              // 802.1X version 2
  b[1] = 0x03;              // packet type: EAPOL-Key
  b[2] = 0x00; b[3] = (uint8_t)(total - 4);  // body length (approx)
  b[4] = 0x02;              // descriptor type: RSN
  b[5] = (uint8_t)(keyInfo >> 8);
  b[6] = (uint8_t)(keyInfo & 0xFF);
  if (nonce && total >= 17 + 32) {
    memcpy(&b[17], nonce, 32);
  }
  return b;
}

// Wrap an EAPOL payload inside an 802.11 data frame with LLC/SNAP.
// `qos` selects a 26-byte (QoS) vs 24-byte MAC header.
inline std::vector<uint8_t> dot11WithEapol(const std::vector<uint8_t>& eapol,
                                           bool qos) {
  int hdr = qos ? 26 : 24;
  std::vector<uint8_t> f(hdr + 8 + (int)eapol.size(), 0);
  f[0] = qos ? 0x88 : 0x08;  // data frame; 0x88 = QoS data subtype 8
  // LLC/SNAP: AA AA 03 00 00 00 88 8E (EAPOL ethertype)
  f[hdr + 0] = 0xAA; f[hdr + 1] = 0xAA; f[hdr + 2] = 0x03;
  f[hdr + 6] = 0x88; f[hdr + 7] = 0x8E;
  memcpy(&f[hdr + 8], eapol.data(), eapol.size());
  return f;
}

}  // namespace fixtures
