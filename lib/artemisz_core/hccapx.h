// hccapx.h — Pure serializer for a Hashcat HCCAPX v4 record (mode 2500).
//
// One record is a fixed 393 bytes. Extracted from handleHccapxDownload() in
// src/main.cpp so the field offsets can be verified against the published
// hccapx v4 layout in a host unit test (see test/test_hccapx.cpp).
//
// HCCAPX v4 field map (byte offset / size):
//    0 / 4   signature "HCPX"
//    4 / 4   version (little-endian) = 4
//    8 / 1   message_pair
//    9 / 1   essid_len
//   10 / 32  essid
//   42 / 1   keyver
//   43 / 16  keymic
//   59 / 6   mac_ap
//   65 / 32  nonce_ap (ANonce)
//   97 / 6   mac_sta
//  103 / 32  nonce_sta (SNonce)
//  135 / 2   eapol_len (little-endian)
//  137 / 256 eapol (the STA->AP EAPOL frame, MIC field zeroed)
#pragma once

#include <cstdint>

namespace artemisz {

static const int HCCAPX_RECORD_LEN = 393;
static const int HCCAPX_EAPOL_MAX = 256;
// Offset of the Key MIC field inside an EAPOL-Key frame (see eapol.h).
static const int HCCAPX_EAPOL_MIC_OFFSET = 81;

struct HccapxInput {
  const char* essid = nullptr;  // not required to be NUL-terminated
  int essidLen = 0;
  const uint8_t* macAp = nullptr;   // 6 bytes
  const uint8_t* macSta = nullptr;  // 6 bytes
  const uint8_t* anonce = nullptr;  // 32 bytes
  const uint8_t* snonce = nullptr;  // 32 bytes
  uint8_t keyver = 0;
  const uint8_t* mic = nullptr;   // 16 bytes
  const uint8_t* eapol = nullptr; // msg2 EAPOL frame
  int eapolLen = 0;
  uint8_t messagePair = 0;  // 0 = M1+M2
};

// Build a 393-byte HCCAPX record from `in` into `out`. `essidLen` is clamped to
// 32, `eapolLen` to 256. The MIC inside the embedded EAPOL copy is zeroed (as
// Hashcat requires) when the frame is long enough to contain it. Returns false
// only if a required pointer is null or `essidLen`/`eapolLen` are negative.
bool buildHccapxRecord(uint8_t out[HCCAPX_RECORD_LEN], const HccapxInput& in);

}  // namespace artemisz
