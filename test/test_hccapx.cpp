#include "hccapx.h"

#include <cstring>

#include "test_framework.h"

using namespace artemisz;

static HccapxInput sampleInput(const uint8_t*& macAp, const uint8_t*& macSta,
                               const uint8_t*& anonce, const uint8_t*& snonce,
                               const uint8_t*& mic, const uint8_t*& eapol,
                               int eapolLen) {
  static uint8_t ap[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
  static uint8_t sta[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
  static uint8_t an[32];
  static uint8_t sn[32];
  static uint8_t m[16];
  static uint8_t ep[256];
  for (int i = 0; i < 32; i++) { an[i] = (uint8_t)(0x40 + i); sn[i] = (uint8_t)(0x80 + i); }
  for (int i = 0; i < 16; i++) m[i] = (uint8_t)(0xC0 + i);
  for (int i = 0; i < 256; i++) ep[i] = (uint8_t)(i & 0xFF);

  macAp = ap; macSta = sta; anonce = an; snonce = sn; mic = m; eapol = ep;

  HccapxInput in;
  in.essid = "TestNet";
  in.essidLen = 7;
  in.macAp = ap; in.macSta = sta;
  in.anonce = an; in.snonce = sn;
  in.keyver = 2;
  in.mic = m;
  in.eapol = ep; in.eapolLen = eapolLen;
  in.messagePair = 0;
  return in;
}

TEST(hccapx_header_and_field_offsets) {
  const uint8_t *ap, *sta, *an, *sn, *mic, *ep;
  HccapxInput in = sampleInput(ap, sta, an, sn, mic, ep, 121);

  uint8_t rec[HCCAPX_RECORD_LEN];
  CHECK(buildHccapxRecord(rec, in));

  // Signature + version.
  CHECK_EQ(rec[0], 'H'); CHECK_EQ(rec[1], 'C');
  CHECK_EQ(rec[2], 'P'); CHECK_EQ(rec[3], 'X');
  CHECK_EQ(rec[4], 4); CHECK_EQ(rec[5], 0);
  CHECK_EQ(rec[6], 0); CHECK_EQ(rec[7], 0);

  CHECK_EQ(rec[8], 0);   // message_pair
  CHECK_EQ(rec[9], 7);   // essid_len
  CHECK_BYTES(rec + 10, "TestNet", 7);

  CHECK_EQ(rec[42], 2);  // keyver
  CHECK_BYTES(rec + 43, mic, 16);
  CHECK_BYTES(rec + 59, ap, 6);
  CHECK_BYTES(rec + 65, an, 32);
  CHECK_BYTES(rec + 97, sta, 6);
  CHECK_BYTES(rec + 103, sn, 32);

  // eapol_len little-endian.
  CHECK_EQ(rec[135], 121 & 0xFF);
  CHECK_EQ(rec[136], (121 >> 8) & 0xFF);
}

TEST(hccapx_embedded_eapol_has_mic_zeroed) {
  const uint8_t *ap, *sta, *an, *sn, *mic, *ep;
  HccapxInput in = sampleInput(ap, sta, an, sn, mic, ep, 121);

  uint8_t rec[HCCAPX_RECORD_LEN];
  CHECK(buildHccapxRecord(rec, in));

  // Bytes before the MIC region should match the source EAPOL frame.
  CHECK_BYTES(rec + 137, ep, HCCAPX_EAPOL_MIC_OFFSET);
  // The 16-byte MIC at offset 81 within the embedded EAPOL must be zeroed.
  uint8_t zero[16] = {0};
  CHECK_BYTES(rec + 137 + HCCAPX_EAPOL_MIC_OFFSET, zero, 16);
  // Bytes after the MIC should again match the source.
  CHECK_BYTES(rec + 137 + HCCAPX_EAPOL_MIC_OFFSET + 16,
              ep + HCCAPX_EAPOL_MIC_OFFSET + 16,
              121 - (HCCAPX_EAPOL_MIC_OFFSET + 16));
}

TEST(hccapx_clamps_oversized_essid_and_eapol) {
  const uint8_t *ap, *sta, *an, *sn, *mic, *ep;
  HccapxInput in = sampleInput(ap, sta, an, sn, mic, ep, 300);  // > 256
  static char longEssid[40];
  memset(longEssid, 'X', sizeof(longEssid));
  in.essid = longEssid;
  in.essidLen = 40;  // > 32

  uint8_t rec[HCCAPX_RECORD_LEN];
  CHECK(buildHccapxRecord(rec, in));
  CHECK_EQ(rec[9], 32);              // essid_len clamped
  CHECK_EQ(rec[135], 256 & 0xFF);   // eapol_len clamped to 256
  CHECK_EQ(rec[136], (256 >> 8) & 0xFF);
}

TEST(hccapx_rejects_null_pointers) {
  HccapxInput in;  // all pointers null
  uint8_t rec[HCCAPX_RECORD_LEN];
  CHECK(!buildHccapxRecord(rec, in));
}
