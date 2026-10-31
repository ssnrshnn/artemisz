#include "eapol.h"

#include "fixtures.h"
#include "frame80211.h"
#include "test_framework.h"

using namespace artemisz;

// Key Information values with the ACK (0x0080) and MIC (0x0100) bits set to
// match each handshake message.
static const uint16_t KI_MSG1 = 0x008A;  // ACK, no MIC
static const uint16_t KI_MSG2 = 0x010A;  // MIC, no ACK
static const uint16_t KI_MSG3 = 0x018A;  // ACK + MIC
static const uint16_t KI_MSG4 = 0x010A;  // MIC, no ACK (zero nonce)

TEST(classify_msg1_ack_no_mic) {
  auto f = fixtures::eapolKey(KI_MSG1, nullptr, 121);
  CHECK_EQ(eapolKeyMessageNumber(f.data(), (int)f.size()), 1);
}

TEST(classify_msg2_mic_nonzero_nonce) {
  uint8_t snonce[32];
  memset(snonce, 0xAB, sizeof(snonce));
  auto f = fixtures::eapolKey(KI_MSG2, snonce, 121);
  CHECK_EQ(eapolKeyMessageNumber(f.data(), (int)f.size()), 2);
}

TEST(classify_msg3_ack_and_mic) {
  auto f = fixtures::eapolKey(KI_MSG3, nullptr, 121);
  CHECK_EQ(eapolKeyMessageNumber(f.data(), (int)f.size()), 3);
}

TEST(classify_msg4_mic_zero_nonce) {
  // Same Key Info as msg2 but the nonce is all zero -> msg4.
  uint8_t zero[32];
  memset(zero, 0, sizeof(zero));
  auto f = fixtures::eapolKey(KI_MSG4, zero, 121);
  CHECK_EQ(eapolKeyMessageNumber(f.data(), (int)f.size()), 4);
}

TEST(classify_rejects_non_eapol_key) {
  auto f = fixtures::eapolKey(KI_MSG1, nullptr, 121);
  f[1] = 0x00;  // not an EAPOL-Key packet type
  CHECK_EQ(eapolKeyMessageNumber(f.data(), (int)f.size()), 0);
}

TEST(classify_rejects_too_short) {
  auto f = fixtures::eapolKey(KI_MSG1, nullptr, 121);
  CHECK_EQ(eapolKeyMessageNumber(f.data(), 3), 0);
}

TEST(key_version_from_key_info) {
  auto f = fixtures::eapolKey(0x010A, nullptr, 121);  // version bits = 2
  CHECK_EQ(eapolKeyVersion(f.data(), (int)f.size()), 2);
}

TEST(nonce_and_mic_extraction) {
  uint8_t nonce[32];
  for (int i = 0; i < 32; i++) nonce[i] = (uint8_t)(i + 1);
  auto f = fixtures::eapolKey(KI_MSG2, nonce, 121);
  // Place a recognisable MIC at offset 81.
  for (int i = 0; i < 16; i++) f[81 + i] = (uint8_t)(0xF0 + i);

  uint8_t gotNonce[32];
  CHECK(eapolKeyNonce(f.data(), (int)f.size(), gotNonce));
  CHECK_BYTES(gotNonce, nonce, 32);

  uint8_t gotMic[16];
  uint8_t wantMic[16];
  for (int i = 0; i < 16; i++) wantMic[i] = (uint8_t)(0xF0 + i);
  CHECK(eapolKeyMic(f.data(), (int)f.size(), gotMic));
  CHECK_BYTES(gotMic, wantMic, 16);
}

TEST(nonce_mic_reject_short_buffers) {
  auto f = fixtures::eapolKey(KI_MSG2, nullptr, 121);
  uint8_t out32[32];
  uint8_t out16[16];
  CHECK(!eapolKeyNonce(f.data(), 20, out32));  // < 49
  CHECK(!eapolKeyMic(f.data(), 90, out16));     // < 97
}

TEST(eapol_offset_in_dot11_non_qos) {
  auto eapol = fixtures::eapolKey(KI_MSG1, nullptr, 121);
  auto frame = fixtures::dot11WithEapol(eapol, /*qos=*/false);
  int off = eapolOffsetIn80211(frame.data(), (int)frame.size(),
                               dataHeaderLen(frame[0]));
  CHECK_EQ(off, 32);  // 24-byte header + 8-byte LLC/SNAP
}

TEST(eapol_offset_in_dot11_qos) {
  auto eapol = fixtures::eapolKey(KI_MSG1, nullptr, 121);
  auto frame = fixtures::dot11WithEapol(eapol, /*qos=*/true);
  int off = eapolOffsetIn80211(frame.data(), (int)frame.size(),
                               dataHeaderLen(frame[0]));
  CHECK_EQ(off, 34);  // 26-byte QoS header + 8-byte LLC/SNAP
}

TEST(eapol_offset_rejects_non_eapol_ethertype) {
  auto eapol = fixtures::eapolKey(KI_MSG1, nullptr, 121);
  auto frame = fixtures::dot11WithEapol(eapol, false);
  frame[24 + 7] = 0x00;  // break the 0x888E ethertype
  CHECK_EQ(eapolOffsetIn80211(frame.data(), (int)frame.size(), 24), -1);
}

TEST(classify_through_dot11_frame) {
  // End-to-end: 802.11 data frame -> EAPOL offset -> message number.
  uint8_t snonce[32];
  memset(snonce, 0x5A, sizeof(snonce));
  auto eapol = fixtures::eapolKey(KI_MSG2, snonce, 121);
  auto frame = fixtures::dot11WithEapol(eapol, true);
  int hdr = dataHeaderLen(frame[0]);
  int off = eapolOffsetIn80211(frame.data(), (int)frame.size(), hdr);
  CHECK(off > 0);
  int avail = (int)frame.size() - off;
  CHECK_EQ(eapolKeyMessageNumber(frame.data() + off, avail), 2);
}
