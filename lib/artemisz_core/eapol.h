// eapol.h — Pure parser for the WPA/WPA2 4-way handshake (EAPOL-Key frames)
// and RSN PMKID extraction.
//
// All functions operate on a pointer to the start of the EAPOL packet (the
// 802.1X "version" byte) together with the number of bytes available from
// that pointer. The 802.11 framing / LLC-SNAP demux lives in
// eapolOffsetIn80211() so the message logic itself stays framing-agnostic and
// unit-testable (see test/test_eapol.cpp).
//
// Byte layout of an EAPOL-Key frame, relative to the EAPOL start `e`:
//   e[0]      802.1X version
//   e[1]      802.1X packet type (0x03 = EAPOL-Key)
//   e[2..3]   packet body length
//   e[4]      descriptor type
//   e[5..6]   Key Information (big-endian)
//   e[7..8]   Key Length
//   e[9..16]  Replay Counter
//   e[17..48] Key Nonce (ANonce in msg1, SNonce in msg2, zero in msg4)
//   e[81..96] Key MIC
//   e[97..98] Key Data Length (big-endian)
//   e[99..]   Key Data (RSN PMKID KDE lives here in msg1)
#pragma once

#include <cstdint>

namespace artemisz {

// Key Information bit masks (within the 16-bit big-endian field at e[5..6]).
static const uint16_t KEYINFO_KEY_MIC = 0x0100;  // MIC present
static const uint16_t KEYINFO_ACK     = 0x0080;  // AP expects a response
static const uint16_t KEYINFO_VERSION = 0x0007;  // key descriptor version

// Returns the offset of the EAPOL packet within an 802.11 data frame, or -1 if
// the frame is not an EAPOL (0x888E) payload. `hdrLen` is the MAC header length
// (see frame80211.h dataHeaderLen). Checks the LLC/SNAP header
// AA AA 03 xx xx xx 88 8E.
int eapolOffsetIn80211(const uint8_t* frame, int len, int hdrLen);

// Read the 16-bit big-endian Key Information field. Returns 0 if out of range.
uint16_t eapolKeyInfo(const uint8_t* e, int avail);

// Classify a 4-way-handshake message: returns 1..4, or 0 if `e` is not a
// recognisable EAPOL-Key frame / is too short.
//   msg1: has ACK, no MIC
//   msg2: no ACK, has MIC, non-zero nonce (SNonce)
//   msg3: has ACK, has MIC
//   msg4: no ACK, has MIC, zero nonce
int eapolKeyMessageNumber(const uint8_t* e, int avail);

// Key descriptor version (1=HMAC-MD5/RC4, 2=HMAC-SHA1-AES, 3=AES-128-CMAC).
// Used as the hccapx `keyver`. Returns 0 if out of range.
uint8_t eapolKeyVersion(const uint8_t* e, int avail);

// Copy the 32-byte Key Nonce (e[17..48]). Returns false if out of range.
bool eapolKeyNonce(const uint8_t* e, int avail, uint8_t out[32]);

// Copy the 16-byte Key MIC (e[81..96]). Returns false if out of range.
bool eapolKeyMic(const uint8_t* e, int avail, uint8_t out[16]);

// Extract the RSN PMKID (OUI 00:0F:AC, type 04) from a msg1 Key Data blob.
// Returns true and fills `out` on success. Bounds-checked against `avail`.
bool extractPmkid(const uint8_t* e, int avail, uint8_t out[16]);

}  // namespace artemisz
