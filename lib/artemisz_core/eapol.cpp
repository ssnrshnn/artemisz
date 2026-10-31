#include "eapol.h"

#include <cstring>

namespace artemisz {

int eapolOffsetIn80211(const uint8_t* frame, int len, int hdrLen) {
  if (frame == nullptr || hdrLen < 0) return -1;
  // Need the 8-byte LLC/SNAP header after the MAC header.
  if (len < hdrLen + 8) return -1;
  const uint8_t* s = frame + hdrLen;
  // AA AA 03 (LLC) <OUI 3 bytes> 88 8E (EAPOL ethertype)
  if (s[0] == 0xAA && s[1] == 0xAA && s[2] == 0x03 && s[6] == 0x88 &&
      s[7] == 0x8E) {
    return hdrLen + 8;
  }
  return -1;
}

uint16_t eapolKeyInfo(const uint8_t* e, int avail) {
  if (e == nullptr || avail < 7) return 0;
  return ((uint16_t)e[5] << 8) | e[6];
}

static bool isEapolKey(const uint8_t* e, int avail) {
  // e[1] == 0x03 is the 802.1X "EAPOL-Key" packet type.
  return e != nullptr && avail >= 7 && e[1] == 0x03;
}

int eapolKeyMessageNumber(const uint8_t* e, int avail) {
  if (!isEapolKey(e, avail)) return 0;

  uint16_t keyInfo = eapolKeyInfo(e, avail);
  bool hasAck = (keyInfo & KEYINFO_ACK) != 0;
  bool hasMic = (keyInfo & KEYINFO_KEY_MIC) != 0;

  if (hasAck && !hasMic) return 1;
  if (!hasAck && hasMic) {
    // Disambiguate msg2 (SNonce present) from msg4 (nonce zeroed). If the
    // nonce bytes are not fully available we conservatively treat it as msg4,
    // matching the original firmware behaviour.
    bool nonceZero = true;
    if (avail >= 17 + 32) {
      for (int n = 0; n < 32; n++) {
        if (e[17 + n] != 0) { nonceZero = false; break; }
      }
    }
    return nonceZero ? 4 : 2;
  }
  if (hasAck && hasMic) return 3;
  return 0;
}

uint8_t eapolKeyVersion(const uint8_t* e, int avail) {
  return (uint8_t)(eapolKeyInfo(e, avail) & KEYINFO_VERSION);
}

bool eapolKeyNonce(const uint8_t* e, int avail, uint8_t out[32]) {
  if (e == nullptr || avail < 17 + 32) return false;
  memcpy(out, e + 17, 32);
  return true;
}

bool eapolKeyMic(const uint8_t* e, int avail, uint8_t out[16]) {
  if (e == nullptr || avail < 81 + 16) return false;
  memcpy(out, e + 81, 16);
  return true;
}

bool extractPmkid(const uint8_t* e, int avail, uint8_t out[16]) {
  // Key Data Length lives at e[97..98]; Key Data starts at e[99].
  if (e == nullptr || avail < 99) return false;
  uint16_t keyDataLen = ((uint16_t)e[97] << 8) | e[98];
  if (keyDataLen < 22) return false;          // KDE is DD 14 00 0F AC 04 + 16
  if (avail < 99 + (int)keyDataLen) return false;

  for (int k = 99; k <= 99 + (int)keyDataLen - 22; k++) {
    // 0xDD = vendor-specific element; OUI 00:0F:AC, type 0x04 = PMKID KDE.
    if (e[k] == 0xDD && e[k + 2] == 0x00 && e[k + 3] == 0x0F &&
        e[k + 4] == 0xAC && e[k + 5] == 0x04) {
      memcpy(out, e + k + 6, 16);
      return true;
    }
  }
  return false;
}

}  // namespace artemisz
