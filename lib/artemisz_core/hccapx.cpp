#include "hccapx.h"

#include <cstring>

namespace artemisz {

bool buildHccapxRecord(uint8_t out[HCCAPX_RECORD_LEN], const HccapxInput& in) {
  if (out == nullptr) return false;
  if (in.macAp == nullptr || in.macSta == nullptr || in.anonce == nullptr ||
      in.snonce == nullptr || in.mic == nullptr || in.eapol == nullptr) {
    return false;
  }
  if (in.essidLen < 0 || in.eapolLen < 0) return false;

  memset(out, 0, HCCAPX_RECORD_LEN);

  // Signature "HCPX" + version 4 (LE).
  out[0] = 'H'; out[1] = 'C'; out[2] = 'P'; out[3] = 'X';
  out[4] = 0x04;  // bytes 5..7 remain zero => little-endian 4

  out[8] = in.messagePair;

  int essidLen = in.essidLen;
  if (essidLen > 32) essidLen = 32;
  out[9] = (uint8_t)essidLen;
  if (in.essid != nullptr && essidLen > 0) {
    memcpy(out + 10, in.essid, essidLen);
  }

  out[42] = in.keyver;
  memcpy(out + 43, in.mic, 16);
  memcpy(out + 59, in.macAp, 6);
  memcpy(out + 65, in.anonce, 32);
  memcpy(out + 97, in.macSta, 6);
  memcpy(out + 103, in.snonce, 32);

  int eapolLen = in.eapolLen;
  if (eapolLen > HCCAPX_EAPOL_MAX) eapolLen = HCCAPX_EAPOL_MAX;
  out[135] = (uint8_t)(eapolLen & 0xFF);
  out[136] = (uint8_t)((eapolLen >> 8) & 0xFF);
  if (eapolLen > 0) {
    memcpy(out + 137, in.eapol, eapolLen);
    // Hashcat expects the MIC field in the embedded EAPOL frame to be zeroed.
    // Need at least MIC_OFFSET+16 bytes present to zero the full 16-byte MIC.
    if (eapolLen >= HCCAPX_EAPOL_MIC_OFFSET + 16) {
      memset(out + 137 + HCCAPX_EAPOL_MIC_OFFSET, 0, 16);
    }
  }
  return true;
}

}  // namespace artemisz
