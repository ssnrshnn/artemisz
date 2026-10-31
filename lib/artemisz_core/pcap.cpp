#include "pcap.h"

namespace artemisz {

static void writeLE32(uint8_t* p, uint32_t v) {
  p[0] = (uint8_t)(v & 0xFF);
  p[1] = (uint8_t)((v >> 8) & 0xFF);
  p[2] = (uint8_t)((v >> 16) & 0xFF);
  p[3] = (uint8_t)((v >> 24) & 0xFF);
}

static void writeLE16(uint8_t* p, uint16_t v) {
  p[0] = (uint8_t)(v & 0xFF);
  p[1] = (uint8_t)((v >> 8) & 0xFF);
}

void pcapGlobalHeader(uint8_t out[PCAP_GLOBAL_HEADER_LEN]) {
  // Magic number d4 c3 b2 a1 => little-endian, microsecond timestamps.
  out[0] = 0xD4; out[1] = 0xC3; out[2] = 0xB2; out[3] = 0xA1;
  // Version major 2, minor 4.
  writeLE16(out + 4, 2);
  writeLE16(out + 6, 4);
  // thiszone (GMT offset) + sigfigs: both zero.
  writeLE32(out + 8, 0);
  writeLE32(out + 12, 0);
  // snaplen 65535.
  writeLE32(out + 16, 65535);
  // network / link-layer type.
  writeLE32(out + 20, PCAP_LINKTYPE_IEEE802_11);
}

void pcapRecordHeader(uint8_t out[PCAP_RECORD_HEADER_LEN], uint32_t tsSec,
                      uint32_t tsUsec, uint32_t capLen, uint32_t origLen) {
  writeLE32(out + 0, tsSec);
  writeLE32(out + 4, tsUsec);
  writeLE32(out + 8, capLen);
  writeLE32(out + 12, origLen);
}

}  // namespace artemisz
