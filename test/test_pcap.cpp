#include "pcap.h"

#include "test_framework.h"

using namespace artemisz;

TEST(pcap_global_header_bytes) {
  uint8_t h[PCAP_GLOBAL_HEADER_LEN];
  pcapGlobalHeader(h);
  const uint8_t want[PCAP_GLOBAL_HEADER_LEN] = {
      0xD4, 0xC3, 0xB2, 0xA1,  // magic (LE, microseconds)
      0x02, 0x00, 0x04, 0x00,  // version 2.4
      0x00, 0x00, 0x00, 0x00,  // thiszone
      0x00, 0x00, 0x00, 0x00,  // sigfigs
      0xFF, 0xFF, 0x00, 0x00,  // snaplen 65535
      0x69, 0x00, 0x00, 0x00   // linktype 105 = IEEE 802.11
  };
  CHECK_BYTES(h, want, PCAP_GLOBAL_HEADER_LEN);
}

TEST(pcap_record_header_little_endian) {
  uint8_t h[PCAP_RECORD_HEADER_LEN];
  pcapRecordHeader(h, 0x11223344, 0x55667788, 100, 100);
  const uint8_t want[PCAP_RECORD_HEADER_LEN] = {
      0x44, 0x33, 0x22, 0x11,  // ts_sec LE
      0x88, 0x77, 0x66, 0x55,  // ts_usec LE
      0x64, 0x00, 0x00, 0x00,  // caplen 100 LE
      0x64, 0x00, 0x00, 0x00   // origlen 100 LE
  };
  CHECK_BYTES(h, want, PCAP_RECORD_HEADER_LEN);
}
