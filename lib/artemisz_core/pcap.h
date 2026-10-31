// pcap.h — Pure serializers for libpcap (classic .pcap) capture files.
//
// Link type is LINKTYPE_IEEE802_11 (105 / 0xA9... no: value 105 = 0x69),
// matching what Wireshark expects for raw 802.11 management/data frames.
// Extracted from handlePcapDownload() in src/main.cpp so the on-wire byte
// layout can be asserted in a host unit test (see test/test_pcap.cpp).
#pragma once

#include <cstdint>

namespace artemisz {

static const int PCAP_GLOBAL_HEADER_LEN = 24;
static const int PCAP_RECORD_HEADER_LEN = 16;
static const uint32_t PCAP_LINKTYPE_IEEE802_11 = 105;

// Write the 24-byte little-endian global header: magic d4c3b2a1, version 2.4,
// snaplen 65535, linktype 105 (IEEE 802.11).
void pcapGlobalHeader(uint8_t out[PCAP_GLOBAL_HEADER_LEN]);

// Write a 16-byte per-packet record header. `caplen` is the number of captured
// bytes that follow; `origLen` is the original on-wire length.
void pcapRecordHeader(uint8_t out[PCAP_RECORD_HEADER_LEN], uint32_t tsSec,
                      uint32_t tsUsec, uint32_t capLen, uint32_t origLen);

}  // namespace artemisz
