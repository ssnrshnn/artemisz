// frame80211.h — Pure, hardware-independent IEEE 802.11 frame field helpers.
//
// These were previously inlined inside the promiscuous RX callback in
// src/main.cpp. Extracted here so they can be unit-tested on the host
// (see test/test_frame80211.cpp) and shared as a single source of truth.
//
// No Arduino / ESP-IDF dependencies — compiles on the ESP32 target and on a
// desktop host alike.
#pragma once

#include <cstdint>

namespace artemisz {

// --- Frame Control field 0 (first byte of an 802.11 MAC header) ---

// Frame type: 0 = management, 1 = control, 2 = data.
inline uint8_t fcType(uint8_t fc0) { return (fc0 >> 2) & 0x03; }

// Frame subtype (0..15); meaning depends on type.
inline uint8_t fcSubtype(uint8_t fc0) { return (fc0 >> 4) & 0x0F; }

// Management subtypes we care about.
static const uint8_t MGMT_PROBE_REQ = 4;
static const uint8_t MGMT_BEACON    = 8;
static const uint8_t MGMT_DISASSOC  = 10;
static const uint8_t MGMT_AUTH      = 11;
static const uint8_t MGMT_DEAUTH    = 12;

static const uint8_t TYPE_MGMT = 0;
static const uint8_t TYPE_CTRL = 1;
static const uint8_t TYPE_DATA = 2;

// A QoS data frame carries a 2-byte QoS Control field, making the MAC header
// 26 bytes instead of 24. QoS data subtypes are 8..15.
inline bool isQoSData(uint8_t fc0) {
  return fcType(fc0) == TYPE_DATA && fcSubtype(fc0) >= 8;
}

// MAC header length for a *data* frame (24 normal, 26 for QoS).
// Mirrors the `isQoS ? 26 : 24` logic from the original sniffer callback.
inline int dataHeaderLen(uint8_t fc0) {
  return (fcSubtype(fc0) >= 8) ? 26 : 24;
}

// Convenience predicates.
inline bool isDeauthOrDisassoc(uint8_t fc0) {
  return fcType(fc0) == TYPE_MGMT &&
         (fcSubtype(fc0) == MGMT_DEAUTH || fcSubtype(fc0) == MGMT_DISASSOC);
}

inline bool isBeacon(uint8_t fc0) {
  return fcType(fc0) == TYPE_MGMT && fcSubtype(fc0) == MGMT_BEACON;
}

inline bool isProbeReq(uint8_t fc0) {
  return fcType(fc0) == TYPE_MGMT && fcSubtype(fc0) == MGMT_PROBE_REQ;
}

}  // namespace artemisz
