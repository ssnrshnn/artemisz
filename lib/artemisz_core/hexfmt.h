// hexfmt.h — Pure byte->hex formatting helpers.
//
// Mirrors the formatting done ad-hoc in src/main.cpp (bytesToStr for MAC
// addresses, and the PMKID hex dump). Kept framework-free so it is testable on
// the host; the firmware's Arduino-String bytesToStr() can be layered on top.
#pragma once

#include <cstddef>
#include <cstdint>

namespace artemisz {

// Format `n` bytes as lowercase hex into `out`. When `colon` is true, bytes are
// separated by ':' (e.g. "aa:bb:cc"). `out` must hold at least
//   n*2 + (colon ? n-1 : 0) + 1   bytes (including the NUL terminator).
// Returns the number of characters written (excluding the NUL).
size_t bytesToHex(const uint8_t* bytes, size_t n, char* out, bool colon);

}  // namespace artemisz
