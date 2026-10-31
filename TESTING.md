# Testing & the `artemisz_core` library

The protocol-parsing and file-serialization logic that used to live inline in
`src/main.cpp` has been extracted into a small, **hardware-independent** C++
library under [`lib/artemisz_core/`](lib/artemisz_core). It has no Arduino or
ESP-IDF dependencies, so it compiles and runs on a normal desktop and can be
unit-tested without an ESP32 or any RF activity.

This is the part of the firmware whose correctness is worth *demonstrating*
(e.g. in a paper or report): the 4-way-handshake parser, PMKID extraction, and
the PCAP / HCCAPX exports are all validated against their documented on-wire
byte layouts.

## Modules

| File | Responsibility |
|------|----------------|
| `frame80211.h` | IEEE 802.11 Frame Control decoding (type/subtype, QoS header length) |
| `eapol.h` / `.cpp` | EAPOL-Key demux, 4-way handshake message classification (msg 1–4), key nonce/MIC/version, RSN PMKID extraction |
| `pcap.h` / `.cpp` | libpcap global + per-record header serialization (LINKTYPE_IEEE802_11) |
| `hccapx.h` / `.cpp` | Hashcat HCCAPX v4 (mode 2500) 393-byte record builder |
| `hexfmt.h` / `.cpp` | Byte → hex formatting (MAC strings, PMKID dumps) |

## Running the tests

No PlatformIO required — only a C++11 compiler:

```sh
make test
```

Example output:

```
Running 30 test(s)...
[PASS] classify_msg1_ack_no_mic
...
77 check(s), 0 failure(s)
```

Under PlatformIO (uses the same sources):

```sh
pio test -e native
```

CI (`.github/workflows/ci.yml`) runs the native suite on every push/PR and, in
a separate job, builds the ESP32 firmware.

## Test framework

A ~90-line header-only harness (`test/test_framework.h`) provides self-registering
`TEST(...)` blocks and `CHECK` / `CHECK_EQ` / `CHECK_BYTES` macros. It is
deliberately dependency-free so the suite behaves identically on a laptop and in
CI. Fixtures for synthetic EAPOL / 802.11 frames live in `test/fixtures.h`.

## Status / next step

The library is fully tested in isolation. The next refactor step is to make
`src/main.cpp` *call* these functions (single source of truth) in its
promiscuous RX callback and PCAP/HCCAPX download handlers, replacing the inline
byte-twiddling. That change must be compile-verified against the ESP32 target
(`pio run -e esp32dev`), which the CI firmware-build job now covers.
