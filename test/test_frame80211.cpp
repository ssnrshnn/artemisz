#include "frame80211.h"
#include "test_framework.h"

using namespace artemisz;

TEST(frame_type_and_subtype) {
  // 0x80 = beacon (type 0 mgmt, subtype 8).
  CHECK_EQ(fcType(0x80), TYPE_MGMT);
  CHECK_EQ(fcSubtype(0x80), MGMT_BEACON);
  // 0x40 = probe request (subtype 4).
  CHECK_EQ(fcSubtype(0x40), MGMT_PROBE_REQ);
  // 0xC0 = deauth (subtype 12).
  CHECK_EQ(fcSubtype(0xC0), MGMT_DEAUTH);
  // 0xA0 = disassoc (subtype 10).
  CHECK_EQ(fcSubtype(0xA0), MGMT_DISASSOC);
  // 0x08 = data (type 2, subtype 0).
  CHECK_EQ(fcType(0x08), TYPE_DATA);
}

TEST(data_header_len_qos_vs_non_qos) {
  CHECK_EQ(dataHeaderLen(0x08), 24);  // normal data (subtype 0)
  CHECK_EQ(dataHeaderLen(0x88), 26);  // QoS data (subtype 8)
  CHECK(isQoSData(0x88));
  CHECK(!isQoSData(0x08));
}

TEST(predicates) {
  CHECK(isBeacon(0x80));
  CHECK(isProbeReq(0x40));
  CHECK(isDeauthOrDisassoc(0xC0));
  CHECK(isDeauthOrDisassoc(0xA0));
  CHECK(!isDeauthOrDisassoc(0x80));
}
