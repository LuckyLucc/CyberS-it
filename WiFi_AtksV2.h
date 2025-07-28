#ifndef SNIFFER_H
#define SNIFFER_H

#include <WiFi.h>
#include <WiFiType.h>
#include <esp_wifi.h>
#include <esp_wifi_types.h>
#include <esp_event.h>
#include <esp_err.h>
#include <lwip/sockets.h>

// Strutture dati
typedef struct {
    uint8_t MAC[6];
    uint8_t channel;
    
    bool operator<(const BeaconList &other) const {
        return memcmp(MAC, other.MAC, 6) < 0;
    }
} BeaconList;

typedef struct {
    String ssid;
    uint8_t bssid[6];
    int8_t rssi;
    wifi_auth_mode_t authmode;
    uint8_t channel;
} WiFiNetwork;

typedef struct {
    String ssid;
    String password;
    bool success;
} BruteForceAttempt;

// Variabili globali estern
extern std::set<String> saved_handshakes;
extern std::set<BeaconList> registered_beacons;
extern std::vector<WiFiNetwork> scannedNetworks;
extern WiFiNetwork* targetNetwork;
extern bool isConnected;
extern bool bruteForceRunning;
extern bool mitmActive;
extern bool floodActive;

// Funzioni di sniffing base
void sniffer_setup();
void sniffer(void *buf, wifi_promiscuous_pkt_type_t type);
bool isEapolPacket(const wifi_promiscuous_pkt_t *packet);
void saveHandshake(const wifi_promiscuous_pkt_t *packet, bool is_beacon, FS &fs);
void openNewPcapFile(FS &fs);
void performDeauth();

// Funzioni di scansione WiFi
void scanWiFiNetworks();
void displayScannedNetworks();

// Funzioni di connessione
bool connectToWiFi(const char* ssid, const char* password);
String keyboardInput();

// Funzioni di brute force
void bruteForceAttack();
std::vector<String> loadCommonPasswords();

// Funzioni di attacco
void performMITMAttack();
void performFloodAttack(const char* type);

// Funzioni di interfaccia utente
void displayMainMenu();
void handleUserInput();

// Utility
void updateDisplay();

#endif // SNIFFER_H