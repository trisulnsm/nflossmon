// (c) 2025 Trisul Network Analytics
#pragma once
#include <cstdint>
#include <map>
#include <iostream>
#include <chrono>
#include <string>
#include <pcap.h> 
#include "ipfix_tracker.h"

struct NetflowV9Header {
    uint16_t version;
    uint16_t count;
    uint32_t sys_uptime;
    uint32_t unix_secs;
    uint32_t sequence_number;
    uint32_t source_id;
} __attribute__((packed));

struct NetflowV5Header {
    uint16_t version;
    uint16_t count;
    uint32_t sys_uptime;
    uint32_t unix_secs;
    uint32_t unix_nsecs;
    uint32_t flow_sequence;
    uint8_t engine_type;
    uint8_t engine_id;
    uint16_t sampling_interval;
} __attribute__((packed));

// New struct to represent the IPFIX header
struct IPFIXHeader {
    uint16_t version;          // Version number (should be 10 for IPFIX)
    uint16_t length;           // Length of the entire IPFIX message
    uint32_t export_time;      // Unix time when the first packet was exported
    uint32_t sequence_number;  // Sequence number of the export
    uint32_t domain_id;        // Observation domain ID
} __attribute__((packed));

// New struct to represent the key
struct RouterKey {
    std::string ip_address;
    uint32_t source_id;

    // Overload the < operator for std::map to work with RouterKey
    bool operator<(const RouterKey& other) const {
        return std::tie(ip_address, source_id) < std::tie(other.ip_address, other.source_id);
    }
};

struct PacketStats {
    uint32_t highest_sequence;
    uint32_t lowest_sequence;
    uint32_t received_packets;
    uint32_t expected_packets;
    uint16_t version;  // Added to track NetFlow version
};

class NetflowProcessor {
public:
    NetflowProcessor(uint32_t snapshot_window, int datalink_type, bool treat_ipfix_as_v9 = false);
    ~NetflowProcessor();

    void process_packet(const u_char* packet, const struct pcap_pkthdr* pkthdr);

private:
    void check_sequence_gap(const RouterKey& key, uint32_t sequence_number, uint32_t unix_secs, uint16_t version, uint16_t nflows);
    void print_and_reset_stats(const RouterKey& key, PacketStats& stats);

    void print_stats();

    std::map<RouterKey, PacketStats> source_stats;  // Use RouterKey as the key
    uint32_t last_print_time;  // when was last print  
    uint32_t last_packet_time; // last packet timestamp used for pcap reading/writing 
    uint32_t snapshot_window;  // New member for snapshot window
    static const int BUCKET_SECONDS = 10;
    CIPFIXTracker ipfix_tracker;
    int datalink_type;  // Add this member variable
    bool treat_ipfix_as_v9;  // Add this member variable
}; 