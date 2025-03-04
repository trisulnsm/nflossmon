#pragma once
#include <cstdint>
#include <map>
#include <iostream>
#include <chrono>
#include <string>
#include <pcap.h> 

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
};

class NetflowProcessor {
public:
    NetflowProcessor(uint32_t snapshot_window = 60);  // Default to 60 seconds
    void process_packet(const u_char* packet, const struct pcap_pkthdr* pkthdr);

private:
    void check_sequence_gap(const RouterKey& key, uint32_t sequence_number, uint32_t unix_secs);
    void print_and_reset_stats(const RouterKey& key, PacketStats& stats);
    std::map<RouterKey, PacketStats> source_stats;  // Use RouterKey as the key
    uint32_t last_print_time;  // Moved to NetflowProcessor class
    uint32_t snapshot_window;  // New member for snapshot window
    static const int BUCKET_SECONDS = 10;
}; 