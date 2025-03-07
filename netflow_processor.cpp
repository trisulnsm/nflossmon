// (c) 2025 Trisul Network Analytics
#include "netflow_processor.h"
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <cstring>
#include <iomanip>
#include <arpa/inet.h>  // For inet_ntop

NetflowProcessor::NetflowProcessor(uint32_t snapshot_window, int datalink_type, bool treat_ipfix_as_v9) 
    : last_print_time(0), snapshot_window(snapshot_window), datalink_type(datalink_type), treat_ipfix_as_v9(treat_ipfix_as_v9) {}

NetflowProcessor::~NetflowProcessor()
{
    last_print_time = last_packet_time;
    print_stats();
}

void NetflowProcessor::process_packet(const u_char* packet, const struct pcap_pkthdr* pkthdr) {
    int link_header_length;
    switch (datalink_type) {  // This needs to be a class member
        case DLT_EN10MB:    // Ethernet
            link_header_length = 14;
            break;
        case DLT_NULL:      // BSD loopback
            link_header_length = 4;
            break;
        case DLT_LINUX_SLL: // Linux cooked capture
            link_header_length = 16;
            break;
        case DLT_RAW:       // Raw IP
            link_header_length = 0;
            break;
        default:
            std::cerr << "Unsupported data link type: " << datalink_type << std::endl;
            return;
    }
    
    const u_char* ip_header = packet + link_header_length;
    
    // Parse IP header
    const struct ip* ip = reinterpret_cast<const struct ip*>(ip_header);
    int ip_header_len = ip->ip_hl * 4;

    // Parse UDP header
    const u_char* udp_header = ip_header + ip_header_len;
    [[maybe_unused]] const struct udphdr* udp = reinterpret_cast<const struct udphdr*>(udp_header);
    
    // Get NetFlow/IPFIX data
    const u_char* netflow_data = udp_header + sizeof(struct udphdr);
    
    // Determine the version
    uint16_t version = ntohs(*reinterpret_cast<const uint16_t*>(netflow_data));

    uint32_t sequence = 0;
    uint32_t source_id = 0;
    uint32_t nflows = 0; 
    bool valid_packet = false;

    if (version == 5) {
        // Parse NetFlow v5 header
        const NetflowV5Header* header = reinterpret_cast<const NetflowV5Header*>(netflow_data);
        sequence = ntohl(header->flow_sequence);
        nflows = ntohs(header->count);
        valid_packet = true;
    } else if (version == 9) {
        // Parse NetFlow v9 header
        const NetflowV9Header* header = reinterpret_cast<const NetflowV9Header*>(netflow_data);
        sequence = ntohl(header->sequence_number);
        source_id = ntohl(header->source_id);
        nflows = 1;
        valid_packet = true;
    } else if (version == 10) {
        const IPFIXHeader* header = reinterpret_cast<const IPFIXHeader*>(netflow_data);
        sequence = ntohl(header->sequence_number);
        source_id = ntohl(header->domain_id);
        
        // Calculate actual number of flows
        if (treat_ipfix_as_v9) {
            nflows = 1;
        } else { 
            nflows = ipfix_tracker.calculate_flows(
                netflow_data + sizeof(IPFIXHeader), 
                ntohs(header->length) - sizeof(IPFIXHeader)
            );  
        }
        
        valid_packet = nflows > 0;
    }


    if (valid_packet) {
        // Get the source IP address
        char src_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip->ip_src), src_ip, INET_ADDRSTRLEN);

        // Use the timestamp from pcap_pkthdr
        uint32_t timestamp = pkthdr->ts.tv_sec;

        // Initialize last_print_time if it's the first packet 
        if (last_print_time == 0) {
            last_print_time = timestamp - (timestamp % snapshot_window);
        }

        // Create the key using the IP address and source ID
        RouterKey key = {src_ip, source_id};

        check_sequence_gap(key, sequence, timestamp, version, nflows);

        last_packet_time = timestamp;
    }

}

void NetflowProcessor::check_sequence_gap(
                    const RouterKey& key, 
                    uint32_t sequence_number, 
                    uint32_t timestamp, 
                    uint16_t version, 
                    uint16_t nflows) {
    // If this is a new key, initialize its stats
    if (source_stats.find(key) == source_stats.end()) {
        source_stats[key] = {sequence_number, sequence_number, nflows, nflows, version};  // Initialize with first sequence and version
        return;
    }

    auto& stats = source_stats[key];
    stats.version = version;  // Update version (in case it changes)

    // Update highest and lowest sequence numbers
    if (sequence_number > stats.highest_sequence) {
        stats.highest_sequence = sequence_number;
    }
    if (sequence_number < stats.lowest_sequence) {
        stats.lowest_sequence = sequence_number; 
    }

    stats.received_packets += nflows;
    stats.expected_packets = stats.highest_sequence - stats.lowest_sequence + nflows;

    // Check if we need to print stats for all keys
    if (timestamp - last_print_time >= snapshot_window) {
        last_print_time = timestamp;  // Update last print time
        print_stats();
    }
}

// This is called every t seconds to dump the entire stats
void NetflowProcessor::print_and_reset_stats(const RouterKey& key, PacketStats& stats) {

    
    double loss_percent = 100.0 * (stats.expected_packets - stats.received_packets) / stats.expected_packets;

    // ANSI escape codes for colors
    const char* RED = "\033[31m";
    const char* RESET = "\033[0m";

    // Print in fixed-width format with color if loss exceeds 5%
    if (loss_percent > 5.0) {
        std::cout << RED;  // Start red color
    }

    // Format version string (v5, v9, or v10/IPFIX)
    std::string version_str = "v" + std::to_string(stats.version);
    if (stats.version == 10) {
        version_str = "IPFIX";
    }

    std::cout << std::left << std::setw(18) << key.ip_address
              << std::setw(10) << version_str
              << std::setw(12) << key.source_id
              << std::setw(10) << std::fixed << std::setprecision(2) << loss_percent
              << std::setw(10) << stats.expected_packets
              << std::setw(10) << stats.received_packets;

    if (loss_percent > 5.0) {
        std::cout << RESET;  // Reset color
    }

    std::cout << std::endl;
    std::cout << std::flush; 
    
    // Reset counters but keep the version
    uint16_t version = stats.version;
    stats.highest_sequence = 0;
    stats.lowest_sequence = UINT32_MAX;
    stats.received_packets = 0;
    stats.expected_packets= 0;
    stats.version = version;
}
void NetflowProcessor::print_stats()
{
    std::cout << std::endl;
    // Convert Unix timestamp to readable format
    time_t raw_time = last_print_time;
    struct tm* timeinfo = localtime(&raw_time);
    char time_buffer[80];
    strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S", timeinfo);
    std::cout << "At: " << time_buffer << std::endl;

    std::cout << std::left << std::setw(18) << "Device"
                << std::setw(10) << "Version"
                << std::setw(12) << "Source ID"
                << std::setw(10) << "Loss (%)"
                << std::setw(10) << "Expected"
                << std::setw(10) << "Received" << std::endl;

    for (auto& [k, s] : source_stats) {
        // only if packets are received
        if (s.received_packets > 0) {
            print_and_reset_stats(k, s);
        }
    }
}
