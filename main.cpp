#include <pcap.h>
#include <iostream>
#include <cstdint>
#include <string>
#include <vector>
#include "netflow_processor.h"

void print_usage(const char* program_name) {
    std::cout << "Usage: " << program_name << " [-i interface | -f file] [-p port] [-t snapshot_window]\n";
    std::cout << "Options:\n";
    std::cout << "  -i interface  Listen on network interface\n";
    std::cout << "  -f file       Read from pcap file\n";
    std::cout << "  -p port       Port number to filter (default: 2055)\n";
    std::cout << "  -t snapshot_window  Snapshot window in seconds (default: 60)\n";
}

void packet_handler(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    NetflowProcessor* processor = reinterpret_cast<NetflowProcessor*>(user_data);
    processor->process_packet(packet, pkthdr);
}

int main(int argc, char* argv[]) {
    std::string input_source;
    bool is_interface = false;
    int port = 2055;  // Default port for NetFlow
    uint32_t snapshot_window = 60;  // Default snapshot window

    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-i" && i + 1 < argc) {
            input_source = argv[++i];
            is_interface = true;
        } else if (arg == "-f" && i + 1 < argc) {
            input_source = argv[++i];
            is_interface = false;
        } else if (arg == "-p" && i + 1 < argc) {
            port = std::stoi(argv[++i]);
        } else if (arg == "-t" && i + 1 < argc) {
            snapshot_window = std::stoi(argv[++i]);
        } else {
            print_usage(argv[0]);
            return 1;
        }
    }

    if (input_source.empty()) {  // Only check for input source, port has default
        print_usage(argv[0]);
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;

    // Open capture handle
    if (is_interface) {
        handle = pcap_open_live(input_source.c_str(), BUFSIZ, 1, 1000, errbuf);
    } else {
        handle = pcap_open_offline(input_source.c_str(), errbuf);
    }

    if (handle == nullptr) {
        std::cerr << "Error opening source: " << errbuf << std::endl;
        return 2;
    }

    // Set up port filter
    std::string filter = "port " + std::to_string(port);
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Error compiling filter: " << pcap_geterr(handle) << std::endl;
        return 2;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "Error setting filter: " << pcap_geterr(handle) << std::endl;
        return 2;
    }

    NetflowProcessor processor(snapshot_window);
    pcap_loop(handle, 0, packet_handler, reinterpret_cast<u_char*>(&processor));

    pcap_freecode(&fp);
    pcap_close(handle);
    return 0;
} 