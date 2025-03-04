#include <pcap.h>
#include <iostream>
#include <cstdint>
#include <string>
#include <vector>
#include "netflow_processor.h"
#include <pwd.h>    // For getpwnam
#include <unistd.h> // For setuid, setgid, getopt
#include <getopt.h> // For getopt

void print_usage(const char* program_name) {
    std::cout << "Usage: " << program_name << " (-i interface | -f file) [-p port] [-t seconds] [-u user] [-h host]\n";
    std::cout << "Options:\n";
    std::cout << "  -i interface  Listen on network interface\n";
    std::cout << "  -f file       Read from pcap file\n";
    std::cout << "  -p port       Port number to filter (default: 2055)\n";
    std::cout << "  -t seconds    Snapshot window in seconds (default: 60)\n";
    std::cout << "  -u user       Drop privileges to this user after opening capture interface\n";
    std::cout << "  -h host       Filter by specific host IP address\n";
}

void packet_handler(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    NetflowProcessor* processor = reinterpret_cast<NetflowProcessor*>(user_data);
    processor->process_packet(packet, pkthdr);
}

bool drop_privileges(const std::string& username) {
    struct passwd* pw = getpwnam(username.c_str());
    if (pw == nullptr) {
        std::cerr << "Error: User '" << username << "' not found\n";
        return false;
    }

    // Drop group privileges first
    if (setgid(pw->pw_gid) != 0) {
        std::cerr << "Error: Failed to drop group privileges\n";
        return false;
    }

    // Drop user privileges
    if (setuid(pw->pw_uid) != 0) {
        std::cerr << "Error: Failed to drop user privileges\n";
        return false;
    }

    return true;
}

int main(int argc, char* argv[]) {
    std::string input_source;
    std::string username;
    std::string host_filter;
    bool is_interface = false;
    int port = 2055;  // Default port for NetFlow
    uint32_t snapshot_window = 60;  // Default snapshot window
    int opt;

    while ((opt = getopt(argc, argv, "i:f:p:t:u:h:")) != -1) {
        switch (opt) {
            case 'i':
                input_source = optarg;
                is_interface = true;
                break;
            case 'f':
                input_source = optarg;
                is_interface = false;
                break;
            case 'p':
                try {
                    port = std::stoi(optarg);
                } catch (const std::exception&) {
                    std::cerr << "Error: Invalid port number\n";
                    return 1;
                }
                break;
            case 't':
                try {
                    snapshot_window = std::stoi(optarg);
                } catch (const std::exception&) {
                    std::cerr << "Error: Invalid snapshot window\n";
                    return 1;
                }
                break;
            case 'u':
                username = optarg;
                break;
            case 'h':
                host_filter = optarg;
                break;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    // Validate required arguments
    if (input_source.empty()) {
        std::cerr << "Error: Must specify either -i interface or -f file\n";
        print_usage(argv[0]);
        return 1;
    }

    // Check if we need root for interface capture
    if (is_interface && geteuid() != 0) {
        std::cerr << "Error: Root privileges required for interface capture\n";
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

    // Set up port filter with optional host
    std::string filter;
    if (!host_filter.empty()) {
        filter = "host " + host_filter + " and port " + std::to_string(port);
    } else {
        filter = "port " + std::to_string(port);
    }

    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Error compiling filter: " << pcap_geterr(handle) << std::endl;
        return 2;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "Error setting filter: " << pcap_geterr(handle) << std::endl;
        return 2;
    }

    // Drop privileges if username is specified and we're capturing from interface
    if (is_interface && !username.empty()) {
        if (!drop_privileges(username)) {
            pcap_close(handle);
            return 3;
        }
        std::cout << "Dropped privileges to user: " << username << std::endl;
    }

    NetflowProcessor processor(snapshot_window);
    pcap_loop(handle, 0, packet_handler, reinterpret_cast<u_char*>(&processor));

    pcap_freecode(&fp);
    pcap_close(handle);
    return 0;
} 