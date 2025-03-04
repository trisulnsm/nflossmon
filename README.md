# nflossmon

We at Trisul Network Analytics want to share the tool that we use to monitor NetFlow Telemetry from our customers. This tool is a simple out of band tool that listens directly to interface traffic and calculates packet loss statistics based on sequence number gaps. Since it is not based on opening a UDP port, it does not interfere with running software. 

Just use it to get a sense of the packet loss on your NetFlow/IPFIX interfaces, then stop it. 


It supports NetFlow v5, v9 and IPFIX (v10)  and calculates packet loss statistics based on sequence number gaps per observation domain. 

It can also read a PCAP file directly. 


## Usage

```bash
./netflow_loss_monitor <pcap_file>
```

## Building

```bash
make
```

### Features

- Supports NetFlow v5, v9 and IPFIX (v10) formats
- Tracks sequence numbers per source router/exporter
- Calculates packet loss percentage over configurable time windows
- Displays statistics including:
  - Source IP address
  - Source ID (for v9/IPFIX)
  - Packet loss percentage
  - Expected vs received packet counts
  - Timestamp for each reporting interval

### Output Format

The tool prints statistics in a tabular format:

```
Source IP    Source ID    Loss %    Expected    Received    Timestamp
192.168.1.1  12345        10.00      1000        900         1618070400
192.168.1.2  67890        5.00       1000        995         1618070460
```

### Configuration

The tool is configurable via command line arguments:


### Arguments

```
Usage: ./netflow_loss_monitor [-i interface | -f file] [-p port] [-t snapshot_window]
Options:
  -i interface  Listen on network interface
  -f file       Read from pcap file
  -p port       Port number to filter (default: 2055)
  -t snapshot_window  Snapshot window in seconds (default: 60)
- `-w <window>`: Time window for packet loss calculation (default: 10 seconds)
- `-f <file>`: Output file for statistics (default: stdout)
```

### Example

```bash
./netflow_loss_monitor -w 10 -f input.pcap
```

This will calculate packet loss statistics over 10-second windows and save the results to `output.txt`.

<svg width="64" height="64" viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg">
  <!-- Background Circle -->
  <circle cx="32" cy="32" r="30" fill="#4CAF50" stroke="#388E3C" stroke-width="2"/>

  <!-- Network Node -->
  <circle cx="32" cy="32" r="8" fill="#FFFFFF" stroke="#388E3C" stroke-width="2"/>

  <!-- Flow Lines -->
  <line x1="32" y1="10" x2="32" y2="24" stroke="#FFFFFF" stroke-width="2" />
  <line x1="32" y1="40" x2="32" y2="54" stroke="#FFFFFF" stroke-width="2" />
  <line x1="10" y1="32" x2="24" y2="32" stroke="#FFFFFF" stroke-width="2" />
  <line x1="40" y1="32" x2="54" y2="32" stroke="#FFFFFF" stroke-width="2" />

  <!-- Arrows -->
  <polygon points="32,10 30,14 34,14" fill="#FFFFFF" />
  <polygon points="32,54 30,50 34,50" fill="#FFFFFF" />
  <polygon points="10,32 14,30 14,34" fill="#FFFFFF" />
  <polygon points="54,32 50,30 50,34" fill="#FFFFFF" />

  <!-- Magnifying Glass -->
  <circle cx="48" cy="48" r="6" fill="none" stroke="#FFFFFF" stroke-width="2"/>
  <line x1="52" y1="52" x2="58" y2="58" stroke="#FFFFFF" stroke-width="2"/>
</svg>
