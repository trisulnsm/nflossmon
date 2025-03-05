# nflossmon

We at Trisul Network Analytics want to share the tool that we use to monitor NetFlow Telemetry from our customers. This tool is a simple out of band tool that listens directly to interface traffic and calculates packet loss statistics based on sequence number gaps. Since it is not based on opening a UDP port, it does not interfere with running software. 

Just use it to get a sense of the packet loss on your NetFlow/IPFIX interfaces, then stop it. 


It supports NetFlow v5, v9 and IPFIX (v10)  and calculates packet loss statistics based on sequence number gaps per observation domain. 

:pushpin:  For IPFIX, the tool uses the IPID field as the sequence number. Should suffice for most use cases. 

It can also read a PCAP file directly. 



## Usage

To print usage type 

```bash
./netflow_loss_monitor 
```
For examples see [Examples](#examples) section.

## Building

```bash
make release
```

### Features

- Supports NetFlow v5, v9 and IPFIX (v10) formats
- Tracks sequence numbers per source router/exporter
- Calculates packet loss percentage over configurable time windows
- Displays statistics including:
  - Source IP address
  - Source ID (for v9/IPFIX)
  - Version (v5, v9, IPFIX)
  - Packet loss percentage
  - Expected vs received packet counts
  - Timestamp for each reporting interval

 - Security: Drop privileges to this user after opening capture interface
 - Filter: Filter by specific host IP address and port

### Output Format

The tool prints statistics in a tabular format:

```
Timestamp: 2025-03-04 18:36:30
Device            Version   Source ID   Loss (%)  Expected  Received  
192.168.1.1       v9        200         0.00      496       496       
192.168.1.2       v9        256         0.00      819       819       

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
  -w <window>   Time window for packet loss calculation (default: 10 seconds)
  -f <file>     Output file for statistics (default: stdout)
  -u user       Drop privileges to this user after opening capture interface
  -h host       Filter by specific host IP address
```

## Examples

Reading a pcap file and printing every 10 seconds

```bash
./netflow_loss_monitor -w 10 -f input.pcap
```

Reading live traffic from an interface and printing every 10 seconds

Notice we are dropping privileges to the nobody user after opening the capture interface.

```bash
sudo ./netflow_loss_monitor -i eth0 -w 10 -u nobody
```

<p align="center">
  <img src="icon.svg" width="128" height="128" alt="NetFlow Loss Monitor Icon">
</p>

