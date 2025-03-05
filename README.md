# nflossmon

We at Trisul Network Analytics want to give back to the community a valuable tool that we use to monitor NetFlow Telemetry from our customers. This tool is a simple out of band tool that listens directly to interface traffic and calculates loss statistics based on sequence number gaps. Since it is not based on opening a UDP port, it does not interfere with running software. 

Just use it to get a sense of the packet loss on your NetFlow/IPFIX interfaces.


It supports NetFlow v5, v9 and IPFIX (v10)  

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
- Calculates loss percentage over configurable time windows
- Displays statistics including:
  - Source IP address
  - Source ID (for v9/IPFIX)
  - Version (v5, v9, IPFIX)
  - Flow Loss percentage 
  - Expected vs received packet counts
  - Timestamp for each reporting interval
 - Security: Drop privileges to this user after opening capture interface
 - Filter: Filter by specific host IP address and port

> :pushpin:  **IPFIX note** For IPFIX, the tool tracks templates and computes the flow gaps as specified in the IPFIX protocol RFC 7011. However some vendors increment the sequence number for each packet rather than for each flow. The option `--ipfix-as-v9` can be used to treat IPFIX as NetFlow v9 for such cases. 

It can also read a PCAP file directly. 

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
  -t reportsecs Reporting window in seconds (default: 60)
  -f <file>     Output file for statistics (default: stdout)
  -u user       Drop privileges to this user after opening capture interface
  -h host       Filter by specific host IP address
  --ipfix-as-v9 Treat IPFIX (v10) as NetFlow v9
```

## Examples

Reading a pcap file and printing report  every 10 seconds

```bash
./netflow_loss_monitor -f input.pcap -t  10 
```

Reading live traffic from an interface 

Notice we are dropping privileges to the `nobody` user after opening the capture interface.

```bash
sudo ./netflow_loss_monitor -i eth0 -u nobody
```

<p align="center">
  <img src="icon.svg" width="128" height="128" alt="NetFlow Loss Monitor Icon">
</p>

