# Advanced Python Network Sniffer

## Overview
This project is a command-line network sniffer built using Python and the Scapy library. It is designed to capture live network traffic, inspect protocols, preview payload data, and store packets in PCAP format for later analysis. 

This tool is targeted toward learning, lab environments, and authorized security testing.

## Features
* **Live Packet Capture:** Monitor network traffic in real-time.
* **Interface Selection:** Bind the sniffer to a specific network interface (e.g., `eth0`, `wlan0`).
* **BPF Filter Support:** Apply Berkeley Packet Filters to isolate specific traffic (e.g., specific ports or protocols).
* **Protocol Detection:** Automatically identifies TCP, UDP, and ICMP traffic, along with specific application-layer protocols like HTTP and DNS.
* **Detailed Packet Info:** Displays Source/Destination IPs, Ports, and Packet Size.
* **Timestamped Output:** Accurate logging for when each packet was captured.
* **Payload Preview:** Extracts and displays readable string data from raw packet payloads.
* **PCAP Logging:** Saves captured packets directly to a `.pcap` file for forensic review in tools like Wireshark.
* **Capture Limits:** Option to stop sniffing after a defined number of packets.
* **Graceful Shutdown:** Handles `Ctrl+C` cleanly without throwing terminal errors.
* **Privilege Enforcement:** Verifies root privileges before execution to prevent access errors.

## Requirements
* Linux / POSIX-compliant system (Recommended)
* Python 3.x
* Root privileges (sudo)
* `scapy` library

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/IJBaig/PacketScope
   cd PacketScope
   ```

2. **Install dependencies:**
   ```bash
   pip3 install -r requirements.txt
   ```

## Usage
*Note: Network sniffing requires low-level network access. You must run this script with root/administrator privileges.*

**Run with default settings (captures all traffic on default interface):**
```bash
sudo python3 sniffer.py
```

**Bind to a specific interface:**
```bash
sudo python3 sniffer.py -i eth0
```

**Apply a BPF filter (e.g., capture only HTTP traffic):**
```bash
sudo python3 sniffer.py -f "tcp port 80"
```

**Save captured packets to a PCAP file:**
```bash
sudo python3 sniffer.py -o capture.pcap
```

**Limit the number of captured packets (e.g., stop after 50 packets):**
```bash
sudo python3 sniffer.py -c 50
```

**Combine options:**
```bash
sudo python3 sniffer.py -i wlan0 -f "udp port 53" -o dns_logs.pcap -c 100
```

## Output Example
```text
[1] 2026-03-04 12:30:11 | TCP | 192.168.1.10:443 -> 142.250.190.78:52344 | Size: 74 bytes
    Data: GET / HTTP/1.1 Host: example.com
```

## Learning Objectives & Educational Value
This project demonstrates practical knowledge of:
* Network protocols and data encapsulation
* Packet-level traffic inspection and analysis
* Utilization of Berkeley Packet Filters (BPF)
* PCAP generation for digital forensics and incident response (DFIR)
* Secure Python scripting practices for security tooling
