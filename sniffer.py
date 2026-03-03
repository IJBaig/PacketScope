import argparse
import sys
import os
from datetime import datetime
from scapy.all import sniff, PcapWriter
from scapy.layers.inet import IP, TCP, UDP, ICMP

packet_count = 0

def packet_callback(packet, log_file_writer=None):
    global packet_count
    packet_count += 1
    
    # We indent everything under this check so we don't try to pull 
    # IP addresses from packets that don't have an IP layer (like ARP packets)
    if packet.haslayer(IP):
        timestamp = datetime.fromtimestamp(packet.time)
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        size = len(packet)

        protocol_name = "Other"
        src_port = ""
        dst_port = ""

        if packet.haslayer(TCP):
            protocol_name = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

            if dst_port == 80 or src_port == 80:
                protocol_name = "HTTP"

        elif packet.haslayer(UDP):
            protocol_name = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

            if dst_port == 53 or src_port == 53:
                protocol_name = "DNS"

        elif packet.haslayer(ICMP):
            protocol_name = "ICMP"

        if src_port and dst_port:
            print(f"[{packet_count}] {timestamp} | {protocol_name} | {src_ip}:{src_port} -> {dst_ip}:{dst_port} | Size: {size} bytes")
        else:
            print(f"[{packet_count}] {timestamp} | {protocol_name} | {src_ip} -> {dst_ip} | Size: {size} bytes")

        if packet.haslayer("Raw"):
            try:
                payload = packet["Raw"].load.decode("utf-8", errors="ignore")
                clean_payload = payload.replace("\n", " ").replace("\r", " ")
                print(f"    Data: {clean_payload[:60]}")
            except Exception:
                print("    Data: [Binary Data]")

    # This needs to be inside the callback function, but outside the IP check 
    # so we can log all packets (even non-IP ones) if a writer is provided.
    if log_file_writer:
        log_file_writer.write(packet)

def start_sniffer(interface, bpf_filter, output_file, count):
    print("[*] Starting Sniffer")
    print(f"[*] Interface: {interface if interface else 'Default'}")
    print(f"[*] Filter: {bpf_filter if bpf_filter else 'None'}")
    print(f"[*] Packet Limit: {count if count else 'Unlimited'}")
    
    pcap_writer = None
    if output_file:
        print(f"[*] Logging to: {output_file}")
        pcap_writer = PcapWriter(output_file, append=True, sync=True)

    try:
        sniff(
            iface=interface,
            filter=bpf_filter,
            prn=lambda pkt: packet_callback(pkt, pcap_writer),
            store=0,
            count=count
        )
    except KeyboardInterrupt:
        print("\n[!] Stopping Sniffer")
    except Exception as e:
        print(f"\n[!] Error: {e}")
    finally:
        if pcap_writer:
            pcap_writer.close()
            print("[*] Log file closed")

# Fixed the entry point typo (was `name == "main"`)
if __name__ == "__main__":
    # Added a check to ensure this only runs on Linux/macOS before checking for root.
    # Windows doesn't use geteuid(), so the original code would crash on Windows.
    if os.name == 'posix' and os.geteuid() != 0:
        print("Run this script as root")
        sys.exit(1)

    # Indented the parser setup so it only runs when the script is executed directly
    parser = argparse.ArgumentParser(description="Advanced Python Network Sniffer")
    parser.add_argument("-i", "--iface", help="Interface to bind to", default=None)
    parser.add_argument("-f", "--filter", help="BPF Filter such as 'tcp port 80'", default=None)
    parser.add_argument("-o", "--output", help="Output file name such as capture.pcap", default=None)
    parser.add_argument("-c", "--count", type=int, help="Number of packets to capture", default=0)

    args = parser.parse_args()

    start_sniffer(args.iface, args.filter, args.output, args.count)
