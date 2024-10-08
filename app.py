from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
import time

# Dictionary to count SYN packets from each IP address
syn_packets = defaultdict(int)
packet_lengths = defaultdict(list)
tcp_retransmissions = defaultdict(int)

def extract_packet_info(packet):
    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        src_ip = ip_layer.src # Source IP
        dst_ip = ip_layer.dst # Destination IP
        packet_length = len(packet)  # Length of the packet
        ttl = ip_layer.ttl  # Time-to-live value
        
        print(f"Packet: {src_ip} -> {dst_ip}, Length: {packet_length}, TTL: {ttl}")

        # Store packet length for analysis
        packet_lengths[src_ip].append(packet_length)

        protocol = ip_layer.proto # Protocol type
        print(f"  Protocol: {protocol}")

        # Detect SYN packets
        if packet.haslayer(TCP):
            tcp_layer = packet.getlayer(TCP)
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            flags = tcp_layer.flags
            
            print(f"  TCP: {src_port} -> {dst_port}, Flags: {flags}")
            # Detect SYN packets
            if flags == 'S':
                syn_packets[src_ip] += 1
                print(f"  SYN packet detected from {src_ip}, Count: {syn_packets[src_ip]}")
                if syn_packets[src_ip] > 20:
                    print(f"  Potential scan detected from {src_ip}")
            # Detect retransmissions
            elif flags == 'R':
                tcp_retransmissions[src_ip] += 1
                print(f"  Retransmission detected from {src_ip}, Count: {tcp_retransmissions[src_ip]}")

        # Detect UDP
        elif packet.haslayer(UDP):
            udp_layer = packet.getlayer(UDP)
            src_port = udp_layer.sport
            dst_port = udp_layer.dport
            print(f"  UDP: {src_port} -> {dst_port}")
            
# Sniff function with promiscuous mode enabled
def start_sniffing(interface):
    print(f"Listening on {interface} in promiscuous mode...")
    sniff(iface=interface, prn=extract_packet_info, promisc=True)

if __name__ == "__main__":
    # Replace this with the correct interface name for your network
    interface = "Wi-Fi"
    start_sniffing(interface)
