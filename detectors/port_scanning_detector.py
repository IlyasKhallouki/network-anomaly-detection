from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
import time
from utilities.logger import Logger


class PortScanningDetector:
    def __init__(self, threshold=10, time_window=10, verbose=False):
        self.threshold = threshold  # Threshold for port scanning detection
        self.time_window = time_window  # Time window to count packets
        self.packet_count = defaultdict(int)  # Count of packets per source IP
        self.packet_lengths = defaultdict(list)  # Store packet lengths for each IP
        self.syn_packets = defaultdict(int)  # Count of SYN packets per source IP
        self.tcp_retransmissions = defaultdict(int)  # Count of TCP retransmissions
        self.start_time = time.time()
        self.logger = Logger()
        self.verbose = verbose

    def extract_packet_info(self, packet):
        """Extract information from packets and detect anomalies."""
        if packet.haslayer(IP):
            ip_layer = packet.getlayer(IP)
            src_ip = ip_layer.src  # Source IP
            dst_ip = ip_layer.dst  # Destination IP
            packet_length = len(packet)  # Length of the packet
            ttl = ip_layer.ttl  # Time-to-live value

            self.packet_lengths[src_ip].append(packet_length)
            self.packet_count[src_ip] += 1

            # Check for anomalies based on packet count
            current_time = time.time()
            time_elapsed = current_time - self.start_time

            if time_elapsed < self.time_window and self.packet_count[src_ip] > self.threshold:
                # TODO: send to logger
                self.logger.log_warning(f"Anomaly detected: {src_ip} has sent {self.packet_count[src_ip]} packets in the last {self.time_window} seconds")
                self.packet_count[src_ip] = 0

            # Reset packet count every time window seconds
            if time_elapsed > self.time_window:
                self.packet_count.clear()
                self.start_time = current_time

            # Detect SYN packets
            if packet.haslayer(TCP):
                tcp_layer = packet.getlayer(TCP)
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport
                flags = tcp_layer.flags

                # Detect SYN packets
                if flags == 'S':
                    self.syn_packets[src_ip] += 1
                    self.logger.log_debug(f"  SYN packet detected from {src_ip}, Count: {self.syn_packets[src_ip]}", print_message=self.verbose)
                    if self.syn_packets[src_ip] > 20:
                        self.logger.log_alert(f"Potential scan detected from {src_ip}")
                        self.syn_packets[src_ip] = 0
                        time.sleep(2.5)

                # Detect retransmissions
                elif flags == 'R':
                    self.tcp_retransmissions[src_ip] += 1
                    self.logger.log_debug(f"Retransmission detected from {src_ip}, Count: {self.tcp_retransmissions[src_ip]}", print_message=self.verbose)

            # Detect UDP packets
            elif packet.haslayer(UDP):
                udp_layer = packet.getlayer(UDP)
                src_port = udp_layer.sport
                dst_port = udp_layer.dport
                self.logger.log_debug(f"UDP packet detected from {src_ip}, Ports: {src_port} -> {dst_port}", print_message=self.verbose)

    def start_sniffing(self, interface="eth0"):
        """Sniff packets on the defined network interface."""
        self.logger.log_info(f"Listening on {interface} in promiscuous mode...")
        sniff(iface=interface, prn=self.extract_packet_info, promisc=True)
