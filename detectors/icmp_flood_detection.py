from collections import defaultdict
import time
from scapy.all import sniff, IP, ICMP

class IcmpFloodDetection:
    def __init__(self, threshold=100, time_interval=10):
        """
        Initialize the ICMP Flood Detection class.

        :param threshold: The number of ICMP packets that should be received in the time interval
        :param time_interval: The time window (in seconds) over which packet counts are considered
        """
        self.threshold = threshold
        self.time_interval = time_interval
        self.packet_count = defaultdict(int)
        self.packet_sizes = defaultdict(list)
        self.start_time = time.time()

    def detect_flood(self, packet):
        """
        Detects ICMP Flood attack based on packet count and packet size.

        :param packet: The packet to be analyzed
        """
        current_time = time.time()
        ip_layer = packet.getlayer(IP)

        if packet.haslayer(ICMP):
            src_ip = ip_layer.src
            packet_size = len(packet)
            self.packet_sizes[src_ip].append(packet_size)
            self.packet_count[src_ip] += 1

            # Detect ICMP flood based on packet count and threshold
            if current_time - self.start_time < self.time_interval and self.packet_count[src_ip] > self.threshold:
                pass
                # TODO: send to logger
                # print(f"ICMP Flood detected from {src_ip}: {self.packet_count[src_ip]} ICMP packets in the last {self.time_interval} seconds")

            # Reset the counter every ANOMALY_TIME_INTERVAL seconds
            if current_time - self.start_time > self.time_interval:
                self.packet_count.clear()
                self.start_time = current_time

    def start_sniffing(self, interface="eth0"):
        """
        Start sniffing for ICMP packets on the given interface.

        :param interface: The network interface to use for sniffing
        """
        print(f"Listening for ICMP packets on interface {interface}...")
        sniff(iface=interface, prn=self.detect_flood, filter="icmp", store=False)

