from scapy.all import sniff, ARP, get_if_addr, get_if_hwaddr
from collections import defaultdict
import time
from utilities.logger import Logger

class ArpSpoofingDetection:
    def __init__(self, time_interval=60, threshold=1, verbose=False):
        """
        Initialize ARP spoofing detection with configurable time interval and threshold.
        
        :param time_interval: Time window (in seconds) for checking for anomalies.
        :param threshold: Number of ARP packets from different MAC addresses for the same IP
                          in the time window to trigger an alert.
        """
        self.logger = Logger()
        self.verbose = verbose
        self.time_interval = time_interval
        self.threshold = threshold
        self.arp_table = defaultdict(list)  # Store IP -> [list of MACs seen in time window]

    def packet_handler(self, packet):
        """Handle each packet and check for ARP spoofing activity."""
        if packet.haslayer(ARP):
            arp_layer = packet.getlayer(ARP)
            src_ip = arp_layer.psrc
            src_mac = arp_layer.hwsrc

            # TODO: send to logger
            # print(f"ARP Packet: {src_ip} -> {src_mac}")
            self.logger.log_debug(message=f"ARP Packet: {src_ip} -> {src_mac}", print_message=self.verbose)

            # Record the MAC address for the IP
            current_time = time.time()
            self.arp_table[src_ip].append((src_mac, current_time))

            # Check for ARP spoofing: if multiple different MAC addresses for the same IP in a short time
            self.detect_arp_spoofing(src_ip)

    def detect_arp_spoofing(self, src_ip):
        """Detect ARP spoofing by checking for different MAC addresses associated with an IP."""
        current_time = time.time()

        # Filter ARP entries within the time window
        recent_entries = [entry for entry in self.arp_table[src_ip] if current_time - entry[1] <= self.time_interval]

        # Get unique MAC addresses seen for this IP
        unique_macs = set([entry[0] for entry in recent_entries])

        if len(unique_macs) > self.threshold:
            # TODO: send to logger
            self.logger.log_alert(message=f"[ALERT] ARP Spoofing detected: {src_ip} has {len(unique_macs)} different MAC addresses in the last {self.time_interval} seconds!", print_message=self.verbose)
            # print(f"[ALERT] ARP Spoofing detected: {src_ip} has {len(unique_macs)} different MAC addresses in the last {self.time_interval} seconds!")

        # Clean up old records outside the time window
        self.arp_table[src_ip] = [entry for entry in self.arp_table[src_ip] if current_time - entry[1] <= self.time_interval]

    def start_sniffing(self, interface="wlp2s0"):
        """Start sniffing for ARP packets on the specified interface."""
        self.logger.log_info(f"Listening for ARP spoofing activity on {interface}...")
        sniff(iface=interface, prn=self.packet_handler, store=0)

