import time
import scapy.all as scapy
from utilities.logger import Logger

class DDoSDetection:
    def __init__(self, packet_rate_threshold=100, connection_threshold=50, time_window=10, verbose=False):
        """
        Initializes DDoS detection with customizable thresholds.
        
        :param packet_rate_threshold: The max number of packets allowed per second before raising an alert.
        :param connection_threshold: The max number of simultaneous connections allowed.
        :param time_window: The time window (in seconds) for evaluating packet rates.
        """
        self.packet_rate_threshold = packet_rate_threshold
        self.connection_threshold = connection_threshold
        self.time_window = time_window
        self.packet_count = 0
        self.connection_log = {}  # Stores connection counts by IP
        self.packet_log = []  # Stores timestamps of packets
        self.start_time = time.time()
        self.logger = Logger()
        self.verbose = verbose

    def detect_packet(self, packet):
        """
        Detects potential DDoS attacks based on packet rates and connection attempts.
        This method should be passed as a callback to Scapy's sniff function.
        """
        self.packet_log.append(time.time())
        self.packet_count += 1

        if scapy.IP in packet:
            src_ip = packet[scapy.IP].src
            
            # Track connections by source IP
            if src_ip not in self.connection_log:
                self.connection_log[src_ip] = time.time()  # Log the first seen time for each IP
            self.connection_log[src_ip] += 1

        # Clean up old entries from packet_log and connection_log
        self._clean_logs()

        # Check for anomalies based on packet rate and connections
        if self._is_ddos_suspected():
            self._raise_alert()
            self.reset()

    def _clean_logs(self):
        """
        Removes old entries from packet_log and connection_log based on the time_window.
        """
        current_time = time.time()

        # Clean up old packets
        self.packet_log = [timestamp for timestamp in self.packet_log if current_time - timestamp <= self.time_window]
        self.packet_count = len(self.packet_log)

        # Clean up old connections (older than time_window)
        for ip, last_seen in list(self.connection_log.items()):
            if current_time - last_seen > self.time_window:
                del self.connection_log[ip]

    def _is_ddos_suspected(self):
        """
        Returns True if packet rate or connection thresholds are exceeded, indicating a possible DDoS attack.
        """
        packet_rate = self.packet_count / self.time_window
        connection_count = len(self.connection_log)
        
        # Check for packet rate and connection thresholds
        if packet_rate > self.packet_rate_threshold or connection_count > self.connection_threshold:
            return True
        return False

    def _raise_alert(self):
        """
        Raises an alert if DDoS attack is suspected.
        """
        print('g')
        self.logger.log_alert("⚠️ DDoS attack suspected! Packet rate or connection threshold exceeded.")

    def reset(self):
        """
        Resets the packet and connection logs.
        """
        self.packet_log = []
        self.connection_log = {}
        self.packet_count = 0
        self.start_time = time.time()

    def start_sniffing(self, interface="eth0"):
        """
        Starts sniffing packets on the specified interface.
        """
        self.logger.log_info(f"Listening for packets on interface {interface}...")
        scapy.sniff(iface=interface, prn=self.detect_packet, store=False)
