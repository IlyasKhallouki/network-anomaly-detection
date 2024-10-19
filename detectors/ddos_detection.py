import time
import scapy.all as scapy

class DDoSDetection:
    def __init__(self, packet_rate_threshold=100, connection_threshold=50, time_window=10):
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
        self.connection_count = 0
        self.packet_log = []  # Stores timestamps of packets
        self.connection_log = {}  # Stores connection counts by IP
        self.start_time = time.time()

    def detect_packet(self, packet):
        """
        Detects potential DDoS attacks based on packet rates and connection attempts.
        This method should be passed as a callback to Scapy's sniff function.
        """
        # Track the packet arrival time
        self.packet_log.append(time.time())
        self.packet_count += 1
        
        if scapy.IP in packet:
            src_ip = packet[scapy.IP].src
            # Track connections by source IP
            if src_ip not in self.connection_log:
                self.connection_log[src_ip] = 0
            self.connection_log[src_ip] += 1
            self.connection_count += 1
        
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
        self.packet_log = [timestamp for timestamp in self.packet_log if current_time - timestamp <= self.time_window]
        self.packet_count = len(self.packet_log)
        
        # Clean up old connections as well (within time window)
        for ip in list(self.connection_log):
            if current_time - self.start_time > self.time_window:
                del self.connection_log[ip]
        self.connection_count = sum(self.connection_log.values())

    def _is_ddos_suspected(self):
        """
        Returns True if packet rate or connection thresholds are exceeded, indicating a possible DDoS attack.
        """
        packet_rate = len(self.packet_log) / self.time_window
        return packet_rate > self.packet_rate_threshold or self.connection_count > self.connection_threshold

    def _raise_alert(self):
        """
        Raises an alert if DDoS attack is suspected.
        """
        # TODO: send to logger
        print("⚠️ DDoS attack suspected! Packet rate or connection threshold exceeded.")
    
    def reset(self):
        """
        Resets the packet and connection logs (useful after handling an alert).
        """
        self.packet_log = []
        self.connection_log = {}
        self.packet_count = 0
        self.connection_count = 0
        self.start_time = time.time()