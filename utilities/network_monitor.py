import scapy.all as scapy
import ipaddress
import psutil
import socket
from utilities.utils import Utils
from utilities.logger import Logger

class NetworkMonitor:
    def __init__(self, interface=None, verbose=False):
        self.logger = Logger()
        self.interface = interface
        self.utils = Utils()
        self.verbose = verbose


    def list_connected_devices(self):
        # Check if no interface was specified and find it
        if self.interface == None:
            try:
                self.interface = self.utils._get_default_interface()
            except Exception as e:
                self.logger.log_error("An error has occured while trying to find an interface")
                exit(1)

        """Lists all devices connected to the network."""
        ip_address, netmask = self.utils._get_ip_and_netmask(self.interface)

        # Calculate the network range using ipaddress module
        network = ipaddress.IPv4Network(f"{ip_address}/{netmask}", strict=False)
        network_range = str(network)

        self.logger.log_info(f"Scanning network range: {network_range}")
        
        # Perform ARP scan over the network range
        arp_request = scapy.ARP(pdst=network_range)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

        devices = []
        for element in answered_list:
            device = {'ip': element[1].psrc, 'mac': element[1].hwsrc}
            devices.append(device)

        return devices

    def list_all_interfaces(self):
        """Lists all network interfaces and their details."""
        interfaces = psutil.net_if_addrs()
        stats = psutil.net_if_stats()

        interface_info = []
        for iface, addr_list in interfaces.items():
            interface_details = {
                'interface': iface,
                'is_up': stats[iface].isup if iface in stats else False,
                'speed': stats[iface].speed if iface in stats else None,
                'ip_address': None,
                'mac_address': None
            }
            for addr in addr_list:
                if addr.family == socket.AF_INET:
                    interface_details['ip_address'] = addr.address
                elif addr.family == psutil.AF_LINK:
                    interface_details['mac_address'] = addr.address

            interface_info.append(interface_details)

        return interface_info
    
    def sniff_packets(self, filter_ip=None, count=10, fields=None, filter_protocol=None, filter_ttl=None, filter_len=None, callback=None):
        """
        Sniffs network packets on the specified interface, filtered by IP, protocol, TTL, or length.

        :param filter_ip: IP address to filter packets (source or destination). If None, no filter is applied.
        :param count: Number of packets to capture. Default is 10.
        :param fields: List of fields to display (e.g., ['src_ip', 'dst_ip', 'protocol']). If None, all fields are shown.
        :param filter_protocol: Protocol number to filter packets. If None, all protocols are captured.
        :param filter_ttl: Filter packets by TTL. Supports > or < prefixes (e.g., '>50', '<120').
        :param filter_len: Filter packets by length. Supports > or < prefixes (e.g., '>100', '<500').
        """
        # Default fields if none are specified
        default_fields = ['src_ip', 'dst_ip', 'protocol', 'ttl', 'len']
        if fields is None:
            fields = default_fields  

        # Check if no interface was specified and find it
        if self.interface is None:
            try:
                self.interface = self.utils._get_default_interface()
                self.logger.log_info(f"Using default interface: {self.interface}")
            except Exception as e:
                raise e

        # Parse TTL and len filters (e.g., '>50', '<100')
        def parse_filter_value(value):
            if value.startswith('+'):
                return '>', int(value[1:])
            elif value.startswith('-'):
                return '<', int(value[1:])
            else:
                return None, None

        ttl_op, ttl_value = parse_filter_value(filter_ttl) if filter_ttl else (None, None)
        len_op, len_value = parse_filter_value(filter_len) if filter_len else (None, None)

        # Packet callback function
        def packet_callback(packet):
            try:
                if packet.haslayer(scapy.IP):
                    # Collect packet details
                    packet_info = {
                        'src_ip': packet[scapy.IP].src,
                        'dst_ip': packet[scapy.IP].dst,
                        'protocol': packet[scapy.IP].proto,
                        'ttl': packet[scapy.IP].ttl,
                        'len': len(packet)
                    }

                    # Apply IP filtering if specified
                    if filter_ip and (packet_info['src_ip'] != filter_ip and packet_info['dst_ip'] != filter_ip):
                        return

                    # Apply protocol filtering if specified
                    if filter_protocol and packet_info['protocol'] != filter_protocol:
                        return

                    # Apply TTL filtering if specified
                    if ttl_op:
                        if ttl_op == '>' and packet_info['ttl'] <= ttl_value:
                            return
                        elif ttl_op == '<' and packet_info['ttl'] >= ttl_value:
                            return

                    # Apply length filtering if specified
                    if len_op:
                        if len_op == '>' and packet_info['len'] <= len_value:
                            return
                        elif len_op == '<' and packet_info['len'] >= len_value:
                            return

                    # Display only the fields specified by the user
                    display_info = {key: packet_info[key] for key in fields if key in packet_info}
                    print(display_info)

            except Exception as e:
                self.logger.log_exception(e)
                exit(1)
                
        if callback == None: callback = packet_callback

        # Sniff packets on the interface
        self.logger.log_info(f"Starting packet sniffing on interface: {self.interface}")
        scapy.sniff(iface=self.interface, prn=callback, count=count, store=False, promisc=True)

    def scan_ports(self, target_ip, ports, scan_type='tcp', os_detection=False, service_detection=False):
        """
        Scans specified ports on a target IP address using the specified scan type,
        and performs OS and service version detection if requested.

        :param target_ip: IP address to scan.
        :param ports: A single port, a range (e.g., 20-25), or a comma-separated list of ports/ranges.
        :param scan_type: Type of scan ('tcp', 'udp', 'syn').
        :param os_detection: Whether to attempt OS detection.
        :param service_detection: Whether to attempt service version detection.
        """
        open_ports = []

        # Parse ports input
        port_list = self._parse_ports(ports)

        self.logger.log_info(f"Scanning ports: {port_list} on {target_ip} using {scan_type.upper()} scan...")

        for port in port_list:
            if scan_type.lower() == 'tcp':
                result = self._tcp_scan(target_ip, port)
            elif scan_type.lower() == 'udp':
                result = self._udp_scan(target_ip, port)
            elif scan_type.lower() == 'syn':
                result = self._syn_scan(target_ip, port)
            else:
                self.logger.log_error(f"Unsupported scan type: {scan_type}")
                return

            if result:
                open_ports.append(port)

                if service_detection:
                    service_info = self._detect_service(target_ip, port)
                    self.logger.log_debug(f"Service on port {port}: {service_info}")

        if os_detection:
            os_info = self._detect_os(target_ip)
            self.logger.log_debug(f"Detected OS: {os_info}")

        return open_ports

    def _parse_ports(self, ports):
        """Parses the ports input and returns a list of individual ports."""
        port_list = []
        for item in ports.split(','):
            if '-' in item:
                start, end = map(int, item.split('-'))
                port_list.extend(range(start, end + 1))
            else:
                port_list.append(int(item.strip()))
        return port_list

    def _tcp_scan(self, target_ip, port):
        """Performs a TCP scan on a given port."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)  # Set a timeout for the connection attempt
            result = sock.connect_ex((target_ip, port))
            return result == 0

    def _udp_scan(self, target_ip, port):
        """Performs a UDP scan on a given port."""
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(1)
            sock.sendto(b'', (target_ip, port))
            try:
                sock.recvfrom(1024)
                return True  # Port is open if we receive a response
            except socket.timeout:
                return False  # Port is closed or filtered

    def _syn_scan(self, target_ip, port):
        """Performs a SYN scan on a given port using Scapy and the specified interface."""
        # Create a SYN packet
        syn_packet = scapy.IP(dst=target_ip) / scapy.TCP(dport=port, flags="S")
        
        # Send the SYN packet and wait for a response
        response, _ = scapy.sr(syn_packet, iface=self.interface, verbose=False, timeout=1)

        if response:
            # Check the flags in the response
            for packet in response:
                if packet[1].haslayer(scapy.TCP):
                    if packet[1][scapy.TCP].flags == 0x12:  # SYN-ACK
                        # Send RST to close the connection
                        scapy.sr(scapy.IP(dst=target_ip) / scapy.TCP(dport=port, flags="R"), iface=self.interface, verbose=False)
                        return True
                    elif packet[1][scapy.TCP].flags == 0x14:  # RST
                        return False
        return False


    def _detect_service(self, target_ip, port):
        """Attempts to detect the service running on the specified port."""
        service_map = {
            22: "SSH",
            80: "HTTP",
            443: "HTTPS",
            21: "FTP",
            25: "SMTP",
            110: "POP3",
            143: "IMAP",
            3306: "MySQL",
            5432: "PostgreSQL",
            6379: "Redis"
        }
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                sock.connect((target_ip, port))
                
                if port in service_map:
                    return service_map[port]

                # Example for further service detection
                if port == 21:  # FTP
                    sock.sendall(b"USER anonymous\r\n")
                    response = sock.recv(1024).decode()
                    if "230" in response:  # Check for successful login
                        return "FTP (Anonymous access)"
                elif port == 80 or port == 443:  # HTTP/HTTPS
                    sock.sendall(b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                    response = sock.recv(1024).decode()
                    if "HTTP" in response:
                        return "Web Service"
                
                return "Unknown service"
        except Exception:
            return "Service not detected"

    def _detect_os(self, target_ip):
        """Detects the operating system based on TTL values from ping responses."""
        try:
            response = scapy.sr1(scapy.IP(dst=target_ip)/scapy.ICMP(), verbose=False, timeout=1)
            if response:
                ttl = response.ttl
                if ttl <= 64:
                    return "Linux/Unix"
                elif ttl <= 128:
                    return "Windows"
                elif ttl <= 255:
                    return "More information required"
            return "No response"
        except Exception as e:
            self.logger.log_error(f"Error in OS detection: {e}")
            return "OS detection failed"