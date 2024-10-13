import scapy.all as scapy
import ipaddress
import psutil
import socket
from utils import Utils

class NetworkMonitor:
    def __init__(self, interface=None):
        self.interface = interface
        self.utils = Utils()


    def list_connected_devices(self):
        # Check if no interface was specified and find it
        if self.interface == None:
            try:
                self.interface = self.utils._get_default_interface()
            except Exception as e:
                print("An error has occured while trying to find an interface")

        """Lists all devices connected to the network."""
        ip_address, netmask = self.utils._get_ip_and_netmask(self.interface)

        # Calculate the network range using ipaddress module
        network = ipaddress.IPv4Network(f"{ip_address}/{netmask}", strict=False)
        network_range = str(network)

        print(f"Scanning network range: {network_range}")
        
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
    
    def sniff_packets(self, filter_ip=None, count=10, fields=None):
        """
        Sniffs network packets on the specified interface, optionally filtered by an IP address,
        and displays selected fields.

        :param filter_ip: IP address to filter packets (source or destination). If None, no filter is applied.
        :param count: Number of packets to capture. Default is 10.
        :param fields: List of fields to display (e.g., ['src_ip', 'dst_ip', 'protocol']). If None, all fields are shown.
        """
        # Default fields if none are specified
        default_fields = ['src_ip', 'dst_ip', 'protocol', 'ttl', 'len']
        if fields is None:
            fields = default_fields  

        # Check if no interface was specified and find it
        if self.interface is None:
            try:
                self.interface = self.utils._get_default_interface()
                print(f"Using default interface: {self.interface}")
            except Exception as e:
                raise e

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

                    # Display only the fields specified by the user
                    display_info = {key: packet_info[key] for key in fields if key in packet_info}

                    print(display_info)

            except Exception as e:
                print(f"Error processing packet: {e}")

        # Sniff packets on the interface
        print(f"Starting packet sniffing on interface: {self.interface}")
        scapy.sniff(iface=self.interface, prn=packet_callback, count=count, store=False, promisc=True)