import scapy.all as scapy
import ipaddress
from utils import Utils

class NetworkMonitor:
    def __init__(self, interface):
        self.interface = interface
        self.utils = Utils()


    def list_connected_devices(self):
        # Check if no interface was specified and find it
        if self.interface == None:
            try:
                self.interface = self.utils._get_default_interface()
            except Exception as e:
                raise e

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
