import scapy.all as scapy
import socket
import struct
import fcntl

class NetworkMonitor:
    def __init__(self, interface):
        self.interface = interface
    
    def _get_network_range(self):
        """Gets the network IP range based on the current IP and subnet mask."""
        # Get the IP address and netmask of the interface
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ip_address = socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', self.interface[:15].encode('utf-8'))
        )[20:24])

        netmask = socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x891b,  # SIOCGIFNETMASK
            struct.pack('256s', self.interface[:15].encode('utf-8'))
        )[20:24])

        # Calculate network range
        ip_bin = struct.unpack('!I', socket.inet_aton(ip_address))[0]
        mask_bin = struct.unpack('!I', socket.inet_aton(netmask))[0]
        network_bin = ip_bin & mask_bin
        broadcast_bin = network_bin | ~mask_bin & 0xFFFFFFFF
        
        network_range = f"{socket.inet_ntoa(struct.pack('!I', network_bin))}/{scapy.IP(netmask).len}"
        return network_range

    def list_connected_devices(self):
        """Lists all devices connected to the network."""
        network_range = self._get_network_range()
        arp_request = scapy.ARP(pdst=network_range)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

        devices = []
        for element in answered_list:
            device = {'ip': element[1].psrc, 'mac': element[1].hwsrc}
            devices.append(device)

        return devices


# Example usage
monitor = NetworkMonitor(interface="Wi-Fi")
connected_devices = monitor.list_connected_devices()

for device in connected_devices:
    print(f"IP: {device['ip']}, MAC: {device['mac']}")
