import psutil
import socket
import struct
import fcntl

class Utils:
    # TODO: Fix what interface is picked
    def _get_default_interface(self):
        """Automatically detect the active network interface."""
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        
        for iface, addr_list in addrs.items():
            if iface in stats and stats[iface].isup:  # Check if the interface is up
                for addr in addr_list:
                    if addr.family == socket.AF_INET:  # Check for IPv4 addresses
                        return iface
        raise Exception()

    def _get_ip_and_netmask(self, interface):
        """Gets the IP address and netmask of the interface."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ip_address = socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', interface[:15].encode('utf-8'))
        )[20:24])

        netmask = socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x891b,  # SIOCGIFNETMASK
            struct.pack('256s', interface[:15].encode('utf-8'))
        )[20:24])

        return ip_address, netmask
