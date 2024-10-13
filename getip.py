from scapy.all import ARP, Ether, srp

def discover_devices(ip_range):
    # Create ARP request packet
    arp = ARP(pdst=ip_range)
    
    # Create Ethernet frame
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    
    # Combine Ethernet frame and ARP packet
    packet = ether/arp
    
    # Send the packet and capture responses
    result = srp(packet, timeout=3, verbose=0)[0]
    
    # List to store discovered devices
    devices = []
    
    # Process each response packet
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    
    return devices

if __name__ == "__main__":
    ip_range = "192.168.11.0/24"  # Adjust this to your network's IP range
    devices = discover_devices(ip_range)
    
    print("Devices found:")
    for device in devices:
        print(f"IP: {device['ip']}, MAC: {device['mac']}")
