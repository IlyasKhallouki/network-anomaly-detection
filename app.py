import argparse
import sys
from utilities.network_monitor import NetworkMonitor
from detectors.ddos_detection import DDoSDetection
from detectors.arp_spoofing_detection import ArpSpoofingDetection
from detectors.icmp_flood_detection import IcmpFloodDetection
from detectors.port_scanning_detector import PortScanningDetector
from utilities.logger import Logger

logger = Logger()

def main():
    parser = argparse.ArgumentParser(
        description="A Python CLI for monitoring your network", 
        epilog="Example usage: app.py sniff --interface eth0"
    )

    # Subparsers for different commands
    subparsers = parser.add_subparsers(dest='command', help="Available commands")

    # Command for listing IP addresses
    parser_ls = subparsers.add_parser('lI', help='List the IP addresses of all the devices connected to the network')
    parser_ls.add_argument('--interface', required=False, type=str, help="Specify an interface")

    # Command for listing interfaces
    parser_ls = subparsers.add_parser('lD', help='List all the network interfaces')

    # Command for sniffing packets
    parser_sniff = subparsers.add_parser('sniff', help='Sniff network packets with optional filters')
    parser_sniff.add_argument('--interface', required=False, type=str, help="Specify an interface")
    parser_sniff.add_argument('--filter-ip', type=str, help="Filter packets by IP address")
    parser_sniff.add_argument('--filter-protocol', type=int, help="Filter packets by protocol number")
    parser_sniff.add_argument('--filter-ttl', type=str, help="Filter packets by TTL (e.g., +50 for greater than 50)")
    parser_sniff.add_argument('--filter-len', type=str, help="Filter packets by length (e.g., -120 for less than 120)")
    parser_sniff.add_argument('--count', type=int, default=10, help="Number of packets to capture")
    parser_sniff.add_argument('--fields', type=str, nargs='*', help="Fields to display (e.g., src_ip, dst_ip)")

    # Command for port scanning
    parser_scan = subparsers.add_parser('scan', help='Scan specified ports on a target IP')
    parser_scan.add_argument('target_ip', type=str, help='Target IP address to scan')
    parser_scan.add_argument('ports', type=str, help='Single port, range (e.g., 20-25), or comma-separated list')
    parser_scan.add_argument('--interface', required=False, type=str, help="Specify an interface")
    parser_scan.add_argument('--type', choices=['tcp', 'udp', 'syn'], default='tcp', help='Specify scan type (tcp, udp, or syn)')
    parser_scan.add_argument('--os-detection', action='store_true', help='Attempt to detect the operating system')
    parser_scan.add_argument('--service-detection', action='store_true', help='Attempt to detect the service version')

    # Command for monitoring anomalies
    parser_monitor = subparsers.add_parser('monitor', help='Monitor network for specific anomalies like botnet, DDoS, etc.')
    parser_monitor.add_argument('--anomaly', choices=['arp', 'ddos', 'icmp_flood', 'port_scanning'], required=False, help="Specify the type of anomaly to monitor")
    parser_monitor.add_argument('--interface', required=False, type=str, help="Specify an interface")
    parser_monitor.add_argument('--verbose', required=False, action='store_true', help="Print more info")

    # Command for version
    parser_version = subparsers.add_parser('version', help='Show the app version')

    # Parse the arguments
    args = parser.parse_args()

    # Handling the logic for each command
    if args.command == 'lI':
        list_devices(args.interface)
    elif args.command == 'lD':
        list_interfaces()
    elif args.command == 'sniff':
        sniff_packets(args.interface, args.filter_ip, args.filter_protocol, args.filter_ttl, args.filter_len, args.count, args.fields)
    elif args.command == 'scan':
        scan_ports(args.interface, args.target_ip, args.ports, args.type, args.os_detection, args.service_detection)
    elif args.command == 'monitor':
        monitor_anomaly(args.anomaly, args.interface, args.verbose)
    elif args.command == 'version':
        show_version()
    else:
        parser.print_help()

def scan_ports(interface, target_ip, ports, scan_type, os_detection, service_detection):
    try:
        monitor = NetworkMonitor(interface=interface)
        open_ports = monitor.scan_ports(target_ip, ports, scan_type, os_detection, service_detection)
        if open_ports:
            logger.log_debug(f"Open ports on {target_ip}: {', '.join(map(str, open_ports))}")
        else:
            logger.log_debug(f"No open ports found on {target_ip}.")
    except Exception as e:
        logger.log_exception(e)
        exit(1)

def sniff_packets(interface, filter_ip, filter_protocol, filter_ttl, filter_len, count, fields):
    monitor = NetworkMonitor(interface)
    monitor.sniff_packets(filter_ip=filter_ip, filter_protocol=filter_protocol, filter_ttl=filter_ttl, filter_len=filter_len, count=count, fields=fields)

def list_devices(interface):
    try:
        monitor = NetworkMonitor(interface)
        devices = monitor.list_connected_devices()
        for device in devices:
            logger.log_info(f"IP: {device['ip']}, MAC: {device['mac']}")
    except Exception as e:
        logger.log_exception(e)
        exit(1)

def list_interfaces():
    try: 
        monitor = NetworkMonitor()
        interfaces = monitor.list_all_interfaces()
        for iface in interfaces:
            logger.log_debug(f"Interface: {iface['interface']}")
            logger.log_info(f"  Status: {'Up' if iface['is_up'] else 'Down'}")
            if iface['speed']:
                logger.log_info(f"  Speed: {iface['speed']} Mbps")
            if iface['ip_address']:
                logger.log_info(f"  IP Address: {iface['ip_address']}")
            if iface['mac_address']:
                logger.log_info(f"  MAC Address: {iface['mac_address']}")
            print("\n")
    except Exception as e:
        logger.log_exception(e)
        exit(1)

def monitor_anomaly(anomaly, interface, verbose):
    detector = None
    if anomaly == 'ddos':
        detector = DDoSDetection(verbose=verbose)
    elif anomaly == 'arp':
        detector = ArpSpoofingDetection(verbose=verbose)
    elif anomaly == 'icmp_flood':
        detector = IcmpFloodDetection(verbose=verbose)
    elif anomaly == 'port_scanning':
        detector = PortScanningDetector(verbose=verbose)
    else:
        try:
            raise Exception("No valid mode was chosen")
        except Exception as e:
            logger.log_exception(e)
            exit(1)

    detector.start_sniffing(interface=interface)

def show_version():
    logger.log_info("CLI App Version 0.2.0")

if __name__ == '__main__':
    main()
