import argparse
import sys
from network_monitor import NetworkMonitor

# Define your main CLI logic here
def main():
    # TODO: fill up the app info
    parser = argparse.ArgumentParser(
        description="A Python CLI for monitoring your network", 
        epilog="Example usage: app.py ls"
    )

    # Add a subparser for different commands
    subparsers = parser.add_subparsers(dest='command', help="Available commands")

    # Command '-ls'
    parser_ls = subparsers.add_parser('lI', help='List the IP addresses of all the devices connected to the network')
    parser_ls.add_argument('--interface', required=False, type=str, help="Specify an interface")

    parser_ls = subparsers.add_parser('lD', help='List all the network interfaces')
    
    # # Example Command 2: add
    # parser_add = subparsers.add_parser('add', help='Add two numbers')
    # parser_add.add_argument('num1', type=int, help='First number')
    # parser_add.add_argument('num2', type=int, help='Second number')

    # Example Command 3: version
    parser_version = subparsers.add_parser('version', help='Show the app version')

    # Parse the arguments
    args = parser.parse_args()

    # Handling the logic for each command
    if args.command == 'lI':
        list_devices(args.interface)
    elif args.command == 'lD':
        list_interfaces()
    elif args.command == 'version':
        show_version()
    else:
        parser.print_help()

def list_devices(interface):
    try:
        monitor = NetworkMonitor(interface)
        devices = monitor.list_connected_devices()
        for device in devices:
            print(f"IP: {device['ip']}, MAC: {device['mac']}")
    except Exception as e:
        if e.args == "interface 0":
            print("Unable to detect an interface - please specify one")
        print(e.args)
        exit(1)


def list_interfaces():
    try: 
        monitor = NetworkMonitor()
        interfaces = monitor.list_all_interfaces()

        for iface in interfaces:
            print(f"Interface: {iface['interface']}")
            print(f"  Status: {'Up' if iface['is_up'] else 'Down'}")
            if iface['speed']:
                print(f"  Speed: {iface['speed']} Mbps")
            if iface['ip_address']:
                print(f"  IP Address: {iface['ip_address']}")
            if iface['mac_address']:
                print(f"  MAC Address: {iface['mac_address']}")
            print("\n")
    except Exception as e:
        # TODO handle exceptions
        print('An Error has occured', e)
        exit(1)

# Display the app version
def show_version():
    print("CLI App Version 0.1.0")

if __name__ == '__main__':
    main()
