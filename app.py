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
    parser_ls = subparsers.add_parser('ls', help='List the IP addresses of all the devices connected to the network')
    parser_ls.add_argument('--interface', required=False, type=str, help="Specify an interface")

    # # Example Command 2: add
    # parser_add = subparsers.add_parser('add', help='Add two numbers')
    # parser_add.add_argument('num1', type=int, help='First number')
    # parser_add.add_argument('num2', type=int, help='Second number')

    # Example Command 3: version
    parser_version = subparsers.add_parser('version', help='Show the app version')

    # Parse the arguments
    args = parser.parse_args()

    # Handling the logic for each command
    if args.command == 'ls':
        list_devices(args.interface)
    elif args.command == 'version':
        show_version()
    else:
        parser.print_help()

def list_devices(interface):
    try:
        monitor = NetworkMonitor(interface)
    except Exception as e:
        if e.args == "interface 0":
            print("Unable to detect an interface - please specify one")
        print(e.args)
        exit(1)
    devices = monitor.list_connected_devices()
    for device in devices:
        print(f"IP: {device['ip']}, MAC: {device['mac']}")

# Display the app version
def show_version():
    print("CLI App Version 0.1.0")

if __name__ == '__main__':
    main()
