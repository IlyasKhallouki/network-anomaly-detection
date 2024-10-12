import argparse
import sys

# Define your main CLI logic here
def main():
    parser = argparse.ArgumentParser(
        description="A Python CLI template", 
        epilog="Example usage: cli_app.py <command> --option"
    )

    # Add a subparser for different commands
    subparsers = parser.add_subparsers(dest='command', help="Available commands")

    # Example Command 1: say-hello
    parser_hello = subparsers.add_parser('say-hello', help='Say hello to a user')
    parser_hello.add_argument('--name', required=True, help='Name of the user')

    # Example Command 2: add
    parser_add = subparsers.add_parser('add', help='Add two numbers')
    parser_add.add_argument('num1', type=int, help='First number')
    parser_add.add_argument('num2', type=int, help='Second number')

    # Example Command 3: version
    parser_version = subparsers.add_parser('version', help='Show the app version')

    # Parse the arguments
    args = parser.parse_args()

    # Handle the logic for each command
    if args.command == 'say-hello':
        say_hello(args.name)
    elif args.command == 'add':
        add_numbers(args.num1, args.num2)
    elif args.command == 'version':
        show_version()
    else:
        parser.print_help()

# Example function 1: say-hello
def say_hello(name):
    print(f"Hello, {name}!")

# Example function 2: add two numbers
def add_numbers(num1, num2):
    result = num1 + num2
    print(f"The sum of {num1} and {num2} is {result}")

# Example function 3: show the version
def show_version():
    print("CLI App Version 1.0")

if __name__ == '__main__':
    main()
