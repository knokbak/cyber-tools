################################################################
# Licensed under the BSD 3-Clause License                      #
# See https://github.com/knokbak/cyber-tools/blob/main/LICENSE #
################################################################

# Utilities for knokbak/cyber-tools
# OK - 27 Sep 2023

import random
from typing import Any, Callable
import zlib

MenuItem = tuple[str, Callable]

# Returns the selected option (0) and the function's response (1) as a tuple
def prompt_menu(menu_title: str, items: list[MenuItem], default: str | None = None) -> tuple[MenuItem, Any]:
    print()
    print(menu_title)
    print('-' * 25)
    for i in range(len(items)):
        item = items[i]
        print(f'{i+1}.  {item[0]}')
    print('-' * 25)
    
    if default:
        result = input(f'Enter an option [{default}]: ')
    else:
        result = input('Enter an option: ')

    if not result and default:
        result = default

    try:
        result = int(result)
    except ValueError:
        print('That is not a number!')
        return prompt_menu(menu_title, items)
    
    if result < 1 or result > len(items):
        print('That is not a valid option!')
        return prompt_menu(menu_title, items)
    
    print()
    item = items[result - 1]
    return (item, item[1]())


# Shows a menu and returns the selected option
def prompt_menu_returnable(menu_title: str, items: list[str], default: str | None = None) -> int:
    print()
    print(menu_title)
    print('-' * 25)
    for i in range(len(items)):
        item = items[i]
        print(f'{i+1}.  {item}')
    print('-' * 25)
    
    if default:
        result = input(f'Enter an option [{default}]: ')
    else:
        result = input('Enter an option: ')

    if not result and default:
        result = default

    try:
        result = int(result)
    except ValueError:
        print('That is not a number!')
        return prompt_menu_returnable(menu_title, items)
    
    if result < 1 or result > len(items):
        print('That is not a valid option!')
        return prompt_menu_returnable(menu_title, items)
    
    print()
    return result


# Show a menu where options can be selected/deselected. 'ok' returns the selected options. multiple options can be selected
def prompt_menu_selectable(menu_title: str, items: list[str], default: list[int] | None = None) -> list[int]:
    selected = []
    if default:
        selected = default

    def show_menu():
        print()
        print(menu_title)
        print('-' * 25)
        for i in range(len(items)):
            item = items[i]
            if i + 1 in selected:
                print(bold(f'{i+1}.  {item}'))
            else:
                print(f'{i+1}.  {item}')
        print('-' * 25)
    
    show_menu()
    print('Select options by entering their numbers. Enter "ok" to finish.')

    while True:
        result = input('Enter an option: ')
        if result == 'ok':
            break

        try:
            result = int(result)
        except ValueError:
            print('That is not a number!')
            continue
        
        if result < 1 or result > len(items):
            print('That is not a valid option!')
            continue
        
        if result in selected:
            selected.remove(result)
        else:
            selected.append(result)
        
        show_menu()
    
    print()
    return selected


# Coverts a MAC address from bytes to a string
def mac_bytes_to_str(mac: bytes) -> str:
    return ':'.join(f'{b:02x}' for b in mac)


# Converts an IPv4 address from bytes to a string
def ipv4_bytes_to_str(ipv4: bytes) -> str:
    return '.'.join(str(b) for b in ipv4)


# Converts an IPv6 address from bytes to a string
def ipv6_bytes_to_str(ipv6: bytes) -> str:
    addr = ':'.join(f'{b:02x}' for b in ipv6)
    addr = addr.replace(':0000:', '::').replace(':000:', '::').replace(':00:', '::')
    return addr


# Builds and prints a table from a list of rows to the console
def print_table(rows: list[list[str]]):
    max_widths = []
    for i in range(len(rows[0])):
        max_widths.append(0)

    for row in rows:
        for i in range(len(row)):
            col = str(row[i])
            if max_widths[i] < len(col):
                max_widths[i] = len(col)
    
    for i in range(len(rows)):
        row = rows[i]
        text = ''

        for ii in range(len(row)):
            col = str(row[ii])
            text += col + ' ' * (max_widths[ii] - len(col) + 4)

        if i == 0:
            text = bold(text)
        
        print(text)


# Request confirmation from the user before transmitting traffic over the network
def confirm_network_transmit() -> bool:
    return (input('I am about to send traffic over the network. Continue? [Y/n]: ').lower() or 'y') == 'y'


# Determines version of IP address
def determine_ip_version(ip: str) -> int:
    if '.' in ip:
        return 4
    elif ':' in ip:
        return 6
    else:
        raise ValueError('Invalid IP address')


# Make console text bold
def bold(text: str) -> str:
    return f'\033[1m{text}\033[0m'


# Returns the interface's MAC address, throws an exception if it can't be found
def get_interface_mac_address(interface: str) -> str:
    try:
        with open(f'/sys/class/net/{interface}/address', 'r') as file:
            return file.read().strip()
    except FileNotFoundError:
        raise FileNotFoundError(f'Could not find MAC address for interface "{interface}"')


# Generate a random MAC address
def generate_random_mac_address() -> str:
    mac_address = []
    for i in range(6):
        byte = random.randint(0, 255)
        mac_address.append(f'{byte:02x}')
    mac_address[0] = mac_address[0][:-1] + '2'
    return ':'.join(mac_address)


# MAC string to bytes
def mac_str_to_bytes(mac: str) -> bytes:
    return bytes.fromhex(mac.replace(':', ''))


# Make text loading bar
def make_progress_bar(text: str, current: float, max: float) -> str:
    if current > max:
        current = max

    percent = current / max
    bar = ''

    for i in range(20):
        if i / 20 < percent:
            bar += '█'
        else:
            bar += '░'
    
    return f'{bar}  {text}'
