################################################################
# Licensed under the BSD 3-Clause License                      #
# See https://github.com/knokbak/cyber-tools/blob/main/LICENSE #
################################################################

# Utilities for knokbak/cyber-tools
# OK - 27 Sep 2023

from functools import partial
from os import geteuid
from utils import prompt_menu
from module_arp import main as arp_main

def main():
    print(f'''
Tools by Ollie Killean

################################################################
# Copyright (c) 2023; Licensed under the BSD 3-Clause License  #
# See https://github.com/knokbak/cyber-tools/blob/main/LICENSE #
################################################################
        
Press Ctrl+C to exit from a mode.
Press Ctrl+Z to quit the program.
    ''')

    if geteuid() != 0:
        raise Exception('This script must be run as root.')

    interface = input('Enter an interface [eth0]: ').lower() or 'eth0'

    prompt_menu('Main Menu', [
        ('ARP', partial(arp_main, interface)),
    ])


if __name__ == '__main__':
    main()
