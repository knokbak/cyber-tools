################################################################
# Licensed under the BSD 3-Clause License                      #
# See https://github.com/knokbak/cyber-tools/blob/main/LICENSE #
################################################################

# Utilities for knokbak/cyber-tools
# OK - 27 Sep 2023

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

    prompt_menu('Main Menu', [
        ('ARP', arp_main),
    ])


if __name__ == '__main__':
    main()
