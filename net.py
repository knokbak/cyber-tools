################################################################
# Licensed under the BSD 3-Clause License                      #
# See https://github.com/knokbak/cyber-tools/blob/main/LICENSE #
################################################################

# Networking library
# OK - 27 Sep 2023

import io
from utils import mac_str_to_bytes

ETHER_TYPES = {
    'IPv4': 0x0800,
    'ARP': 0x0806,
    'IPv6': 0x86DD
}

def layer_2(src_mac: str, dest_mac: str, ethertype: int, packet: bytes) -> bytes:
    ETH_DEST_MAC = mac_str_to_bytes(dest_mac)
    ETH_SRC_MAC = mac_str_to_bytes(src_mac)
    ETH_TYPE = bytes(ethertype)

    eth_header = ETH_DEST_MAC + ETH_SRC_MAC + ETH_TYPE
    return eth_header + packet
