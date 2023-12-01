#!/usr/bin/env python3
"""
This is UDP client for ICMP VPN.
It uses libpcap to form and write UDP packets into ICMP datagram.
Your goal is to implement some missing functions

N.B. Please don't mess with libpcap ctypes and copy and paste until you know what you are doing for sure.
This example shall work on Linux, WSL and macOS (any)
"""
import socket
import struct

import proto

if __name__ == '__main__':
    my_ip = '10.10.10.???'
    vpn_server_ip = '10.10.10.1' if my_ip.startswith('10.10.10') else '10.10.11.1'
    my_mac = '00:00:00:00:00:00'  # use ifconfig | ip link to find your mac
    srv_mac = '00:00:00:00:00:00'  # use arp -a | ip neigh to find my mac... or your router's mac in case of WSL
    interface = 'eth0'  # your interface connected to the network

    pcap = proto.PcapWrapper(interface)
    pcap.set_filter(f"icmp[icmptype] = icmp-echoreply and src {vpn_server_ip} and dst {my_ip}")
    pcap.start_capture()
    # send handshake
    eth_hdr = proto.pack_eth_header(proto.mac_to_bytes(my_mac), proto.mac_to_bytes(srv_mac), 0x0800)
    icmp_packet = proto.pack_icmp(8, 0, 65535, 65535, b'\xde\xad\xbe\xef\xde\xad\xbe\xef')
    ip_hdr = proto.pack_ip_header(my_ip, vpn_server_ip, 1, len(icmp_packet) + 20)
    pcap.inject_packet(eth_hdr + ip_hdr + icmp_packet)
    while True:
        handshake_response = pcap.next_packet()
        if len(handshake_response) == 74:
            break
    vpn_ip, vpn_netmask, vpn_key = struct.unpack("4s4s8s", handshake_response[58:74])
    vpn_ip = socket.inet_ntoa(vpn_ip)
    vpn_netmask = socket.inet_ntoa(vpn_netmask)
    print(f"Server gave you {vpn_ip}/{vpn_netmask} address")
    # create UDP packet - pack("!HHHH") with 'getflag\n' data
    _data = b''
    udp_hdr = b'00000000'  # Look into proto.py for examples
    ip_hdr = b''  # Create VIRTUAL IP Header.
    packet = proto.repack_packet_with_checksum(
        ip_hdr + udp_hdr + _data)  # This function repacks header with good checksum
    _len = struct.pack("!H", len(packet))
    # encrypt and put it into ICMP packet
    packet = _len + proto.encrypt_bytes(packet, vpn_key)  # LEN must prepend DATA
    icmp_packet = b''  # Create ICMP packet. Look into handshake to get the idea
    ip_hdr = b''  # Create IP header. Look into handshake to get the idea
    pcap.inject_packet(eth_hdr + ip_hdr + icmp_packet)
    while True:
        flag_response = pcap.next_packet()
        if len(flag_response) > 60:
            break
    _len, = struct.unpack("!H", flag_response[58:60])
    _data = proto.encrypt_bytes(flag_response[60:], vpn_key)
    print(_data[28:_len].decode("utf-8").strip())
