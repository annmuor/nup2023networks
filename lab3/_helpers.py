#!/usr/bin/env python3
import socket
import struct
from typing import List, Tuple

def get_my_ip(target: str) -> Tuple[str, str]:
    test_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    test_sock.connect((target, 1))
    my_ip, _ = test_sock.getsockname()
    test_sock.close()
    return my_ip

def pack_ip_header(src, dst):
    ip_ihl = 5
    ip_ver = 4
    ip_tos = 0
    ip_len = 0
    ip_id = 33
    ip_frag = 0
    ip_ttl = 64
    ip_proto = socket.IPPROTO_TCP
    ip_check = 0
    ip_saddr = socket.inet_aton(src)
    ip_daddr = socket.inet_aton(dst)
    ip_ihl_ver = (ip_ver << 4) + ip_ihl
    return struct.pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_len, ip_id, ip_frag, ip_ttl, ip_proto, ip_check,
                       ip_saddr, ip_daddr)

def unpack_ip_header(header) -> Tuple[str, str]:
    ip_ihl_ver, ip_tos, ip_len, ip_id, ip_frag, ip_ttl, ip_proto, ip_check, \
            ip_saddr, ip_daddr = struct.unpack('!BBHHHBBH4s4s', header)
    return socket.inet_ntoa(ip_saddr), socket.inet_ntoa(ip_daddr)

def pack_tcp_header(sport, dport, check=0):
    tcp_seq = 0
    tcp_ack = 0
    tcp_doff = (5 << 4) + 0
    tcp_flags = 0 + (1 << 1) + (0 << 2) + (0 << 3) + (0 << 4) + (0 << 5)
    tcp_window = 0
    tcp_hdr = struct.pack('!HHLLBBHHH', sport, dport, tcp_seq, tcp_ack, tcp_doff, tcp_flags, tcp_window, check,
                          0)
    return tcp_hdr

def unpack_tcp_header(header) -> Tuple[int, int, int]:
    sport, dport, tcp_seq, tcp_ack, tcp_doff, \
            tcp_flags, tcp_window, check, urg = struct.unpack('!HHLLBBHHH', header)
    return (sport, dport, tcp_flags)

def repack_tcp_header(src, dst, sport, dport):
    src_ip = socket.inet_aton(src)
    dst_ip = socket.inet_aton(dst)
    tcp_hdr = pack_tcp_header(sport, dport)
    hdr = struct.pack("!4s4sBBH", src_ip, dst_ip, 0, socket.IPPROTO_TCP, len(tcp_hdr))
    hdr = hdr + tcp_hdr
    check = 0
    for i in range(0, len(hdr), 2):
        w = (hdr[i] << 8) + (hdr[i + 1])
        check = check + w
    check = (check >> 16) + (check & 0xffff)
    check = ~check & 0xffff
    return pack_tcp_header(sport, dport, check)
