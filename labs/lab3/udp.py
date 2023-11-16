#!/usr/bin/env python3
import socket
from struct import pack
from time import sleep

# |--------------- UDP HEADER --------------|
# |    SOURCE PORT     |  DESTINATION PORT  | = 32 bits
# |--------------------|--------------------|
# |      LENGTH        |      CHECKSUM      | = 32 bits
# |-----------------------------------------|

def ip_header(src, dst):
    return pack("!BBHHHBBH4s4s", 69, 0, 0, 1, 0, 64, 17, 0, socket.inet_aton(src), socket.inet_aton(dst))

# pack function allows you to pack different values (bytes, shorts, ints, strings ) into bytes
# Format:
# ! - network byte order
# B unsigned char
# H unsigned short
# I unsigned int
# L unsigned long
# Q unsigned long long
# s char[]

my_ip = '10.10.10.99' # change to your ip
target_ip = '10.10.10.65'
# Warning: you need r00t to run this
# Good luck (:
sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
sock.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
ip_hdr = ip_header(my_ip, target_ip)
# TODO - fix this 2 variables
udp_hdr = b'00000000'
data = b'12345678910'
# /TODO

while True:
    sock.sendto(ip_hdr + udp_hdr + data, (target_ip, 0))
    sleep(1)
