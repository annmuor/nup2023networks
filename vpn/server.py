import ctypes
import threading
from _socket import inet_ntoa
from struct import unpack
from threading import Thread
from typing import Tuple

import libpcap


class VPNServerClient(object):
    def __init__(self, src, dst, smac, dmac):
        pass

    def had_handshake(self) -> bool:
        pass

    def send_handshake(self, interface):
        pass

    def send_data(self, interface, data):
        pass

    def encode_and_send(self, interface, data):
        pass


def select_next_client_ip(self) -> str:
    pass


def gen_crypto_key(self) -> str:
    pass


def send_icmp_handshake(eth_hdr, src, dst, client_ip, netmask, key):
    pass


def unpack_eth_header(header) -> Tuple[bytes, bytes, int]:
    return unpack("!6s6sH", header)


def unpack_ip_header(header) -> Tuple[str, str, int, int]:
    ip_ihl_ver, ip_tos, ip_len, ip_id, ip_frag, ip_ttl, ip_proto, ip_check, \
        ip_saddr, ip_daddr = unpack('!BBHHHBBH4s4s', header)
    return inet_ntoa(ip_saddr), inet_ntoa(ip_daddr), ip_proto, ip_len


def unpack_icmp_header(header):
    icmp_type, icmp_code, checksum, _id, seq, timestamp = unpack("!BBHHH16s", header)
    return icmp_type, icmp_code, _id, seq


class VPNServer(object):
    def __init__(self, inner_ip, outer_int, ):
        self.inner_int = "lo"
        self.inner_ip = inner_ip
        self.inner_pcap = None
        self.outer_int = outer_int
        self.outer_pcap = None
        self.clients = {}
        self.lock = threading.Lock()

    def init_libpcap(self):
        try:
            err_buf = ctypes.create_string_buffer(libpcap.PCAP_ERRBUF_SIZE)
            self.inner_pcap = libpcap.create(self.inner_int.encode("utf-8"), err_buf)
            if not self.inner_pcap:
                print(f"Error: {err_buf}")
                exit(1)
            libpcap.set_immediate_mode(self.inner_pcap, 1)
            libpcap.setdirection(self.inner_pcap, libpcap.PCAP_D_IN)
            libpcap.set_snaplen(self.inner_pcap, 65535)
            self.outer_pcap = libpcap.create(self.outer_int.encode("utf-8"), err_buf)
            if not self.outer_pcap:
                print(f"Error: {err_buf}")
                exit(1)
            libpcap.set_immediate_mode(self.outer_pcap, 1)
            libpcap.set_snaplen(self.outer_pcap, 65535)
            libpcap.set_promisc(self.outer_pcap, 1)
        except Exception as e:
            print(f"init_libpcap went wrong: {e}")
            exit(1)

    def run(self):
        self.init_libpcap()
        Thread(target=self.thread_inner, name="thread_inner").start()
        self.thread_outer()

    def thread_outer(self):
        if libpcap.activate(self.outer_pcap) < 0:
            print("Failed to activate outer pcap")
            exit(1)
        while True:
            hdr = libpcap.pkthdr()
            data = libpcap.next(self.outer_pcap, hdr)
            buff = bytes([data[x] for x in range(0, hdr.caplen)])
            dst_mac, src_mac, eth_type = unpack_eth_header(buff[:14])
            if eth_type != 0x0800:  # Not IP protocol
                continue
            ip_src, ip_dst, ip_proto, ip_len = unpack_ip_header(buff[14:34])
            if ip_proto != 0x01:  # Not ICMP
                continue
            icmp_type, icmp_code, icmp_id, icmp_seq = unpack_icmp_header(buff[34:58])
            data = buff[58:]
            print(
                f"[outer] got {ip_src} -> {ip_dst} {ip_proto} {ip_len} {icmp_type} {icmp_code} {icmp_id} {icmp_seq} {data} packet")
            if icmp_type != 0x08 or icmp_code != 0x00 or icmp_seq != 0xffff:
                continue
            client = None
            if ip_src in self.clients:
                client = self.clients[ip_src]
            else:
                client = VPNServerClient(src=ip_src, dst=ip_dst, smac=src_mac, dmac=dst_mac)
            if client is None:
                continue
            if not client.had_handshake():
                # write client his IP back
                client.send_handshake(self.outer_int)
            else:
                # write client's packet into inner interface
                client.send_data(self.inner_int, data)

    def thread_inner(self):
        if libpcap.activate(self.inner_pcap) < 0:
            print("Failed to activate outer pcap")
            exit(1)
        while True:
            hdr = libpcap.pkthdr()
            data = libpcap.next(self.inner_pcap, hdr)
            buff = bytes([data[x] for x in range(0, hdr.caplen)])
            mac_dst, mac_src, eth_type = unpack_eth_header(buff[:14])
            if eth_type != 0x0800:  # Not IP datagram
                continue
            ip_src, ip_dst, ip_proto, ip_len = unpack_ip_header(buff[14:34])
            print(f"[inner] got {ip_src} -> {ip_dst} {ip_proto} {ip_len} packet")
            if ip_dst == self.inner_ip:
                continue
            print(f"[inner] got {ip_src} -> {ip_dst} {ip_proto} {ip_len} packet")
            client = None
            if ip_dst in self.clients:
                client = self.clients[ip_dst]
            if client is None:
                continue
            client.encode_and_send(self.outer_int, buff[14:])  # keep all stuff as it was except for MAC layer


if __name__ == '__main__':
    from sys import argv

    if len(argv) != 3:
        print(f"Usage: {argv[0]} <server_inner_ip> <outer int>")
        exit(1)
    VPNServer(argv[1], argv[2]).run()
