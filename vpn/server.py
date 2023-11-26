import ctypes
import threading
from _socket import inet_ntoa, inet_aton
from random import randbytes
from struct import unpack, pack
from threading import Thread
from typing import Tuple

import libpcap

last_ip = None


def select_next_client_ip() -> str:
    global last_ip
    if last_ip:
        target = inet_ntoa(pack("!L", last_ip))
        last_ip += 1
    else:
        target = '127.0.0.1'
    return target


def gen_crypto_key() -> bytes:
    return randbytes(8)


def unpack_eth_header(header) -> Tuple[bytes, bytes, int]:
    return unpack("!6s6sH", header)


def pack_eth_header(src: bytes, dst: bytes, ethtype: int) -> bytes:
    return pack("!6s6sH", dst, src, ethtype)


def unpack_ip_header(header) -> Tuple[str, str, int, int]:
    ip_ihl_ver, ip_tos, ip_len, ip_id, ip_frag, ip_ttl, ip_proto, ip_check, \
        ip_saddr, ip_daddr = unpack('!BBHHHBBH4s4s', header)
    return inet_ntoa(ip_saddr), inet_ntoa(ip_daddr), ip_proto, ip_len


def internet_checksum(data: bytes) -> int:
    checksum = 0
    if len(data) % 2 != 0:
        data += b'\x00'  # add padding
    for i in range(0, len(bytes), 2):
        up = unpack("!H", data[i:i + 2])
        checksum += up
    while checksum > 0xffff:
        checksum = (checksum & 0xffff) + (checksum >> 16)
    return ~checksum


def pack_ip_header(src: str, dst: str, ip_proto: int, _len: int) -> bytes:
    no_checksum_hdr = pack("!BBHHHBBH4s4s", 0x45, 00, _len, 0, 0x4000, 64, ip_proto, 0, inet_aton(src), inet_aton(dst))
    checksum = internet_checksum(no_checksum_hdr)
    return pack("!BBHHHBBH4s4s", 0x45, 00, _len, 0, 0x4000, 64, ip_proto, checksum, inet_aton(src), inet_aton(dst))


def unpack_icmp_header(header) -> Tuple[int, int, int, int]:
    icmp_type, icmp_code, checksum, _id, seq, timestamp = unpack("!BBHHH16s", header)
    return icmp_type, icmp_code, _id, seq


def pack_icmp(icmp_type: int, icmp_code: int, _id: int, seq: int, data) -> bytes:
    no_checksum_header = pack("!BBHHH", icmp_type, icmp_code, 0, _id, seq)
    no_checksum_header += b'\x00' * 16
    no_checksum_header += data
    checksum = internet_checksum(no_checksum_header)
    checksum_header = pack("!BBHHH", icmp_type, icmp_code, checksum, _id, seq)
    return checksum_header + b'\x00' * 16 + data


class VPNServerClient(object):
    def __init__(self, cli_ip, srv_ip, cli_mac, srv_mac):
        self.cli_ip = cli_ip
        self.srv_ip = srv_ip
        self.cli_mac = cli_mac
        self.srv_mac = srv_mac
        self.vpn_ip = select_next_client_ip()
        self.vpn_key = gen_crypto_key()
        self._handshake = False
        print(f"new vpn client: {cli_ip}:{self.vpn_ip}")

    def had_handshake(self) -> bool:
        return self._handshake

    def send_handshake(self, interface):
        data = pack("4s4s8s", inet_aton(self.vpn_ip), inet_aton('255.255.255.0'), self.vpn_key)
        eth_hdr = pack_eth_header(self.cli_mac, self.srv_mac, 0x0800)
        icmp_data = pack_icmp(0, 0, 0xffff, 0xffff, data)
        ip_hdr = pack_ip_header(self.cli_ip, self.srv_ip, 0x01, len(data) + 20)
        buffer = eth_hdr + ip_hdr + icmp_data
        libpcap.inject(interface, buffer, len(buffer))
        self._handshake = True
        print(f"[outer] sent handshake: {self.cli_ip}:{self.vpn_ip} -> {buffer}")

    def send_data(self, interface, data, _len):
        eth_hdr = pack_eth_header(b'\x00' * 6, b'\x00' * 6, 0x0800)
        # TODO: decode data
        buffer = eth_hdr + data[:_len]
        libpcap.inject(interface, buffer, len(buffer))
        print(f"[inner] sent data: {self.cli_ip}:{self.vpn_ip} -> {buffer}")

    def encode_and_send(self, interface, data):
        eth_hdr = pack_eth_header(self.cli_mac, self.srv_mac, 0x0800)
        # TODO: encode data
        icmp_data = pack_icmp(0, 0, len(data), 0xffff, data)
        ip_hdr = pack_ip_header(self.cli_ip, self.srv_ip, 0x01, len(icmp_data) + 20)
        buffer = eth_hdr + ip_hdr + icmp_data
        libpcap.inject(interface, buffer, len(buffer))
        print(f"[outer] sent data: {self.cli_ip}:{self.vpn_ip} -> {buffer}")


class VPNServer(object):
    def __init__(self, inner_ip, outer_int, ):
        global last_ip
        self.inner_int = "lo"
        self.inner_ip = inner_ip
        self.inner_pcap = None
        self.outer_int = outer_int
        self.outer_pcap = None
        self.clients = {}
        self.lock = threading.Lock()
        last_ip, = unpack("!L", inet_aton(self.inner_ip))
        last_ip += 10

    def init_libpcap(self):
        try:
            err_buf = ctypes.create_string_buffer(libpcap.PCAP_ERRBUF_SIZE)
            self.inner_pcap = libpcap.create(self.inner_int.encode("utf-8"), err_buf)
            if not self.inner_pcap:
                print(f"Error: {err_buf}")
                exit(1)
            libpcap.set_immediate_mode(self.inner_pcap, 1)
            libpcap.set_snaplen(self.inner_pcap, 65535)
            self.outer_pcap = libpcap.create(self.outer_int.encode("utf-8"), err_buf)
            if not self.outer_pcap:
                print(f"Error: {err_buf}")
                exit(1)
            libpcap.set_immediate_mode(self.outer_pcap, 1)
            libpcap.set_snaplen(self.outer_pcap, 65535)
            libpcap.set_promisc(self.outer_pcap, 1)
            libpcap.setdirection(self.outer_pcap, libpcap.PCAP_D_IN)
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
            try:
                hdr = libpcap.pkthdr()
                data = libpcap.next(self.outer_pcap, hdr)
                buff = bytes([data[x] for x in range(0, hdr.caplen)])
                mac_dst, mac_src, eth_type = unpack_eth_header(buff[:14])
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
                with self.lock:
                    if ip_src in self.clients:
                        client = self.clients[ip_src]
                    else:
                        client = VPNServerClient(cli_ip=ip_src, srv_ip=ip_dst, cli_mac=mac_src, srv_mac=mac_dst)
                if client is None:
                    continue
                if not client.had_handshake():
                    # write client his IP back
                    client.send_handshake(self.outer_pcap)
                else:
                    # write client's packet into inner interface
                    client.send_data(self.inner_pcap, data, icmp_id)
            except KeyboardInterrupt:
                exit(1)
            except:
                pass

    def thread_inner(self):
        if libpcap.activate(self.inner_pcap) < 0:
            print("Failed to activate outer pcap")
            exit(1)
        while True:
            try:
                hdr = libpcap.pkthdr()
                data = libpcap.next(self.inner_pcap, hdr)
                buff = bytes([data[x] for x in range(0, hdr.caplen)])
                mac_dst, mac_src, eth_type = unpack_eth_header(buff[:14])
                if eth_type != 0x0800:  # Not IP datagram
                    continue
                ip_src, ip_dst, ip_proto, ip_len = unpack_ip_header(buff[14:34])
                if ip_dst == self.inner_ip:
                    continue
                if ip_dst == ip_src:  # all this 127.0.0.1 @ lo traffic goes home
                    continue
                print(f"[inner] got {ip_src} -> {ip_dst} {ip_proto} {ip_len} packet")
                client = None
                with self.lock:
                    if ip_dst in self.clients:
                        client = self.clients[ip_dst]
                if client is None:
                    continue
                client.encode_and_send(self.outer_pcap, buff[14:])  # keep all stuff as it was except for MAC layer
            except KeyboardInterrupt:
                exit(1)
            except:
                pass


if __name__ == '__main__':
    from sys import argv

    if len(argv) != 3:
        print(f"Usage: {argv[0]} <server_inner_ip> <outer int>")
        exit(1)
    VPNServer(argv[1], argv[2]).run()
