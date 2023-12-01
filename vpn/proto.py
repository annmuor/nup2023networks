import ctypes
from _socket import inet_ntoa, inet_aton
from struct import unpack, pack
from typing import Tuple

import libpcap

try:
    from random import randbytes
except ImportError:
    def randbytes(_len: int) -> bytes:
        from random import randint
        return bytearray([randint(0, 255) for _x in range(0, _len)])


def gen_crypto_key() -> bytes:
    return randbytes(8)


def unpack_eth_header(header) -> Tuple[bytes, bytes, int]:
    return unpack("!6s6sH", header)


def pack_eth_header(src: bytes, dst: bytes, ethtype: int) -> bytes:
    return pack("!6s6sH", dst, src, ethtype)


def internet_checksum(data: bytes) -> int:
    checksum = 0
    if len(data) % 2 != 0:
        data += b'\x00'  # add padding
    for i in range(0, len(data), 2):
        up, = unpack("!H", data[i:i + 2])
        checksum += up
    while checksum > 0xffff:
        checksum = (checksum & 0xffff) + (checksum >> 16)
    return (~checksum) & 0xffff


def unpack_ip_header(header) -> Tuple[str, str, int, int]:
    ip_ihl_ver, ip_tos, ip_len, ip_id, ip_frag, ip_ttl, ip_proto, ip_check, \
        ip_saddr, ip_daddr = unpack('!BBHHHBBH4s4s', header)
    return inet_ntoa(ip_saddr), inet_ntoa(ip_daddr), ip_proto, ip_len


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


def encrypt_bytes(data: bytes, key: bytes) -> bytes:
    ret = bytearray()
    _rest = 8 - (len(data) % len(key))
    data += randbytes(_rest)
    for b in range(0, len(data), len(key)):
        for k in range(0, len(key)):
            ret.append(data[b + k] ^ key[k])
    return ret


def netmask_to_prefix(netmask):
    int_mask, = unpack("!L", inet_aton(netmask))
    for shift_bit in range(0, 32):
        _prefix = 1 << shift_bit
        if int_mask & _prefix == _prefix:
            return 32 - shift_bit
    return 32


def repack_packet_with_checksum(packet: bytes) -> bytes:
    ip_saddr, ip_daddr, _proto, _len = unpack_ip_header(packet[:20])
    if _proto == 0x06:  # tcp
        sport, dport, tcp_seq, tcp_ack, tcp_doff, \
            tcp_flags, tcp_window, check, urg = unpack('!HHLLBBHHH', packet[20:40])
        data = packet[40:]
        phdr = pack("!4s4sBBH", inet_aton(ip_saddr), inet_aton(ip_daddr), 0, 0x06, len(packet) - 20)
        tcp_zero_hdr = pack('!HHLLBBHHH', sport, dport, tcp_seq, tcp_ack, tcp_doff,
                            tcp_flags, tcp_window, 0, urg)
        check = internet_checksum(phdr + tcp_zero_hdr + data)
        tcp_hdr = pack('!HHLLBBHHH', sport, dport, tcp_seq, tcp_ack, tcp_doff,
                       tcp_flags, tcp_window, check, urg)

        ip_hdr = pack_ip_header(ip_saddr, ip_daddr, 0x06, 40 + len(data))
        return ip_hdr + tcp_hdr + data

    if _proto == 0x11:  # udp
        sport, dport, _udp_len, chksum = unpack("!HHHH", packet[20:28])
        phdr = pack("!4s4sBBH", inet_aton(ip_saddr), inet_aton(ip_daddr), 0, 0x11, _udp_len)
        udp_zero_hdr = pack("!HHHH", sport, dport, _udp_len, 0)
        data = packet[28:]
        chksum = internet_checksum(phdr + udp_zero_hdr + data)
        udp_hdr = pack("!HHHH", sport, dport, _udp_len, chksum)
        ip_hdr = pack_ip_header(ip_saddr, ip_daddr, 0x11, 20 + 8 + len(data))
        return ip_hdr + udp_hdr + data
    return packet


def mac_to_bytes(mac: str) -> bytes:
    return bytes([int(x, 16) for x in mac.split(':')])


class PcapWrapper(object):
    def __init__(self, interface: str):
        err_buf = ctypes.c_buffer(libpcap.PCAP_ERRBUF_SIZE)
        if libpcap.init(libpcap.PCAP_CHAR_ENC_UTF_8, err_buf) != 0:
            print(f"pcap_init failed: {err_buf}")
            exit(0)
        self.handler = libpcap.create(interface.encode("utf-8"), err_buf)
        if self.handler is None:
            print(f"pcap_create failed: {err_buf}")
            exit(0)
        self.filter = None
        libpcap.set_snaplen(self.handler, 65535)
        libpcap.set_immediate_mode(self.handler, 1)

    def set_filter(self, _filter: str):
        bpf = libpcap.bpf_program()
        if libpcap.compile(self.handler, bpf, _filter.encode("utf-8"), 1, libpcap.PCAP_NETMASK_UNKNOWN) == 0:
            self.filter = bpf

    def start_capture(self):
        if libpcap.activate(self.handler) != 0:
            libpcap.perror(self.handler, "pcap_activate error: ".encode("utf-8"))
            exit(0)
        if self.filter is not None:
            libpcap.setfilter(self.handler, self.filter)

    def next_packet(self) -> bytes:
        hdr = libpcap.pkthdr()
        data = libpcap.next(self.handler, hdr)
        return bytes([data[x] for x in range(0, hdr.caplen)])

    def inject_packet(self, packet: bytes):
        if libpcap.inject(self.handler, packet, len(packet)) <= 0:
            libpcap.perror(self.handler, "inject_activate error: ".encode("utf-8"))
