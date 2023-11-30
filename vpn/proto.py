from _socket import inet_ntoa, inet_aton
from struct import unpack, pack
from typing import Tuple
try:
    from random import randbytes
except ImportError:
    def randbytes(_len: int) -> bytes:
        from random import randint
        return bytearray([randint(0, 255) for _x in range(0,_len)])


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
    icmp_type, icmp_code, checksum, _id, seq = unpack("!BBHHH", header)
    return icmp_type, icmp_code, _id, seq


def pack_icmp(icmp_type: int, icmp_code: int, _id: int, seq: int, data) -> bytes:
    no_checksum_header = pack("!BBHHH", icmp_type, icmp_code, 0, _id, seq)
    no_checksum_header += data
    checksum = internet_checksum(no_checksum_header)
    checksum_header = pack("!BBHHH", icmp_type, icmp_code, checksum, _id, seq)
    return checksum_header


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


def pack_tcp_header(sport, dport, check=0):
    tcp_seq = 0
    tcp_ack = 0
    tcp_doff = (5 << 4) + 0
    tcp_flags = 0 + (1 << 1) + (0 << 2) + (0 << 3) + (0 << 4) + (0 << 5)
    tcp_window = 0
    tcp_hdr = pack('!HHLLBBHHH', sport, dport, tcp_seq, tcp_ack, tcp_doff, tcp_flags, tcp_window, check,
                   0)
    return tcp_hdr


def unpack_tcp_header(header) -> Tuple[int, int, int]:
    sport, dport, tcp_seq, tcp_ack, tcp_doff, \
        tcp_flags, tcp_window, check, urg = unpack('!HHLLBBHHH', header)
    return


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
