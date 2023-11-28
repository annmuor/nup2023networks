from _socket import inet_ntoa, inet_aton
from random import randbytes
from struct import unpack, pack
from typing import Tuple


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
    _rest = len(key) - len(data) if len(data) < len(key) \
        else len(data) % len(key)
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
