import ctypes
import time
from _socket import inet_ntoa
from struct import unpack, pack
from threading import Thread

import libpcap

import proto

last_ip = None


def select_next_client_ip() -> str:
    global last_ip
    if last_ip:
        target = inet_ntoa(pack("!L", last_ip))
        last_ip += 1
    else:
        target = '127.0.0.1'
    return target


class VPNClient(object):
    def __init__(self, outer_int, remote_ip):
        global last_ip
        self.inner_int = "lo"
        self.inner_ip = None
        self.netmask = None
        self.inner_pcap = None
        self.outer_int = outer_int
        self.remote_ip = remote_ip
        self.outer_pcap = None
        self.vpn_key = bytearray([247, 91, 148, 85, 213, 102, 18, 246])

    def init_libpcap(self):
        try:
            err_buf = ctypes.create_string_buffer(libpcap.PCAP_ERRBUF_SIZE)
            self.inner_pcap = libpcap.create(self.inner_int.encode("utf-8"), err_buf)
            if not self.inner_pcap:
                print(f"Error: {err_buf}")
                exit(1)
            libpcap.set_immediate_mode(self.inner_pcap, 1)
            libpcap.set_snaplen(self.inner_pcap, 65535)
            libpcap.set_promisc(self.inner_pcap, 1)
            self.outer_pcap = libpcap.create(self.outer_int.encode("utf-8"), err_buf)
            if not self.outer_pcap:
                print(f"Error: {err_buf}")
                exit(1)
            libpcap.set_immediate_mode(self.outer_pcap, 1)
            libpcap.set_snaplen(self.outer_pcap, 65535)
        except Exception as e:
            print(f"init_libpcap went wrong: {e}")
            exit(1)

    def send_handshake(self):
        data = b'\xde\xad\xbe\xef\xde\xad\xbe\xef'
        eth_hdr = proto.pack_eth_header(b'\xbc\x54\x2f\xcb\x7b\x2c', b'\xe0\x1c\xfc\x96\xd8\x8c', 0x0800)
        icmp_data = proto.pack_icmp(8, 0, 0xffff, 0xffff, data)
        ip_hdr = proto.pack_ip_header('192.168.0.144', self.remote_ip, 0x01, len(icmp_data) + 20)
        buffer = eth_hdr + ip_hdr + icmp_data
        print("handshake === ", [x for x in buffer])
        libpcap.inject(self.outer_pcap, buffer, len(buffer))

    def thread_outer(self):
        if libpcap.activate(self.outer_pcap) < 0:
            print("Failed to activate outer pcap")
            exit(1)
        self.send_handshake()
        _handshake = False
        while True:
            try:
                hdr = libpcap.pkthdr()
                data = libpcap.next(self.outer_pcap, hdr)
                buff = bytes([data[x] for x in range(0, hdr.caplen)])
                mac_dst, mac_src, eth_type = proto.unpack_eth_header(buff[:14])
                if eth_type != 0x0800:  # Not IP protocol
                    continue
                ip_src, ip_dst, ip_proto, ip_len = proto.unpack_ip_header(buff[14:34])
                if ip_proto != 0x01:  # Not ICMP
                    continue
                icmp_type, icmp_code, icmp_id, icmp_seq = proto.unpack_icmp_header(buff[34:58])
                data = buff[58:]
                print(
                    f"[outer] got {ip_src} -> {ip_dst} {ip_proto} {ip_len} {icmp_type} {icmp_code} {icmp_id} {icmp_seq} {data}")
                if icmp_type != 0x00 or icmp_code != 0x00 or icmp_seq != 0xffff:
                    continue
                if ip_src != self.remote_ip:
                    continue
                if ip_dst == self.remote_ip:
                    continue
                if icmp_id == 0xffff and not _handshake:  # this is our handshake
                    self.inner_ip, self.netmask, self.vpn_key = unpack("4s4s8s", data)
                    self.inner_ip = inet_ntoa(self.inner_ip)
                    self.netmask = inet_ntoa(self.netmask)
                    print(f"[handshake] got response: {self.inner_ip}/{self.netmask} = {self.vpn_key}")
                    _handshake = True
                else:
                    eth_hdr = proto.pack_eth_header(b'\x00' * 6, b'\x00' * 6, 0x0800)
                    _len, = unpack("!H", data[:2])
                    data = proto.encrypt_bytes(data[2:], self.vpn_key)
                    data = eth_hdr + data[:_len]
                    libpcap.inject(self.inner_pcap, data, len(data))
            except Exception as e:
                print(f"thread_outer exception: {e}")

    def thread_inner(self):
        if libpcap.activate(self.inner_pcap) < 0:
            print("Failed to activate outer pcap")
            exit(1)
        while True:
            try:
                hdr = libpcap.pkthdr()
                data = libpcap.next(self.inner_pcap, hdr)
                buff = bytes([data[x] for x in range(0, hdr.caplen)])
                mac_dst, mac_src, eth_type = proto.unpack_eth_header(buff[:14])
                if eth_type != 0x0800:  # Not IP datagram
                    continue
                ip_src, ip_dst, ip_proto, ip_len = proto.unpack_ip_header(buff[14:34])
                if ip_dst == self.inner_ip:
                    continue
                if ip_dst == ip_src:  # all this 127.0.0.1 @ lo traffic goes home
                    continue
                print(f"[inner] got {ip_src} -> {ip_dst} {ip_proto} {ip_len} packet")
                _len = pack("!H", len(buff[14:]))
                data = proto.encrypt_bytes(buff[14:], self.vpn_key)
                data = _len + data
                eth_hdr = proto.pack_eth_header(b'\xbc\x54\x2f\xcb\x7b\x2c', b'\xe0\x1c\xfc\x96\xd8\x8c', 0x0800)
                icmp_data = proto.pack_icmp(8, 0, 0xffff, 0xffff, data)
                ip_hdr = proto.pack_ip_header('192.168.0.144', self.remote_ip, 0x01, len(icmp_data) + 20)
                buffer = eth_hdr + ip_hdr + icmp_data
                libpcap.inject(self.outer_pcap, buffer, len(buffer))
            except Exception as e:
                print(f"thread_inner exception: {e}")

    def run(self):
        self.init_libpcap()
        inner = Thread(target=self.thread_inner, name="thread_inner")
        inner.daemon = True
        inner.start()
        outer = Thread(target=self.thread_outer, name="thread_outer")
        outer.daemon = True
        outer.start()
        try:
            while True:
                time.sleep(2)
                eth_hdr = proto.pack_eth_header(b'\xbc\x54\x2f\xcb\x7b\x2c', b'\xe0\x1c\xfc\x96\xd8\x8c', 0x0800)
                data = pack("!H", 0)
                icmp_data = proto.pack_icmp(8, 0, 0xffff, 0xffff, data)
                ip_hdr = proto.pack_ip_header('192.168.0.144', self.remote_ip, 0x00, 20 + len(icmp_data))
                buffer = eth_hdr + ip_hdr + icmp_data
                libpcap.inject(self.outer_pcap, buffer, len(buffer))
        except KeyboardInterrupt:
            exit(0)


if __name__ == '__main__':
    VPNClient('wlp41s0', '162.19.155.86').run()
