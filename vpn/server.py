import ctypes
import subprocess
import threading
import time
from _socket import inet_ntoa, inet_aton
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


class VPNServerClient(object):
    def __init__(self, cli_ip, srv_ip, cli_mac, srv_mac):
        self.cli_ip = cli_ip
        self.srv_ip = srv_ip
        self.cli_mac = cli_mac
        self.srv_mac = srv_mac
        self.vpn_ip = select_next_client_ip()
        self.vpn_key = proto.gen_crypto_key()
        self._handshake = False
        self._last = time.time()
        print(f"new vpn client: {cli_ip}:{self.vpn_ip}")

    def had_handshake(self) -> bool:
        return self._handshake

    def is_dead(self) -> bool:
        return time.time() - self._last > 30


class VPNServer(object):
    def __init__(self, inner_ip, netmask, outer_int, ):
        global last_ip
        self.inner_int = "lo"
        self.inner_ip = inner_ip
        self.netmask = netmask
        self.inner_pcap = None
        self.outer_int = outer_int
        self.outer_pcap = None
        self.clients = {}
        self.lock = threading.Lock()
        last_ip, = unpack("!L", inet_aton(self.inner_ip))
        last_ip += 10
        self._inner_ip_int, = unpack("!L", inet_aton(self.inner_ip))
        self._inner_mask_int, = unpack("!L", inet_aton(self.netmask))

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

    def is_my_client(self, ip):
        _ip_int, = unpack("!L", inet_aton(ip))
        return True if _ip_int & self._inner_mask_int == self._inner_ip_int & self._inner_mask_int \
            else False

    def send_handshake(self, client: VPNServerClient):
        data = pack("4s4s8s", inet_aton(client.vpn_ip), inet_aton(self.netmask), client.vpn_key)
        eth_hdr = proto.pack_eth_header(client.srv_mac, client.cli_mac, 0x0800)
        icmp_data = proto.pack_icmp(0, 0, 0xffff, 0xffff, data)
        ip_hdr = proto.pack_ip_header(client.srv_ip, client.cli_ip, 0x01, len(icmp_data) + 20)
        buffer = eth_hdr + ip_hdr + icmp_data
        libpcap.inject(self.outer_pcap, buffer, len(buffer))
        client._handshake = True
        client._last = time.time()
        print(f"[outer] sent handshake: {client.cli_ip}:{client.vpn_ip} -> {buffer}")

    def receive_data_from_client(self, client: VPNServerClient, data: bytes, _len: int):
        eth_hdr = proto.pack_eth_header(b'\x00' * 6, b'\x00' * 6, 0x0800)
        data = proto.encrypt_bytes(data, client.vpn_key)
        data = data[:_len]
        # if this is the data for _our_ client - let's check the IP header
        if len(data) < 20: # keep-alive ?
            return
        src, dst, _proto, _len = proto.unpack_ip_header(data[:20])
        if src != client.vpn_ip:
            print(f"Client sent us a packet from not their IP: {src} != {client.vpn_ip}")
            return
        # check if this is for our client
        _target_client = None
        if self.is_my_client(dst) and dst != self.inner_ip:
            with self.lock:
                if dst in self.clients:
                    _target_client = self.clients[dst]
                else:
                    print(f"Package for my client {dst}, but I haven't this client connected here")
                    return
        if _target_client is not None:
            self.send_data_to_client(_target_client, data)
        else:
            buffer = eth_hdr + data
            libpcap.inject(self.inner_pcap, buffer, len(buffer))
            client._last = time.time()
            print(f"[inner] sent data: {client.cli_ip}:{client.vpn_ip} -> {buffer}")

    def send_data_to_client(self, client: VPNServerClient, data: bytes):
        eth_hdr = proto.pack_eth_header(client.cli_mac, client.srv_mac, 0x0800)
        data = proto.encrypt_bytes(data, client.vpn_key)
        icmp_data = proto.pack_icmp(0, 0, len(data), 0xffff, data)
        ip_hdr = proto.pack_ip_header(client.cli_ip, client.srv_ip, 0x01, len(icmp_data) + 20)
        buffer = eth_hdr + ip_hdr + icmp_data
        libpcap.inject(self.outer_pcap, buffer, len(buffer))
        print(f"[outer] sent data: {client.cli_ip}:{client.vpn_ip} -> {buffer}")

    def thread_outer(self):
        if libpcap.activate(self.outer_pcap) < 0:
            print("Failed to activate outer pcap")
            exit(1)
        while True:
            try:
                hdr = libpcap.pkthdr()
                data = libpcap.next(self.outer_pcap, hdr)
                buff = bytes([data[x] for x in range(0, hdr.caplen)])
                if len(buff) < 34:
                    continue
                mac_dst, mac_src, eth_type = proto.unpack_eth_header(buff[:14])
                if eth_type != 0x0800:  # Not IP protocol
                    continue
                ip_src, ip_dst, ip_proto, ip_len = proto.unpack_ip_header(buff[14:34])
                if ip_proto != 0x01:  # Not ICMP
                    continue
                icmp_type, icmp_code, icmp_id, icmp_seq = proto.unpack_icmp_header(buff[34:58])
                data = buff[58:]
                print(
                    f"[outer] got {ip_src} -> {ip_dst} {ip_proto} {ip_len} {icmp_type} {icmp_code} {icmp_id} {icmp_seq} {data} packet")
                if icmp_type != 0x08 or icmp_code != 0x00 or icmp_seq != 0xffff:
                    continue
                client = None
                with self.lock:
                    if ip_src in self.clients:
                        client = self.clients[ip_src]
                        client._last = time.time()
                    else:
                        client = VPNServerClient(cli_ip=ip_src, srv_ip=ip_dst, cli_mac=mac_src, srv_mac=mac_dst)
                        self.clients[ip_src] = client
                if not client.had_handshake():
                    # write a client his IP back
                    self.send_handshake(client)
                else:
                    # write client's packet into inner interface
                    self.receive_data_from_client(client, data, icmp_id)
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
                if len(buff) < 34:
                    continue
                mac_dst, mac_src, eth_type = proto.unpack_eth_header(buff[:14])
                if eth_type != 0x0800:  # Not IP datagram
                    continue
                ip_src, ip_dst, ip_proto, ip_len = proto.unpack_ip_header(buff[14:34])
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
                client._last = time.time()
                self.send_data_to_client(client, buff[14:])  # keep all stuff as it was except for MAC layer
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
        # loop and list clients that are expired
        # set IP address
        prefix = proto.netmask_to_prefix(self.netmask)
        prefix_ip = self._inner_ip_int & self._inner_mask_int
        prefix_ip = inet_ntoa(pack("!L", prefix_ip))
        subprocess.run(["ip", "addr", "add", f"{self.inner_ip}/32", "dev", "lo"])
        subprocess.run(["ip", "route", "add", f"{prefix_ip}/{prefix}", "dev", "lo", "src", self.inner_ip])
        try:
            while True:
                with self.lock:
                    to_remove = [x for x in self.clients.keys() if self.clients[x].is_dead()]
                    for key in to_remove:
                        del self.clients[key]
                        print(f"Client {key} is considered inactive and dropped")
                time.sleep(30)
        except KeyboardInterrupt:
            print("Exiting....")
            subprocess.run(["ip", "route", "del", f"{prefix_ip}/{prefix}", "dev", "lo", "src", self.inner_ip])
            subprocess.run(["ip", "addr", "del", f"{self.inner_ip}/32", "dev", "lo"])
            exit(0)


if __name__ == '__main__':
    from sys import argv

    if len(argv) != 4:
        print(f"Usage: {argv[0]} <server_inner_ip> <netmask> <outer int>")
        exit(1)
    VPNServer(argv[1], argv[2], argv[3]).run()
