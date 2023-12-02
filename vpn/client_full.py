import time
from threading import Thread

import proto


class VPNClient(object):
    def __init__(self, outer_int, my_ip, server_ip, my_mac, server_mac):
        self.inner_int = "lo"  # change this for mac ? or not?
        self.inner_ip = None
        self.netmask = None
        self.inner_pcap = None
        self.outer_int = outer_int
        self.my_ip = my_ip
        self.server_ip = server_ip
        self.my_mac = proto.mac_to_bytes(my_mac)
        self.server_mac = proto.mac_to_bytes(server_mac)
        self.outer_pcap = None
        self.vpn_key = bytes([0, 0, 0, 0, 0, 0, 0, 0])
        self.eth_header = proto.pack_eth_header(self.my_mac, self.server_mac, 0x0800)

    def init_libpcap(self):
        try:
            self.inner_pcap = proto.PcapWrapper(self.inner_int)
            self.outer_pcap = proto.PcapWrapper(self.outer_int)
            self.outer_pcap.set_filter("icmp[icmptype] = icmp-echoreply")
            self.inner_pcap.set_filter(f"net {self.inner_ip}/{self.netmask}")
        except Exception as e:
            print(f"init_libpcap went wrong: {e}")
            exit(1)

    def send_handshake(self):
        handshake = b''  # put a handshake here
        self.outer_pcap.inject_packet(self.eth_header + handshake)
        print("[outer] handshake sent")

    def thread_outer(self):
        self.outer_pcap.start_capture()
        self.send_handshake()
        _handshake = False
        while True:
            try:
                buff = self.outer_pcap.next_packet()
                mac_dst, mac_src, eth_type = proto.unpack_eth_header(buff[:14])
                if eth_type != 0x0800:  # Not IP protocol
                    continue
                ip_src, ip_dst, ip_proto, ip_len = proto.unpack_ip_header(buff[14:34])
                if ip_proto != 1:  # Not ICMP
                    continue
                if ip_src != self.server_ip:
                    continue
                icmp_type, icmp_code, icmp_id, icmp_seq = proto.unpack_icmp_header(buff[34:58])
                data = buff[58:]
                if icmp_seq != 65535:
                    continue
                if len(data) == 16 and not _handshake:  # this is our handshake
                    # unpack data to get key and all the stuff
                    # Create routing configuration as the server does
                    # Don't forget to add 192.168.254.0/24 network
                    # TODO: change to ifconfig / route for MAC
                    _handshake = True
                else:
                    data = b''  # decrypt and transfer data to loopback interface
                    self.inner_pcap.inject_packet(data)
            except Exception as e:
                print(f"thread_outer exception: {e}")

    def thread_inner(self):
        self.inner_pcap.start_capture()
        while True:
            try:
                buff = self.inner_pcap.next_packet()
                mac_dst, mac_src, eth_type = proto.unpack_eth_header(buff[:14])
                if eth_type != 0x0800:  # Not IP datagram
                    continue
                ip_src, ip_dst, ip_proto, ip_len = proto.unpack_ip_header(buff[14:34])
                if ip_dst == self.inner_ip:
                    continue
                if ip_dst == ip_src:  # all this 127.0.0.1 @ lo traffic goes home
                    continue
                print(f"[inner] got {ip_src} -> {ip_dst} {ip_proto} {ip_len} packet")
                data = b''  # create a packet using data you have here, encrypt it and send back to the server
                self.outer_pcap.inject_packet(self.eth_header + data)
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
        except KeyboardInterrupt:
            exit(0)


if __name__ == '__main__':
    my_ip = '10.10.10.??'
    vpn_server_ip = '10.10.10.1' if my_ip.startswith('10.10.10') else '10.10.11.1'
    my_mac = '00:00:00:00:00:00'  # use ifconfig | ip link to find your mac
    srv_mac = '00:00:00:00:00:00'  # use arp -a | ip neigh to find my mac... or your router's mac in case of WSL
    interface = 'eth0'  # your interface connected to the network
    VPNClient(interface, my_ip, vpn_server_ip, my_mac, srv_mac).run()
