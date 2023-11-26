## VPN Server project

This VPN server uses PCAP library to do their job.
Guess what? You need to implement the client!

### How it works

It uses ICMP to encapsulate IP traffic inside. Why ICMP? Because it's so common, so no one will filter it.
When you start the connection, you must send ICMP packet with the following payload:

- type(1) = 0x08 ( echo request )
- code(1) = 0x00
- checksum(2) - valid
- ID(2) - 0xffff
- SEQ(2) - 0xffff
- Timestamp(16) - 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
- Data(8): 0xde 0xad 0xbe 0xef 0xde 0xad 0xbe 0xef

Server shall answer you with the following ICMP packet:

- type(1) = 0x00 ( echo request )
- code(1) = 0x00
- checksum(2) - valid
- ID(2) - 0xffff
- SEQ(2) - 0xffff
- Timestamp(16) - 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
- Data(20): client_ip network_mask encryption key

#### Fields

* Server IP - four bytes, network (BE) order
* Client IP - four bytes, network (BE) order
* Network Mask - four bytes, network (BE) order
* Encryption key - eight bytes

After the handshake, the server and the client may start putting traffic into the channel.
**Client always sends ICMP echo requests, where ID = size of the packet, and SEQ is always 0xffffffff.**
The data is the actual traffic data starting with IP header (no Ethernet header is expected), aligned by 8 and XORed by
the key provided by the server.

**Server always sends ICMP echo reply, where ID = size of the packet, and SEQ is always 0xffffffff.**
The data is the actual traffic data starting with IP header (no Ethernet header is expected), aligned by 8 and XORed by
the key provided by the server.

