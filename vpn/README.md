## VPN Server project

This VPN server uses PCAP library to do their job.
Guess what? You need to implement the client!

### Protocol

This VPN uses ICMP Echo-Request and Echo-Reply protocol

| FIELD     | BYTES | VALUE  |
|-----------|-------|--------|
| TYPE      | 1     | 8 or 0 |
| CODE      | 1     | 0      |
| ID        | 2     | 65535  |
| SEQ       | 2     | 65535  |
| TIMESTAMP | 16    | 0      |
| DATA      | Vary  | Vary   |

#### TYPE

Type is 8 for packages from CLIENT to SERVER and 0 for packages from SERVER to CLIENT

#### DATA

DATA may be the following:

- Handshake - CLIENT sends 0xde0xad0xbe0xef0xde0xad0xbe0xef ( 8 bytes )
- Handshake - SERVER sends IPv4 (4 bytes) NETMASK (4 bytes) KEY (8 bytes)
- Keep-alive - CLIENT sends 0 (2 bytes)
- IPv4 datagram - CLIENT or SERVER sends DATA LEN (2 bytes, NETWORK endinan) and ENCRYPTED DATA

#### ENCRYPTION

All data sent by CLIENT or SERVER are padded to be encrypted by XOR with KEY LENGTH (8).
So to send 68 bytes packet, CLIENT or SERVER must add 4 RANDOM BYTES and must send 72 BYTES, encrypted by XOR key
LEN field must be set to 68 though.

### How it works

Client starts the session by sending to server ICMP echo-request (type 8 code 0) package with SEQ 65535 and 2xdeadbeef
data.

Server responds by sending ICMP echo-reply (type 0 code 0) package with SEQ 65535 and assigned IPv4, Netmask and
Encryption Key.

After this session is considered ready and client and server may exchange data using ICMP echo-request and ICMP
echo-reply.

### Session Example
Client: 