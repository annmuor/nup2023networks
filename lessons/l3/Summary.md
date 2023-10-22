# Key takeouts

- TLS/SSL protocols are hard to implement and twice hard to debug
- The Internet is still built on trust
- TCP is reliable, but slow and not very secure
- UDP is cheap and is getting more use because of it

## TLS/SSL

- [TLS handshake process](https://www.cloudflare.com/learning/ssl/what-happens-in-a-tls-handshake/)
- [Diffie-Hellman key exchange](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange)
- [Current list of root CAs](https://www.checktls.com/showcas.html)

## UDP protocol

### Header

- source port (16 bits) - from 0 to 65535, sender application address within the computer
- destination port (16 bits) - from 0 to 65535, receiver application address within the computer
- packet length (16 bits)
- packet checksum (16 bits)

### Connection state

None. Connection is not set. You can set and receive anything. Called **stateless** protocol.

## TCP protocol

### Header

- source port (16 bits) - from 0 to 65535, sender application address within the computer
- destination port (16 bits) - from 0 to 65535, receiver application address within the computer
- sequence number (32 bits) - number of bytes sent, total
- acknowledge number (32 bits) - number of bytes received, total
- header length (4 bits) - number of 32-bits (4 bytes) words in the header. 5 by default
- reserved (6 bits) - for further use
- flags (6 bits) - look flags.
- window size (16 bits) - how much data we transfer before waiting for ACK
- checksum (16 bits) - for the header
- urgent pointer (16 bits) - for URG flag
- options (from 0 to 320 bits depends on header length field) - some options for TCP optional features
- 20 or more bytes in total

### Flags (from higher to lower bit)

- URG - to send urgent packets
- ACK - to acknowledge the connection or the packet
- PSH - to process the data immediately and not wait for the buffer
- RST - to abrupt the connection (connection refused error) in case of error
- SYN - to start connection
- FIN - to end the connection after all the data is transmitted

### TCP connection process

C - Client, S - Server

- C: send a TCP packet with SYN flag bits set, source and destination ports and options (if applicable), with zero data
- S: send a TCP packet with SYN and ACK flag bits set, source and destination ports and options (if applicable), with
  zero data
- C: send a TCP packet with ACK flag bits set, source and destination ports and options (if applicable), with zero data
- Now the client or the server may start sending the data, seq and ack fields are set to 1 on both ends
- C: send a TCP packet (seq = 1*, ack = 1*), len=5
- S: send a TCP packet (seq = 1*, ack = 6*), len=5, ACK flag
- C: send a TCP packet (seq = 6*, ack = 6*), len=10, ACK flag
- ....
- C: send a TCP packet with FIN flag set
- S: send a TCP packet with ACK flag set
- S: send a TCP packet with FIN flag set
- C: send a TCP packet with ACK flag set
- connection closed

** the sequence and acknowledge numbers may start from any numbers, so 1 is relative number, not absolute

## Labs

See [Labs](Labs.md) section