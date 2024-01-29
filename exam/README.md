## NUP23 Exam

1. You can download your files from [file service](https://annmuor.im/exam/)
2. You shall insert your answers into [challenges page](https://8255344e21fcaf7b.annmuor.im/challenges)
3. Your task code is visible into the challenges page
4. Your student code is visible into your [profile](https://8255344e21fcaf7b.annmuor.im/user)

#### PCAP - 12% ( 120 points )

- You're given a pcap with large ( > 100000 ) amount of packets
- Your goal is to find the flag into **multicast** UDP **packet** with **broken** IP checksum.
- This the only packet contains flag

#### DNS - 14% ( 140 points )

- You're given a binary that works as a DNS server.
- It listens UDP and TCP port 6053 on 127.0.0.1 and answers to some type of queries, like A, CNAME and so on.
- Try to get all the data from the server to find the flag.

You may also need to use HEX2ASCII decoder, like

```python3
bytes.fromhex("557365206469672C204C756B6521").decode("utf-8")
```

#### HTTP - 14% ( 140 points )

- You're given a binary that works as an HTTP server.
- This HTTP server uses H/1.1337 HTTP version that is unsupported in most browsers.
- Start from / and follow the instructions to get your flag.

#### TCP - 15% ( 150 points )

You're given a binary that works as TCP server.
Your goal is to connect to the TCP port the program listens, so find the port first.
Your source port must be the same as the destination port.

After the connection is established - send the "getflag" command.
No more, no less. No quotes, no CRLF.

Look into console output to get the idea why it's not working. Trial and error are expected.

#### WIFI - 15% ( 150 points )

You're given a pcap file with captured WI-FI traffic. Using all the tools you may find on the Internet, decrypt the
traffic and find the flag.
P.S. Flag is not so obvious seen, it's somewhere in the traffic exchange.

#### TLS - 15% ( 150 points )

- You're given a binary that listens TCP port 4888 with SNI-enabled SSL/TLS.
- Your goal is to connect to the server with correct parameters and send "getflag" command.
- Look into console output to get the idea why it's not working. Trial and error are expected.

#### REV - 15% ( 150 points )

You're given a pcap file with captured traffic of unknown protocol. Also, you're given the protocol details in writings.
Your goal is to reverse engineer the protocol, collect the data and find the flag.

