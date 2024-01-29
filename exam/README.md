## NUP23 Exam files

### Schematics

```
           [BONUS]

  [WIFI] [TCP] [REV] [TLS]
      \   /      \   /
      [DNS]     [HTTP]
          \     /
          [PCAP]

```

#### PCAP - 12% ( 120 points )

You're given a pcap file with large  ( > 100000 ) amount of packets
Your goal is to find the flag into **multicast UDP packet** with **broken IP checksum**.

#### DNS - 14% ( 140 points )

You're given a binary for Linux/OSX Arm/OSX Intel/Windows that works as a DNS server.
It listens UDP and TCP port 6053 on 127.0.0.1 and answers to some type of queries, like A, CNAME and so on.
Try to get **all** the data from the server to find the flag.

You may also need to use HEX2ASCII decoder, like

```python3
bytes.
fromhex("557365206469672C204C756B6521").
decode("utf-8")
```

P.S. Do chmod 755 for Linux/OSX and [disable Gatekeeper](https://disable-gatekeeper.github.io/) for OSX.

#### HTTP - 14% ( 140 points )

You're given a binary for Linux/OSX Arm/OSX Intel/Windows that works as an HTTP server.
This HTTP server uses H/1.1337 HTTP version that is unsupported in most browsers.
Start from / and follow the instructions to get your flag.

P.S. Do chmod 755 for Linux/OSX and [disable Gatekeeper](https://disable-gatekeeper.github.io/) for OSX.


#### TCP - 15% ( 150 points )

You're given a binary for Linux/OSX Arm/OSX Intel/Windows that works as TCP server.
Your goal is to connect to the TCP port the program listens, so find the port first.
Your source port must be the same as the destination port.

After the connection is established - send the "getflag" command.
No more, no less. No quotes, no CRLF.

Look into console output to get the idea why it's not working. Trial and error are expected.

P.S. Do chmod 755 for Linux/OSX and [disable Gatekeeper](https://disable-gatekeeper.github.io/) for OSX.

#### WIFI - 15% ( 150 points )

You're given a pcap file with captured WIFI traffic. Using all the tools you may find on the Internet, decrypt the
traffic and find the flag.
P.S. Flag is not so obvious seen, it's somewhere in the traffic exchange.



#### TLS - 15% ( 150 points )

You're given a binary for Linux/OSX Arm/OSX Intel/Windows that listens TCP port 4888 with custom SSL/TLS.
You're also given a PCAP file with a single successfull connection. You may find there that TLS uses some unstandard
constants there.
Your goal is to connect to the port and send the "getflag" command.

Look into console output to get the idea why it's not working. Trial and error are expected.

P.S. Do chmod 755 for Linux/OSX and [disable Gatekeeper](https://disable-gatekeeper.github.io/) for OSX.


#### REV - 15% ( 150 points )

You're given a pcap file with captured traffic of unknown protocol. Also, you're given the protocol details in writings.
Your goal is to reverse engineer the protocol, collect the data and find the flag.

#### BONUS - 15% ( 150 points )

You can solve bonus task instead of any other given task and still get your 100% mark.
Or you can solve bonus task on top of your 100% score just because you feel unhappy to leave any unsolved tasks here.

( I've no idea what to put there yet )
