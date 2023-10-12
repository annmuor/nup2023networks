#!/usr/bin/env python3
import select
import sys
from socket import socket, SOCK_DGRAM, IPPROTO_UDP, AF_INET, SOL_SOCKET, SO_BROADCAST, SO_REUSEPORT

address = ("255.255.255.255", 24555)
if __name__ == '__main__':
    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
    sock.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
    sock.setsockopt(SOL_SOCKET, SO_REUSEPORT, 1)
    sock.bind(("0.0.0.0", 24555))
    stdin = sys.stdin.buffer
    streams = [sock, stdin]

    while True:
        try:
            readable, _, exeptable = select.select(streams, [], streams)
            for stream in readable:
                if sock is stream:
                    message, addr = sock.recvfrom(65535)
                    try:
                        message = message.decode("utf-8").strip()
                        print(f"[{addr}]>> {message}")
                    except:
                        sys.stdout.write(message)
                if stdin is stream:
                    try:
                        message = stdin.readline().strip()
                        sock.sendto(message, address)
                    except:
                        sys.stderr.write("[!!] Error sending data to the chat")
            for stream in exeptable:
                exit(0)
        except KeyboardInterrupt:
            exit(0)
