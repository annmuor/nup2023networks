#!/usr/bin/env python
import multiprocessing.pool
import multiprocessing.reduction
import socket

import requests



def thread_fn(cli):
    cli.send("NUP23{IPv6_c0nn3cts_p30pl3}\n".encode("utf-8"))
    cli.close()


s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.bind(("::", 65321))
s.listen(5)
print("Listening on :65321")
while True:
    (cli, addr) = s.accept()
    print(f"Incoming client: {addr}")
    try:
        thread_fn(cli)
    except Exception as e:
        print("Some error: ", e)
        pass
