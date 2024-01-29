#!/usr/bin/env python
import multiprocessing.pool
import multiprocessing.reduction
import socket

import requests


def thread_fn(cli):
    cli.send("NP23{TTL_is_1_byte}\n".encode("utf-8"))
    cli.close()


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("0.0.0.0", 64322))
s.listen(5)
print("Listening on :64322")
while True:
    (cli, addr) = s.accept()
    print(f"Incoming client: {addr}")
    try:
        thread_fn(cli)
    except Exception as e:
        print("Some error: ", e)
        pass
