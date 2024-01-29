#!/usr/bin/env python
import multiprocessing.pool
import multiprocessing.reduction
import socket

import requests



def thread_fn(cli):
    cli.send("NUP23{P4rt_kn41ng}".encode("utf-8"))
    cli.send("\r\n".encode("utf-8"))
    cli.close()


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("0.0.0.0", 64323))
s.listen(5)
print("Listening on :64323")
while True:
    (cli, addr) = s.accept()
    print(f"Incoming client: {addr}")
    try:
        thread_fn(cli)
    except Exception as e:
        print("Some error: ", e)
        pass
