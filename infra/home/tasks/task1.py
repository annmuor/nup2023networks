#!/usr/bin/env python
import multiprocessing.pool
import multiprocessing.reduction
import socket

import requests



def thread_fn(cli):
    cli.send("NUP23{SRV_R3c0rds_ar3_1nterest1ng}\n".encode("utf-8"))
    cli.close()


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("0.0.0.0", 64321))
s.listen(5)
print("Listening on :64321")
while True:
    (cli, addr) = s.accept()
    print(f"Incoming client: {addr}")
    try:
        thread_fn(cli)
    except Exception as e:
        print("Some error: ", e)
        pass
