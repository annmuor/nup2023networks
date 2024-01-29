#!/usr/bin/env python
import multiprocessing.pool
import multiprocessing.reduction
import socket
import time
import requests



def thread_fn(cli):
    for i in range(1,10):
        cli.send(".".encode("utf-8"))
        time.sleep(1)
    cli.send("NUP23{TCP_Pr0t0c0l_1s_f4n}\n".encode("utf-8"))
    cli.close()


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("0.0.0.0", 64333))
s.listen(5)
print("Listening on :64333")
while True:
    (cli, addr) = s.accept()
    print(f"Incoming client: {addr}")
    try:
        thread_fn(cli)
    except Exception as e:
        print("Some error: ", e)
        pass
