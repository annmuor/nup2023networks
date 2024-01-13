- You're given a binary
  for [Linux](task02.linux)/[OSX M1/M2](task02.armmac)/[OSX Intel](task02.x64mac)/[Windows](task02.exe) that works as a
  DNS server.
- It listens UDP and TCP port 6053 on 127.0.0.1 and answers to some type of queries, like A, CNAME and so on.
- Try to get all the data from the server to find the flag.

You may also need to use HEX2ASCII decoder, like

```python
bytes.fromhex("557365206469672C204C756B6521")
```

**P.S. Do chmod 755 for Linux/OSX and [disable Gatekeeper](https://disable-gatekeeper.github.io/) for OSX.**