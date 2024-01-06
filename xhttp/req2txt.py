#!/usr/bin/env python3
import sys
for b in sys.stdin.buffer.read():
    br = bytearray()
    if b >= 88:
        b -= 88
    br.append(b)
    sys.stdout.buffer.write(br)

sys.stdout.buffer.flush()
