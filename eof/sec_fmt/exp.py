#!/usr/bin/env python
from pwn import *

r = process(
    ["./share/src/ld-linux.so.2", "./share/sec_fmt"],
    env={"LD_PRELOAD": "./share/src/libc.so.6"},
)
# r = remote("10.105.0.21", 12858)

r.interactive()
