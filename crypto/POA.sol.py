from pwn import *
from Crypto.Util.number import bytes_to_long
from tqdm import tqdm

BLOCK_SIZE = 16
X80 = bytes_to_long(b"\x80")


def byte_arr_to_long_arr(arr):
    rst = []
    for i in range(len(arr)):
        rst.append(int(arr[i]))
    return rst


def long_arr_to_hex_arr(arr):
    return bytes(arr).hex()


def oracle(r, iv, ct):
    block = [0] * BLOCK_SIZE

    for j in tqdm(range(BLOCK_SIZE - 1, -1, -1)):
        for k in range(256):
            p = iv.copy()

            p[j] = p[j] ^ k ^ X80
            payload = long_arr_to_hex_arr(p + ct)

            r.sendline(payload)
            s = r.recvline().decode()
            if s == "Well received :)\n":
                block[j] = k
                iv[j] = iv[j] ^ k
                break

    return block


def main():
    # r = process("./POA_4af88990ab364609.py")
    r = remote('edu-ctf.zoolab.org', 10004)

    inp = bytes.fromhex(r.recvline().decode().strip())  # hex style input
    blocks_num = len(inp) // BLOCK_SIZE
    inp = byte_arr_to_long_arr(inp)

    pt = []
    for i in tqdm(range(1, blocks_num)):
        offset = i * BLOCK_SIZE
        prv = inp[offset - BLOCK_SIZE : offset]
        nxt = inp[offset : offset + BLOCK_SIZE]
        block = oracle(r, prv, nxt)
        pt += block

    print("".join(list(map(chr, pt))).strip("\x00"))


if __name__ == "__main__":
    main()
