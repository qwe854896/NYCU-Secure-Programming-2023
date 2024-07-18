from secret import flag
from Crypto.Util.number import bytes_to_long, getPrime

def xorrrrr(nums):
    n = len(nums)
    result = [0] * n
    for i in range(1, n):
        result = [ result[j] ^ nums[(j+i) % n] for j in range(n)]
    return result

secret = bytes_to_long(flag)
mods = [ getPrime(32) for i in range(20)]
muls = [ getPrime(20) for i in range(20)]

hint = [secret * muls[i] % mods[i] for i in range(20)]

print(f"hint = {xorrrrr(hint)}")
print(f"muls = {xorrrrr(muls)}")
print(f"mods = {xorrrrr(mods)}")
