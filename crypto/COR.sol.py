import random
from secret import FLAG
from Crypto.Util.number import long_to_bytes


class LFSR:
    def __init__(self, tap, state):
        self._tap = tap
        self._state = state

    def getbit(self):
        f = sum([self._state[i] for i in self._tap]) & 1
        x = self._state[0]
        self._state = self._state[1:] + [f]
        return x


class triLFSR:
    def __init__(self, lfsr1, lfsr2, lfsr3):
        self.lfsr1 = lfsr1
        self.lfsr2 = lfsr2
        self.lfsr3 = lfsr3

    def getbit(self):
        x1 = self.lfsr1.getbit()
        x2 = self.lfsr2.getbit()
        x3 = self.lfsr3.getbit()
        return x2 if x1 else x3


lfsr1 = LFSR([0, 1, 2, 5], [random.randrange(2) for _ in range(19)])
lfsr2 = LFSR([0, 1, 2, 5], [random.randrange(2) for _ in range(23)])
lfsr3 = LFSR([0, 1, 2, 5], [random.randrange(2) for _ in range(27)])
cipher = triLFSR(lfsr1, lfsr2, lfsr3)
flag = map(int, "".join(["{:08b}".format(c) for c in FLAG]))

output = []
for _ in range(200):
    output.append(cipher.getbit())

for b in flag:
    output.append(cipher.getbit() ^ b)

print(output)

out =  [0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0]

out_flag = out[200:]
out = out[:200]

import itertools
from tqdm import tqdm


def correlation_attack(stream, key_len):
    for b in tqdm(range(key_len)):
        for C in itertools.combinations(range(key_len), b):
            key_candidate = [
                1 - stream[i] if i in C else stream[i] for i in range(key_len)
            ]
            lfsr = LFSR([0, 1, 2, 5], key_candidate)
            S = [lfsr.getbit() for _ in range(200)]
            matches = sum(a == b for a, b in zip(stream, S))
            if matches >= 140:
                print(key_candidate)
                return key_candidate


# cor_2 = correlation_attack(out, 23)
# cor_3 = correlation_attack(out, 27)

cor_2 = [1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1]
cor_3 = [0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1]

lfsr2 = LFSR([0, 1, 2, 5], cor_2)
lfsr3 = LFSR([0, 1, 2, 5], cor_3)

out = out + out_flag
lfsr2_s = [lfsr2.getbit() for _ in out]
lfsr3_s = [lfsr3.getbit() for _ in out]

flag = []
for i in tqdm(range(1 << 19)):
    force_key = [(i >> j) & 1 for j in range(19)]
    lfsr1 = LFSR([0, 1, 2, 5], force_key)

    suc = True
    for i in range(200):
        if (lfsr2_s[i] if lfsr1.getbit() else lfsr3_s[i]) != out[i]:
            suc = False
            break

    if suc:
        print(force_key)
        lfsr = LFSR([0, 1, 2, 5], force_key)
        for j, s in enumerate(out):
            flag.append(s ^ (lfsr2_s[j] if lfsr.getbit() else lfsr3_s[j]))

print(long_to_bytes(int("".join(map(str, flag[200:])), 2)))
