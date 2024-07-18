#!/usr/bin/env python3

import subprocess
from sage.all import *


for i in range(43):
    s = ["0"] * 43
    s[i] = "1"
    s = "".join(s)
    command = f"gdb -ex 'starti {s}' -ex 'b *0x00005555555569d7' -ex 'c' -ex 'dump memory bin/{i} 0x000055555555a2a0 0x000055555555a2a0+43' -ex 'quit' ./stateful.exe"
    subprocess.run(command, shell=True)

X = []

for i in range(43):
    s = [ord("0")] * 43
    s[i] = ord("1")
    X.append(s)

X = Matrix(Zmod(256), X)

B = []

for i in range(43):
    with open(f"bin/{i}", "rb") as f:
        B.append(f.read())


B = Matrix(Zmod(256), B).transpose()
B_inv = B.inverse()

b = "241AAC33B8A3140CED4265555FC493A1FB9B9870DB546CAEF9525F0D744049968C655335C3DA748033EC7D"
b = [int(b[i : i + 2], 16) for i in range(0, len(b), 2)]
b = vector(Zmod(256), b)

flag = X * B_inv * b

flag = "".join([chr(int(x)) for x in flag])
print(flag)

# AIS3{@r3_y0U_@_sTATEful_0R_St@T3LeS5_CtF3r}
