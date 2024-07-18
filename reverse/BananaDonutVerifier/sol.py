import numpy as np

def load_bytes(byte_string):
    byte_list = [byte_string[i : i + 2] for i in range(0, len(byte_string), 3)]
    int_list = [int(byte, 16) for byte in byte_list]
    return int_list


with open('data.txt', 'r') as f:
    data = f.read()
    l = load_bytes(data)

with open('output.txt', 'r') as f:
    data = f.read()
    l2 = data.split('\n')
    l2 = [int(i) for i in l2 if i != '']

# XOR l and l2
l3 = [l[i] ^ l2[i] for i in range(len(l2))]

# l3 is an integer list
# convert l3 to byte string
X_bytes = [bytes([x]) for x in l3]
X_bytes_string = b''.join(X_bytes)
print(X_bytes_string)