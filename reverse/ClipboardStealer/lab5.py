def rc4_decrypt(key, cipher):
    # Initialization
    S = list(range(256))
    j = 0
    plaintext = []

    # Key-scheduling algorithm
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    # Pseudo-random generation algorithm
    i = j = 0
    for byte in cipher:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) % 256]
        plaintext.append(byte ^ k)

    return bytes(plaintext)

# RC4 key and cipher text
key = b"\xf0\xc7\xd3\x0e\x7f,\x15\xba"
cipher = b"C`[_N\xba\x9f\x9e\xe3xoU\xcb\x81$\xfa\xe7\xbf\x0d\x1b<$\xb7N\x95\xf3\xa4\xbd\xd0\xe6CP\xce\x02\xf0\xb1\xcdV\xb0\xe8\x16I\x09\"v\xfb\x9d:^\x08VV6\x08\xac\xa6q\x01\x00\x00\x00\x00\x00\x00"

# Decrypt the cipher text
plaintext = rc4_decrypt(key, cipher)
print("Decrypted plaintext:", plaintext)

# FLAG{C2_cU540m_Pr0t0C01}