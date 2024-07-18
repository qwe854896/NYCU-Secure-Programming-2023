def custom_hash(a1):
    v2 = 0xCBF29CE484222325
    for char in a1:
        v3 = ord(char) ^ v2
        v2 = 0x100000001B3 * v3
        v2 = v2 & 0xFFFFFFFFFFFFFFFF
    return v2


def find_function_name(filename, target_hash):
    with open(filename, "r") as file:
        function_names = file.read().splitlines()

    for function_name in function_names:
        hash_value = custom_hash(function_name)
        if hash_value == target_hash:
            return function_name

    return None


filename = "kernel32.dll.txt"
# target_hash = 0x2DF8494D5C13046
target_hashes = [
    0x69D265FE6B1C110F,
    0x578960F1FC7FFF25,
    0xFA55E32C9D72A921,
    0xE0746E00B47C0477,
    0xE7BDCAD1F3AE0E13,
    0x1C71D0537E2246F5,
    0x121E523CBB49F938,
    0x1C8EF920B632E586,
    0x28D0403A889E4F69,
    0x556A045B10DE85,
    0x2E97865AB85128C3,
    0x2FA16C1D95E4306A,
    0x5D35AEBEDFD88117,
    0xFC59546FD0D3D778,
    0xEBC4E8E9B1542DEE,
]
for target_hash in target_hashes:
    function_name = find_function_name(filename, target_hash)
    print(function_name)
