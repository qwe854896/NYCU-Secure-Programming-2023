def custom_hash(string):
    hash_value = 0
    for char in string:
        hash_value += ((hash_value << 11) | (hash_value >> 21)) + ord(char) + 1187
        hash_value = hash_value & 0xFFFFFFFF  # Ensure hash_value is within the range of int32
    return hash_value


def find_function_name(target_hash):
    with open("user32.dll.txt", "r") as file:
        function_names = file.read().splitlines()

    for function_name in function_names:
        hash_value = custom_hash(function_name)
        if hash_value == target_hash:
            return function_name

    return None


target_hash = 0x416F607
function_name = find_function_name(target_hash)
print(function_name)
