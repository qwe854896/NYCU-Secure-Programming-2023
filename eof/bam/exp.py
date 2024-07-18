def sub_9D2C(a1):
    if a1 > 47 and a1 <= 57:
        return a1 - 48
    if a1 > 96 and a1 <= 102:
        return a1 - 87
    if a1 <= 64 or a1 > 70:
        return 0
    return a1 - 55


# s = "8637a69R764OYIp7Og54z4cl727p06264454bnrIOl5P955$3f4ZIr334cvo25bebod7fRI1fbc5M3z52gxlbd0l409rv27f"
# s = "68637a697647544c72706264454b5955"

# s = "68637a69R764OYIp7Og54z4cl727p06264454bnrIOl5P955" + "3f4ZIr334cvo25bebod7fRI1fbc5M3z52gxlbd0l409rv27f"

s = "68637a697647544c72706264454b5955"
s = "3f4334c25bebd7f1fbc5352bd040927f"

# hczivGTLrpbdEKYU

for c in s:
    print(sub_9D2C(ord(c)), end=" ")
