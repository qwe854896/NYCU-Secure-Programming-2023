from z3 import *
from string import printable


# Reuse the code from scramble.py
def apply_scramble_pattern(input_bytes, patterns, result, solver):
    for i, operations in enumerate(patterns):
        src = input_bytes[i]
        for operation in operations:
            if operation is None:
                continue
            elif operation[0] == "add":
                src += operation[1]
            elif operation[0] == "sub":
                src -= operation[1]
            elif operation[0] == "lsh":
                src <<= operation[1]
            src &= 0xFFFFFFFF

        solver.add(src == result[i])


def main():
    # Constants
    patterns = [[('sub', 20935)], [('sub', 31575), ('lsh', 9), ('add', 45363), ('add', 35372), ('sub', 15465)], [('add', 19123), ('add', 35260), ('sub', 49421), ('lsh', 8)], [('lsh', 1), ('sub', 4977), ('sub', 55837)], [('add', 16937)], [('sub', 56984), ('lsh', 2), ('sub', 32363), ('sub', 46293)], [('sub', 94), ('sub', 48860), ('sub', 18342), ('lsh', 3)], [('add', 37549), ('sub', 36283), ('lsh', 6), ('add', 6253)], [('add', 34661), ('sub', 13281), ('sub', 64107)], [('sub', 8525), ('sub', 30349), ('sub', 26744)], [('lsh', 2), ('sub', 18120), ('sub', 63091), ('add', 17287), ('sub', 37618), ('add', 2237)], [('sub', 48573), ('sub', 4449), ('add', 36013), ('sub', 64051)], [('add', 10415), ('lsh', 3), ('lsh', 10)], [('add', 5676), ('lsh', 3), ('lsh', 10), ('add', 32002), ('sub', 60775)], [('add', 35939), ('sub', 32666), ('sub', 45639), ('add', 2077), ('sub', 16253)], [('sub', 30392), ('sub', 26913), ('sub', 14009), ('sub', 62416)], [('sub', 15056), ('sub', 40527)], [('lsh', 5)], [('lsh', 1), ('sub', 16070)], [('add', 2045)], [('lsh', 8), ('add', 37087), ('sub', 22013), ('lsh', 10), ('lsh', 2)], [('add', 31880), ('sub', 56557), ('lsh', 6), ('lsh', 5), ('lsh', 8), ('add', 15535)], [('add', 22937), ('add', 4060)], [('add', 8462), ('sub', 4463), ('sub', 45810), ('lsh', 1)], [('sub', 10144), ('lsh', 8), ('lsh', 5), ('lsh', 1), ('lsh', 8)], [('add', 49937), ('lsh', 2), ('add', 60982), ('sub', 24799)], [('lsh', 4), ('add', 53340), ('add', 50619), ('sub', 56111), ('add', 6134), ('lsh', 1)], [('sub', 22577), ('sub', 50645)], [('add', 21265), ('sub', 41440)], [('add', 63314), ('sub', 45755), ('add', 62216)], [('sub', 52616)], [('add', 21192)], [('add', 62573), ('sub',18811)], [('add', 35452), ('sub', 11573), ('sub', 49079), ('sub', 36361), ('sub', 26862), ('lsh', 9)], [('add', 13610), ('lsh', 7), ('lsh', 3), ('sub', 28490), ('lsh', 10), ('add', 44742)], [('lsh', 10), ('sub', 1797), ('sub', 10564), ('add', 12394)], [('add', 45165), ('lsh', 10), ('sub', 60610), ('sub', 63002), ('sub', 14851), ('lsh', 1)], [('add', 34840), ('lsh', 3), ('sub', 16907)], [('add', 4404), ('lsh', 3), ('lsh', 7), ('lsh', 6)], [('lsh', 6), ('add', 51738), ('sub', 24621), ('add', 58646)], [('lsh', 1)], [('add', 29375), ('sub', 419), ('add', 2854), ('sub', 11878), ('lsh', 10), ('add', 40151)], [('add', 22953)]]
    scrambled_results = [4294946431, 4278905078, 1286912, 4294906624, 17060, 4294661164, 4294429720, 94573, 4294924666, 4294901787, 4294868383, 4294886344, 86147072, 47247259, 4294910851, 4294833676, 4294911813, 3040, 4294951460, 2160, 171843584, 4734127, 27100, 4294883864, 884998144, 236375, 111420, 4294894192, 4294947222, 79889, 4294914775, 21308, 43873, 4249743360, 1477674694, 113697, 92442178, 262757, 295239680, 91843, 210, 20569303, 23078]

    bit_length = 32  # 32-bit integer
    flag_length = len(patterns)

    # Initialize Z3 solver
    solver = Solver()

    # Initialize flag variables
    flag = [BitVec(f"flag_{i}", bit_length) for i in range(flag_length)]

    # flag_i is printable
    printable_min = min([ord(c) for c in printable])
    printable_max = max([ord(c) for c in printable])
    for i in range(flag_length):
        solver.add(And(flag[i] >= printable_min, flag[i] <= printable_max))

    # Enumerate all patterns
    apply_scramble_pattern(flag, patterns, scrambled_results, solver)

    # Check if the formula is satisfiable
    if solver.check() == sat:
        print(
            "".join(
                [chr(solver.model()[flag[i]].as_long()) for i in range(flag_length)]
            )
        )


if __name__ == "__main__":
    main()
