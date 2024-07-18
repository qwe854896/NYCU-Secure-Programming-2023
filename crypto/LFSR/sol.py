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


def get_matrix(m, n):
    return [[0 for _ in range(n)] for __ in range(m)]


def matrix_mul(A, B):
    p, q, r = len(A), len(B), len(B[0])
    C = get_matrix(p, r)

    for i in range(p):
        for j in range(r):
            for k in range(q):
                C[i][j] ^= A[i][k] & B[k][j]

    return C


def matrix_power(A, p):
    n = len(A)
    I = get_matrix(n, n)

    for i in range(n):
        I[i][i] = 1

    while p:
        if p & 1:
            I = matrix_mul(I, A)
        A = matrix_mul(A, A)
        p >>= 1

    return I


def gaussian_elimination(B):
    N = len(B)

    for i in range(N):
        jj = i
        for j in range(i, N):
            if B[j][i] == 1:
                jj = j
                break

        B[i], B[jj] = B[jj], B[i]

        for j in range(i + 1, N):
            if B[j][i]:
                for k in range(i, N + 1):
                    B[j][k] ^= B[i][k]

    for i in range(N - 1, 0, -1):
        for j in range(i):
            if B[j][i]:
                for k in range(i, N + 1):
                    B[j][k] ^= B[i][k]

    return B


def main():
    taps = [0, 2, 17, 19, 23, 37, 41, 53]
    stream = [0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0]

    N = 64
    A = get_matrix(N, N)

    for i in range(63):
        A[i][i + 1] = 1

    for tap in taps:
        A[63][tap] = 1

    A71 = matrix_power(A, 71)
    A_b = matrix_power(A, 70 + 256 * 71)

    B = get_matrix(N, N)

    for i in range(N):
        B[i] = A_b[0]
        A_b = matrix_mul(A_b, A71)

    for i in range(N):
        B[i].append(stream[256 + i])
        B[i].append(i)

    B = gaussian_elimination(B)

    key = [0] * N
    for i in range(N):
        key[i] = B[i][N]

    randomness = LFSR(taps, key)
    output = []
    for _ in range(len(stream)):
        for __ in range(70):
            randomness.getbit()
        output.append(randomness.getbit())

    flag = [0] * 256
    for i in range(len(flag)):
        flag[i] = output[i] ^ stream[i]

    print(long_to_bytes(int("".join(map(str, flag)), base=2)))


if __name__ == "__main__":
    main()
