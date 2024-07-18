def is_prime(n):
    if n < 2:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True


primes = [n for n in range(2, 1024) if is_prime(n)]
print(primes)


for prime in primes:
    # print binary expression
    print(bin(prime)[2:])
