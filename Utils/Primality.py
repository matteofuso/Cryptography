from Utils.FirstPrimes import first_primes
import random
import math

def miller_rabin(w: int, iterations: int) -> bool:
    """Miller-Rabin primality test."""
    # https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
    m = w - 1
    a = 0
    # Più grande esponte per cui 2^a divide w-1
    while m % 2 == 0:
        m >>= 1
        a += 1
    wlen = w.bit_length()
    for i in range(iterations):
        while True:
            b = random.randrange(1 << (wlen - 1), (1 << wlen) - 1)
            if b > 1 and b < w - 1:
                break
        g = math.gcd(b, w)
        if g > 1:
            return False
        z = pow(b, m, w)
        if z == 1 or z == w - 1:
            continue
        for j in range(a - 1):
            x = z
            z = pow(x, 2, w)
            if z == w - 1 or z == 1:
                break
        if z == w - 1:
            continue
        return False
    return True


def TestDivision(n: int):
    for p in first_primes:
        if n % p == 0:
            return False
    return True

def MR_Iterations(bit_size: int) -> int:
    miller_rabin_iterations = (
        (2048, 3),
        (1024, 4),
        (512, 10),
        (256, 30),
        (128, 50),
        (0, 100)
    )
    for i in range(len(miller_rabin_iterations)):
        if bit_size < miller_rabin_iterations[i][0]:
            return miller_rabin_iterations[i][1]

def ProbablyPrime(n: int) -> bool:
    if n in first_primes:
        return True
    elif n < first_primes[-1]:
        return False
    if TestDivision(n) == False:
        return False
    bit_size = n.bit_length()
    return miller_rabin(n, MR_Iterations(bit_size))

def GenerateProbeblyPrime(bit: int) -> int:
    while True:
        n = random.randint(2 ** (bit - 1), 2**bit - 1)
        if ProbablyPrime(n):
            return n