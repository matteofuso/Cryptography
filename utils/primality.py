import random
from utils.mathematics import mathematics

class primality:
    __iterations = [
        (2048, 3),
        (1024, 4),
        (512, 10),
        (256, 30),
        (128, 50),
        (0, 100)
    ]

    def __get_iterations(n):
        for limit, iterations in primality.__iterations:
            if n >= limit:
                return iterations

    def miller_rabin(n):
        k = primality.__get_iterations(n.bit_length())

        if n == 2 or n == 3:
            return True
        if n <= 1 or n % 2 == 0:
            return False

        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2

        for _ in range(k):
            a = random.randint(2, n - 2)
            x = mathematics.pow(a, d, n)

            if x == 1 or x == n - 1:
                continue

            for _ in range(r - 1):
                x = mathematics.pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False

        return True
    
    def random_prime(bits):
        while True:
            p = random.getrandbits(bits) | 1
            if primality.miller_rabin(p):
                return p