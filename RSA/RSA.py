from utils.primality import primality
from utils.mathematics import mathematics
from RSA.RSAKey import RSAPrivKey
import random

class RSA:
    def generate_key(bits, rand_e=False):
        p = primality.random_prime(bits // 2)
        q = p
        while q == p:
            q = primality.random_prime(bits // 2)
        n = p * q
        
        lambda_n = mathematics.lcm(p - 1, q - 1)

        if rand_e:
            while True:
                e = random.randint(2, lambda_n - 1)
                if mathematics.gcd(e, lambda_n) == 1:
                    break
        else:
            e = 65537
        d = mathematics.pow(e, -1, lambda_n)
        return RSAPrivKey(n, d, e=e, p=p, q=q)