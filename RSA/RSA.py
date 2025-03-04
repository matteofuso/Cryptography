from utils.primality import primality
from utils.mathematics import mathematics
from RSA.RSAKey import RSAPrivKey
import random

class RSA:
    def calculate_e(phi, rand = False):
        if rand:
            while True:
                e = random.randint(2, phi - 1)
                if mathematics.gcd(e, phi) == 1:
                    return e
        if mathematics.gcd(65537, phi) != 1 or phi < 65537:
            return RSA.calculate_e(phi, True)
        return 65537

    def generate_key(bits, rand_e=False):
        p = primality.random_prime(bits // 2)
        q = p
        while q == p:
            q = primality.random_prime(bits // 2)
        n = p * q
        phi = (p - 1) * (q - 1)
        e = RSA.calculate_e(phi, rand_e)
        d = mathematics.modinv(e,phi)
        return RSAPrivKey(n, d, e=e, p=p, q=q)