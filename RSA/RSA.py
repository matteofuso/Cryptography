from utils.primality import primality
from RSA.RSAKey import RSAKey

class RSA:
    def generate_key(bits):
        p = primality.random_prime(bits // 2)
        q = primality.random_prime(bits // 2)
        n = p * q
        phi = (p - 1) * (q - 1)
        e = 65537
        d = pow(e, -1, phi)
        return RSAKey(n, e, d, p, q)