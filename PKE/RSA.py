from PKE import RSAFunctions
from Utils import BytesOperations
import math


class RSA:
    def PrimitiveEncrypt(self, message: str) -> bytes:
        """RSA encryption primitive (RSAEP)"""
        m = BytesOperations.BytesToInt(message.encode())
        e = RSAFunctions.PrimitiveEncrypt(self.key, m)
        return BytesOperations.IntToBytes(e)

    def PrimitiveDecrypt(self, ciphertext: bytes) -> str:
        """RSA decryption primitive (RSADP)"""
        m = BytesOperations.BytesToInt(ciphertext)
        c = RSAFunctions.PrimitiveDecrypt(self.key, m)
        return BytesOperations.IntToBytes(c).decode()

    def Encrypt(self, message: str, L=b"") -> bytes:
        """RSA encryption (RSAES-OAEP-ENCRYPT)"""
        return RSAFunctions.Encrypt(message.encode(), self.key, L=L)

    def Decrypt(self, ciphertext: bytes, L=b"") -> str:
        """RSA decryption (RSAES-OAEP-DECRYPT)"""
        return RSAFunctions.Decrypt(ciphertext, self.key, L=L).decode()


class PublicKey(RSA):
    def __init__(self, n, e) -> None:
        self.key = RSAFunctions.Key(n, e)

    def __str__(self) -> str:
        return f"n: {self.key.m}, e: {self.key.e}"

    def Export(self) -> str:
        return RSAFunctions.PublicKeyExport(self.key.m, self.key.e)


class PrivateKey(RSA):
    def __init__(self, **args) -> None:
        if "p" in args and "q" in args:
            self.primes = RSAFunctions.Primes(args["p"], args["q"])
            n = args["p"] * args["q"]
            if "d" in args and "e" in args:
                self.key = RSAFunctions.Key(n, args["d"])
                self.public = PublicKey(n, args["e"])
            else:
                self = GenerateKeys(self.primes)
        else:
            if "n" in args and "d" in args:
                self.key = RSAFunctions.Key(args["n"], args["d"])
            if "n" in args and "e" in args:
                self.public = PublicKey(args["n"], args["e"])

    def __str__(self) -> str:
        return f"n: {self.key.m}, d: {self.key.e}"

    def Export(self) -> str:
        return RSAFunctions.PrivateKeyExport(self.key.m, self.public.key.e, self.key.e, self.primes.p, self.primes.q)


def Generate(bit: int = 2048, e: int = 65537, **args) -> PrivateKey:
    """Generate a private key with bit length bit and e as public exponent."""
    if "p" in args and "q" in args:
        primes = RSAFunctions.Primes(args["p"], args["q"])
    primes = RSAFunctions.GeneratePrimes(bit, e)
    return GenerateKeys(primes, e)


def GenerateKeys(primes, e: int = 65537):
    """Generate public and private key."""
    n = primes.p * primes.q
    d = pow(e, -1, math.lcm(primes.p - 1, primes.q - 1))
    return PrivateKey(n=n, d=d, e=e, p=primes.p, q=primes.q)
