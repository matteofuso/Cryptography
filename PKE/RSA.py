from PKE import RSAUtils
import math


class RSA:
    def PrimitiveEncrypt(self, message: str) -> bytes:
        """RSA encryption primitive (RSAEP)"""
        m = RSAUtils.BytesToInt(message.encode())
        e = RSAUtils.PrimitiveEncrypt(self.key, m)
        return RSAUtils.IntToBytes(e)

    def PrimitiveDecrypt(self, ciphertext: bytes) -> str:
        """RSA decryption primitive (RSADP)"""
        m = RSAUtils.BytesToInt(ciphertext)
        c = RSAUtils.PrimitiveDecrypt(self.key, m)
        return RSAUtils.IntToBytes(c).decode()

    def Encrypt(self, message: str, L=b"") -> bytes:
        """RSA encryption (RSAES-OAEP-ENCRYPT)"""
        return RSAUtils.Encrypt(message.encode(), self.key, L=L)

    def Decrypt(self, ciphertext: bytes, L=b"") -> str:
        """RSA decryption (RSAES-OAEP-DECRYPT)"""
        return RSAUtils.Decrypt(ciphertext, self.key, L=L).decode()


class PublicKey(RSA):
    def __init__(self, n, e) -> None:
        self.key = RSAUtils.Key(n, e)

    def __str__(self) -> str:
        return f"n: {self.key.m}, e: {self.key.e}"


class PrivateKey(RSA):
    def __init__(self, **args) -> None:
        if "p" in args and "q" in args:
            self.primes = RSAUtils.Primes(args["p"], args["q"])
            n = args["p"] * args["q"]
            if "d" in args and "e" in args:
                self.key = RSAUtils.Key(n, args["d"])
                self.public = PublicKey(n, args["e"])
            else:
                self.GenerateKeys()
        else:
            if "n" in args and "d" in args:
                self.key = RSAUtils.Key(args["n"], args["d"])
            if "n" in args and "e" in args:
                self.public = PublicKey(args["n"], args["e"])

    def __str__(self) -> str:
        return f"n: {self.key.m}, d: {self.key.e}"

    def Generate(self, bit: int = 2048, e: int = 65537, **args) -> None:
        """Generate a private key with bit length bit and e as public exponent."""
        if "p" in args and "q" in args:
            self.primes = RSAUtils.Primes(args["p"], args["q"])
        self.primes = RSAUtils.GeneratePrimes(bit, e)
        self.GenerateKeys(e)
        return self

    def GenerateKeys(self, e: int = 65537):
        """Generate public and private key."""
        n = self.primes.p * self.primes.q
        self.public = PublicKey(n, e)
        d = pow(e, -1, math.lcm(self.primes.p - 1, self.primes.q - 1))
        self.key = RSAUtils.Key(n, d)
