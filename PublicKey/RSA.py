from PublicKey import RFC3447 as RFC

class RSA:
    def PrimitiveEncrypt(self, message: str) -> bytes:
        m = RFC.BytesToInt(message.encode())
        e = RFC.PrimitiveEncrypt(self.key, m)
        return RFC.IntToBytes(e)

    def PrimitiveDecrypt(self, ciphertext: bytes) -> str:
        m = RFC.BytesToInt(ciphertext)
        c = RFC.PrimitiveDecrypt(self.key, m)
        return RFC.IntToBytes(c).decode()

    def Encrypt(self, message: str, L = b"") -> bytes:
        return RFC.Encrypt(message.encode(), self.key, L=L)
    
    def Decrypt(self, ciphertext: bytes, L = b"") -> str:
        return RFC.Decrypt(ciphertext, self.key, L=L).decode()


class PublicKey(RSA):
    def __init__(self, n: int, e: int):
        self.key = RFC.Key(n, e)


class PrivateKey(RSA):
    def __init__(self, p: int, q: int, e: int, d: int) -> None:
        n = p * q
        self.key = RFC.Key(n, d)
        self.public = PublicKey(n, e)
        self.primes = Primes(p, q)


class Primes:
    def __init__(self, p: int, q: int):
        self.p = p
        self.q = q
