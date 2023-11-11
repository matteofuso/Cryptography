from PublicKey import RSAUtils
from Crypto.Math.Numbers import Integer
import math

class RSA:
    def PrimitiveEncrypt(self, message: str) -> bytes:
        m = RSAUtils.BytesToInt(message.encode())
        e = RSAUtils.PrimitiveEncrypt(self.key, m)
        return RSAUtils.IntToBytes(e)

    def PrimitiveDecrypt(self, ciphertext: bytes) -> str:
        m = RSAUtils.BytesToInt(ciphertext)
        c = RSAUtils.PrimitiveDecrypt(self.key, m)
        return RSAUtils.IntToBytes(c).decode()

    def Encrypt(self, message: str, L=b"") -> bytes:
        return RSAUtils.Encrypt(message.encode(), self.key, L=L)

    def Decrypt(self, ciphertext: bytes, L=b"") -> str:
        return RSAUtils.Decrypt(ciphertext, self.key, L=L).decode()


class PublicKey(RSA):
    def __init__(self, n, e) -> None:
        self.key = RSAUtils.Key(n, e)


class PrivateKey(RSA):
    def __init__(self, **args) -> None:
        if "p" in args and "q" in args:
            self.primes = RSAUtils.Primes(args["p"], args["q"])
            n = args["p"] * args["q"]
            if "d" in args and "e" in args:
                if "d" in args:
                    self.key = RSAUtils.Key(n, args["d"])
                if "e" in args:
                    self.public = PublicKey(n, args["e"])
        else:
            if "n" in args and "d" in args:
                self.key = RSAUtils.Key(args["n"], args["d"])
            if "n" in args and "e" in args:
                self.public = PublicKey(args["n"], args["e"])

    def Generate(self, bit: int, e: int = 65537) -> None:
        #p = 146065727846072970675673617211914657919789631444432171130837563827813529841909412592089872362021089162398719907236675343033662167438594710385797318337604999857930902193700833430847126837265126967654061308218859681580476070937034820637804714470788586771041507985043662401167925806857993918692883347942675979739
        #q = 174510642330412499167556036577522251193387388488614257817252340221718298353115007722319993911898411528561684449014710063598093670231250289925192087452280136591942461013268618656450710576981423847735866492565706481939425365276843989383470432369494984492119669102039535894210026833793980281381409232915961955411
        #self.primes = RSAUtils.Primes(p, q)
        self.primes = RSAUtils.GeneratePrimes(bit)
        n = self.primes.p * self.primes.q
        self.public = PublicKey(n, e)
        #totiente = (self.primes.p - 1) * (self.primes.q - 1)
        lcm = math.lcm(self.primes.p - 1, self.primes.q - 1)
        d = pow(e, -1, lcm)
        self.key = RSAUtils.Key(n, d)
        return self