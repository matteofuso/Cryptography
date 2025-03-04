from utils.mathematics import mathematics

class RSAPubKey():
    def __init__(self, n, e):
        self.n = n
        self.e = e
    
    def encrypt(self, message: str|int) -> int:
        if type(message) == str:
            message = int.from_bytes(message.encode(), "big")
        if message >= self.n:
            raise ValueError("Message is too large")
        return mathematics.pow(message, self.e, self.n)
    
    def __str__(self):
        return f"(n) = {self.n}\n(e) = {self.e}"
    
    def __repr__(self):
        return self.__str__()

class RSAPrivKey():
    def __init__(self, n: str, d: str, e: str = None, p: str = None, q: str = None):
        self.n = n
        self.d = d
        if e:
            self.e = e
            self.p = p
            self.q = q
    
    def public_key(self) -> RSAPubKey:
        if hasattr(self, "e"):
            return RSAPubKey(self.n, self.e)
        return None

    def decrypt(self, ciphertext: int) -> str:
        message = mathematics.pow(ciphertext, self.d, self.n)
        return message.to_bytes((message.bit_length() + 7) // 8, "big").decode()
    
    def __str__(self):
        if hasattr(self, "e"):
            return f"(n) = {self.n}\n(e) = {self.e}\n(d) = {self.d}\n(p) = {self.p}\n(q) = {self.q}"
        return f"(n) = {self.n}\n(d) = {self.d}"
    
    def __repr__(self):
        return self.__str__()