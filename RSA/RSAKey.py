
class RSAKey:
    def __init__(self, n, e, d = None, p = None, q = None):
        self.n = n
        self.e = e
        if d:
            self.d = d
        if p:
            self.p = p
            self.q = q
    
    def public_key(self):
        return RSAKey(self.n, self.e)
    
    def private_key(self):
        return self if self.is_private() else None

    def is_private(self):
        return hasattr(self, "d")
    
    def __str__(self):
        if self.is_private():
            return f"n = {self.n}\ne = {self.e}\nd = {self.d}\np = {self.p}\nq = {self.q}"
        return f"n = {self.n}\ne = {self.e}"