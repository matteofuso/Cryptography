from Crypto.PublicKey import RSA

key = RSA.generate(2048)
print(f"n: {key.n}")
print(f"e: {key.e}")
print(f"d: {key.d}")
print(f"p: {key.p}")
print(f"q: {key.q}")
print(f"u: {key.u}")