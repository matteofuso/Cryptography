from Crypto.PublicKey import RSA

key = RSA.generate(2048)
# print(f"n: {key.n}")
# print(f"e: {key.e}")
# print(f"d: {key.d}")
# print(f"p: {key.p}")
# print(f"q: {key.q}")
# print(f"u: {key.u}")

from PublicKey import RSA

key = RSA.PrivateKey().Generate(2048)

print(f"p= {key.primes.p},")
print(f"q= {key.primes.q},")
print(f"e= {key.public.key.e},")
print(f"d= {key.key.e}")