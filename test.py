from PKE import RSA
from base64 import b64encode

key = RSA.Generate(1024)
message = "Encrypt me! Would you kindly?"

print(key)
print(key.public)
print(f"p: {key.primes.p}, q: {key.primes.q}")

print("Encrypt with EME-OAEP:")
encrypted = key.Encrypt(message)
print("Crypted text: " + b64encode(encrypted).decode("utf-8"))
decryped = key.public.Decrypt(encrypted)
print("Decrypted text: " + decryped)

print()
print("Encrypt with primitive:")
encrypted = key.PrimitiveEncrypt(message)
print("Crypted text: " + b64encode(encrypted).decode("utf-8"))
decryped = key.public.PrimitiveDecrypt(encrypted)
print("Decrypted text: " + decryped)
print()

with open("private.pem", "w") as f:
    f.write(key.Export())
    f.close()
    
with open("public.pem", "w") as f:
    f.write(key.public.Export())
    f.close()