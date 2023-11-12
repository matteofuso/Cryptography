from PKE import RSA
from base64 import b64encode

key = RSA.PrivateKey().Generate(1024)
message = "Encrypt me! Would you kindly?"


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
