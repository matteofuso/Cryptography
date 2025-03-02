from RSA.RSAKey import RSAPubKey
import base64

def main():
    n = input("Insert n: ")
    e = input("Insert e: ")
    m = input("Insert message: ")
    rsa = RSAPubKey(int(n), int(e))
    c = rsa.encrypt(m)
    print()
    print(f"Encrypted message: {c}")
    c = base64.b64encode(c.to_bytes((c.bit_length() + 7) // 8, "big")).decode()
    print(f"Base64 encoded: {c}")

if __name__ == "__main__":
    main()