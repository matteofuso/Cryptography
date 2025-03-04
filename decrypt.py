from RSA.RSAKey import RSAPrivKey
import base64

def main():
    d = input("Insert d: ")
    n = input("Insert n: ")
    key = RSAPrivKey(int(n), d=int(d))
    c = input("Insert base64 message: ")
    c = int.from_bytes(base64.b64decode(c), "big")
    try:
        m = key.decrypt(c)
    except ValueError as e:
        print(e)
        return
    print()
    print(f"Decrypted message: {m}")

if __name__ == "__main__":
    main()