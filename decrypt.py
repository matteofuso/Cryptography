from RSA.RSAKey import RSAPrivKey

def main():
    d = input("Insert d: ")
    n = input("Insert n: ")
    key = RSAPrivKey(int(n), d=int(d))
    c = int(input("Insert ciphertext: "))
    m = key.decrypt(c)
    print()
    print(f"Decrypted message: {m}")

if __name__ == "__main__":
    main()