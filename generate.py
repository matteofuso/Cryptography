from RSA.RSA import RSA

def main():
    priv = RSA.generate_key(2048)
    pub = priv.public_key()

    print(f"Public key: {pub}")
    print()
    print(f"Private key: {priv}")

if __name__ == "__main__":
    main()