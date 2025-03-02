from RSA.RSA import RSA

def main():
    key_size = input("Insert the key size: ")
    random_e = input("Randomize e? (y/n): ").lower() == "y"
    priv = RSA.generate_key(int(key_size), random_e)
    pub = priv.public_key()

    print()
    print(f"Public key:")
    print(pub)
    print()
    print(f"Private key:")
    print(priv)

if __name__ == "__main__":
    main()