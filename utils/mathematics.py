class mathematics:
    def pow(b, e, m):
        if e < 0:
            # Compute modular inverse using the Extended Euclidean Algorithm
            b = mathematics.modinv(b, m)
            e = -e  # Convert to positive exponent

        c = 1
        while e > 0:
            if e % 2 == 1:
                c = (c * b) % m
            b = (b * b) % m
            e //= 2
        return c

    def modinv(a, m):
        """Computes modular inverse of a mod m using Extended Euclidean Algorithm"""
        g, x, _ = mathematics.extended_gcd(a, m)
        if g != 1:
            raise ValueError(f"No modular inverse exists for {a} mod {m}")
        return x % m  # Ensure the result is positive

    def extended_gcd(a, b):
        """Returns (gcd, x, y) such that a*x + b*y = gcd(a, b)"""
        if a == 0:
            return (b, 0, 1)
        g, x1, y1 = mathematics.extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return (g, x, y)

    def gcd(a, b):
        while b:
            a, b = b, a % b
        return a
    
    def lcm(a, b):
        return a * b // mathematics.gcd(a, b)