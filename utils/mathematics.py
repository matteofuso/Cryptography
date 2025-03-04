class mathematics:
    def pow(b, e, m):
        if e < 0:
            b = mathematics.modinv(b, m)
            e = -e

        c = 1
        while e > 0:
            if e % 2 == 1:
                c = (c * b) % m
            b = (b * b) % m
            e //= 2
        return c

    def modinv(a, m):
        g, x, _ = mathematics.extended_gcd(a, m)
        if g != 1:
            raise ValueError(f"No modular inverse exists for {a} mod {m}")
        return x % m

    def extended_gcd(a, b):
        # Initialize variables
        old_r, r = a, b
        old_s, s = 1, 0
        old_t, t = 0, 1
        
        # Iterate until r becomes 0
        while r != 0:
            quotient = old_r // r
            old_r, r = r, old_r - quotient * r
            old_s, s = s, old_s - quotient * s
            old_t, t = t, old_t - quotient * t

        return old_r, old_s, old_t

    def gcd(a, b):
        while b:
            a, b = b, a % b
        return a
    
    def lcm(a, b):
        return a * b // mathematics.gcd(a, b)