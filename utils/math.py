
class math:
    def pow(b, e, m):
        c = 1 
        while e > 0:
            if e % 2 == 1:
                c = (c * b) % m
            b = (b * b) % m
            e //= 2
        return c
