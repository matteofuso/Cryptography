def BytesToInt(X: bytes) -> int:
    """Convert octet string to nonnegative integer (OS2IP)"""
    # RFC3447 4.2 OS2IP
    # https://datatracker.ietf.org/doc/html/rfc3447#section-4.1
    x = 0
    for i in range(len(X)):
        x += X[i] * 256 ** (len(X) - i - 1)
    return x


def IntToBytes(x: int, xLen: int = -1) -> bytes:
    """Convert nonnegative integer to octet string (I2OSP)"""
    # RFC3447 4.1 I2OSP
    # https://datatracker.ietf.org/doc/html/rfc3447#section-4.1
    if xLen != -1 and x >= 256**xLen:
        raise ValueError("integer too large")
    X = b""
    while True:
        X = (x % 256).to_bytes(1, "big") + X
        x = x // 256
        if x == 0:
            break
    if xLen != -1:
        X = b"\x00" * (xLen - len(X)) + X
    return X

def XOR(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings together."""
    if len(a) != len(b):
        raise ValueError("lengths must be equal")
    c = b""
    for i in range(len(a)):
        c += (a[i] ^ b[i]).to_bytes(1, "big")
    return c