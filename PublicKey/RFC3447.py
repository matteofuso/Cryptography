from os import urandom
import hashlib


class Key:
    def __init__(self, m, e):
        self.m = m
        self.e = e


def XOR(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings together."""
    if len(a) != len(b):
        raise ValueError("lengths must be equal")
    c = b""
    for i in range(len(a)):
        c += (a[i] ^ b[i]).to_bytes(1, "big")
    return c


def PrimitiveEncrypt(key: Key, m: int) -> int:
    """RSA encryption primitive (RSAEP)"""
    # RFC3447 5.1.1 RSAEP
    # https://datatracker.ietf.org/doc/html/rfc3447#section-5.1.1
    if m < 0 or m >= key.m:
        raise ValueError("message representative out of range")
    return int(pow(m, key.e, key.m))


def PrimitiveDecrypt(key: Key, c: int) -> int:
    """RSA decryption primitive (RSADP)"""
    # RFC3447 5.1.2 RSADP
    # https://datatracker.ietf.org/doc/html/rfc3447#section-5.1.2
    if c < 0 or c >= key.m:
        raise ValueError("ciphertext representative out of range")
    return int(pow(c, key.e, key.m))


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


def MGF1(Z: bytes, l: int, Hash=hashlib.sha1) -> bytes:
    """Mask generation function."""
    # RFC3447 B.2.1 MGF1
    # https://datatracker.ietf.org/doc/html/rfc3447#appendix-B.2.1
    hLen = Hash().digest_size
    if l > (hLen << 32):  # << 32 is the same as * 2^32
        raise ValueError("mask too long")
    T = b""
    counter = 0
    while len(T) < l:
        C = int.to_bytes(counter, 4, "big")
        T += Hash(Z + C).digest()
        counter += 1
    return T[:l]


def EmeOaepEncoding(
    Hash, MGF, mLen: int, hLen: int, k: int, M: bytes, L: bytes
) -> bytes:
    """EME-OAEP encoding"""
    # RFC3447 7.1.1.2 EME-OAEP encoding
    # https://datatracker.ietf.org/doc/html/rfc3447#section-7.1.1
    lHash = Hash(L).digest()
    ps_len = k - mLen - 2 * hLen - 2
    ps = b"\x00" * ps_len
    db = lHash + ps + b"\x01" + M
    seed = urandom(hLen)
    dbMask = MGF(seed, k - hLen - 1)
    maskedDB = XOR(db, dbMask)
    seedMask = MGF(maskedDB, hLen)
    maskedSeed = XOR(seed, seedMask)
    return b"\x00" + maskedSeed + maskedDB


def EmeOaepDecoding(Hash, MGF, EM: bytes, L: bytes, hLen: int, k: int) -> bytes:
    """EME-OAEP decoding"""
    # RFC3447 7.1.2.3 EME-OAEP decoding
    # https://datatracker.ietf.org/doc/html/rfc3447#section-7.1.2
    lHash = Hash(L).digest()
    Y = EM[0]
    maskedSeed = EM[1 : hLen + 1]
    maskedDB = EM[hLen + 1 :]
    seedMask = MGF(maskedDB, hLen)
    seed = XOR(maskedSeed, seedMask)
    dbMask = MGF(seed, k - hLen - 1)
    db = XOR(maskedDB, dbMask)
    lHash2 = db[:hLen]
    separator = db.find(b"\x01") + 1
    if separator == 0 or lHash != lHash2 or Y != 0:
        raise ValueError("decryption error")
    return db[separator:]


def Encrypt(M: bytes, key: Key, Hash=hashlib.sha1, MGF=MGF1, L=b"") -> bytes:
    """RSAES-OAEP-ENCRYPT"""
    # RFC3447 7.1.1 Encryption operation
    # https://datatracker.ietf.org/doc/html/rfc3447#section-7.1.1
    mLen = len(M)
    hLen = Hash().digest_size
    k, r = divmod(key.m.bit_length(), 8)
    if r != 0:
        k += 1
    # 1 Length checking
    if mLen > k - 2 * hLen - 2:
        raise ValueError("message too long")
    # 2 EME-OAEP encoding
    EM = EmeOaepEncoding(Hash, MGF, mLen, hLen, k, M, L)
    # 3 RSA encryption
    m = BytesToInt(EM)
    c = PrimitiveEncrypt(key, m)
    C = IntToBytes(c, k)
    return C


def Decrypt(C: bytes, key: Key, Hash=hashlib.sha1, MGF=MGF1, L=b"") -> bytes:
    """RSAES-OAEP-DECRYPT"""
    # RFC3447 7.1.2 Encryption operation
    # https://datatracker.ietf.org/doc/html/rfc3447#section-7.1.2
    hLen = Hash().digest_size
    k, r = divmod(key.m.bit_length(), 8)
    if r != 0:
        k += 1
    # 1 Length checking
    if (len(C) != k) or (k < 2 * hLen + 2):
        raise ValueError("decryption error")
    # 2 RSA decryption
    c = BytesToInt(C)
    m = PrimitiveDecrypt(key, c)
    EM = IntToBytes(m, k)
    # 3 EME-OAEP decoding
    M = EmeOaepDecoding(Hash, MGF, EM, L, hLen, k)
    return M
