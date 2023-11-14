from os import urandom
from Utils import Primality, BytesOperations, DER
import hashlib
import math


class Key:
    def __init__(self, m, e):
        self.m = m
        self.e = e


class Primes:
    def __init__(self, p: int, q: int):
        self.p = p
        self.q = q


def PrivateKeyExport(n, e, d, p, q, oid = "1.2.840.113549.1.1.1"):
    # PrivateKeyInfo ::= SEQUENCE {
    #     version                   Version,
    #     privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
    #     privateKey                PrivateKey,
    #     attributes           [0]  IMPLICIT Attributes OPTIONAL
    # }
    payload = DER.SequenceEncode(
        [
            DER.NumberEncode(0),
            DER.SequenceEncode(
                [DER.OIDEncode(oid), DER.NullEncode()]
            ),
            DER.OctetStringEncode(
                DER.SequenceEncode(
                    [
                        DER.NumberEncode(0),
                        DER.NumberEncode(n),
                        DER.NumberEncode(e),
                        DER.NumberEncode(d),
                        DER.NumberEncode(p),
                        DER.NumberEncode(q),
                        DER.NumberEncode(d % (p - 1)),
                        DER.NumberEncode(d % (q - 1)),
                        DER.NumberEncode(pow(q, -1, p)),
                    ]
                )
            ),
        ]
    )
    return DER.BuildPEM(payload, "RSA PRIVATE KEY")


def PublicKeyExport(n, e, oid = "1.2.840.113549.1.1.1"):
    payload = DER.SequenceEncode(
        [
            DER.SequenceEncode(
                [DER.OIDEncode(oid), DER.NullEncode()]
            ),
            DER.BitStringEncode(
                DER.SequenceEncode([DER.NumberEncode(n), DER.NumberEncode(e)])
            ),
        ]
    )
    return DER.BuildPEM(payload, "PUBLIC KEY")


def GeneratePrimes(bit: int, e: int) -> Primes:
    """Generate two primes p and q with bit length bit and e as public exponent."""
    pBit = bit // 2
    qBit = bit - pBit
    while True:
        p = Primality.GenerateProbeblyPrime(pBit)
        q = Primality.GenerateProbeblyPrime(qBit)
        if (
            p != q
            and (p * q).bit_length() == bit
            and math.gcd(e, (p - 1) * (q - 1)) == 1
        ):
            break
    if p > q:
        p, q = q, p
    return Primes(p, q)


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
    maskedDB = BytesOperations.XOR(db, dbMask)
    seedMask = MGF(maskedDB, hLen)
    maskedSeed = BytesOperations.XOR(seed, seedMask)
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
    seed = BytesOperations.XOR(maskedSeed, seedMask)
    dbMask = MGF(seed, k - hLen - 1)
    db = BytesOperations.XOR(maskedDB, dbMask)
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
    m = BytesOperations.BytesToInt(EM)
    c = PrimitiveEncrypt(key, m)
    C = BytesOperations.IntToBytes(c, k)
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
    c = BytesOperations.BytesToInt(C)
    m = PrimitiveDecrypt(key, c)
    EM = BytesOperations.IntToBytes(m, k)
    # 3 EME-OAEP decoding
    M = EmeOaepDecoding(Hash, MGF, EM, L, hLen, k)
    return M
