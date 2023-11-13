from Utils import BytesOperations
import binascii

INTEGER = 2
SEQUENCE = 48

def OctetLen(length):
    """Build length octets according to BER/DER definite form."""
    if length > 127:
        encoding = BytesOperations.IntToBytes(length)
        return bytes([len(encoding) + 128]) + encoding
    return bytes([length])


def DerBuilder(tag, payload: bytes):
    return bytes([tag]) + OctetLen(len(payload)) + payload


def EncodeNumber(n: int):
    payload = b""
    while True:
        payload = bytes([n & 0xFF]) + payload
        if 128 <= n <= 255:
            payload = bytes([0]) + payload
        if -128 <= n <= 255:
            break
        n >>= 8
    return DerBuilder(INTEGER, payload)


def EncodeSequence(params):
    payload = b""
    for param in params:
        payload += EncodeNumber(param)
    return DerBuilder(SEQUENCE, payload)

def BuildPEM(data, type):
    out = "-----BEGIN %s-----\n" % type
    for i in range(0, len(data), 48):
        out += binascii.b2a_base64(data[i:i + 48]).decode("latin-1")

    out += "-----END %s-----" % type
    return out