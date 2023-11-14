from Utils import BytesOperations
import binascii

INTEGER = 2
BITSTRING = 3
OCTETSTRING = 4
OBJECTIDENTIFIER = 6
SEQUENCE = 48


def OctetLen(length):
    if length > 127:
        encoding = BytesOperations.IntToBytes(length)
        return bytes([len(encoding) + 128]) + encoding
    return bytes([length])

def OIDNumberEncode(number: int):
    b = bytearray()
    if number > 127:
        b.append(number % 128)
        while True:
            number >>= 7
            if number == 0:
                break
            b.insert(0, number % 128 + 128)
    else:
        b = bytes([number])
    return b

def Encapsulate(tag: int, payload: bytes):
    return bytes([tag]) + OctetLen(len(payload)) + payload


def NumberEncode(number: int):
    data = bytearray()
    while True:
        data.insert(0, number & 0xFF)
        if 128 <= number <= 255:
            data.insert(0, 0)
        if -128 <= number <= 255:
            break
        number >>= 8
    return Encapsulate(INTEGER, data)


def SequenceEncode(params):
    payload = bytearray()
    for param in params:
        payload += param
    return Encapsulate(SEQUENCE, payload)

def OctetStringEncode(string: bytes):
    return Encapsulate(OCTETSTRING, string)

def BitStringEncode(string: bytes):
    octet = string[-1]
    unused = 0
    for i in range(8):
        if octet & 0x01 == 0:
            octet >>= 1
            unused += 1
    print(string[-1], unused)
    return Encapsulate(BITSTRING, bytes([unused]) + string)

def OIDEncode(oid: str = "1.2.840.113549.1.1.1"):
    b = bytearray()
    # First two
    first = int(oid.split('.')[0])
    second = int(oid.split('.')[1])
    b.append(first*40+second)
    for i in oid.split('.')[2:]:
        b+=OIDNumberEncode(int(i))
    return Encapsulate(OBJECTIDENTIFIER, b)

def NullEncode():
    return bytes([5, 0])

def BuildPEM(data, type):
    out = "-----BEGIN %s-----\n" % type
    for i in range(0, len(data), 48):
        out += binascii.b2a_base64(data[i:i + 48]).decode("latin-1")
    out += "-----END %s-----" % type
    return out