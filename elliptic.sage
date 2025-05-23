from typing import Tuple, Any
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from base64 import b64encode, b64decode
from pprint import pprint

from sage.all import EllipticCurve, GF, ZZ, discrete_log
from sage.schemes.elliptic_curves.ell_point import EllipticCurvePoint_finite_field
from sage.schemes.elliptic_curves.ell_finite_field import EllipticCurve_finite_field


def params() -> Tuple[EllipticCurvePoint_finite_field, EllipticCurve_finite_field, int]:
    p = 50043062554237280172405801360375653460619548838234052036762494431728976610313
    a = 43327883319811199442996705732365163443043431995328598938729525921048235234958
    b = 45494814375791703888029144132071347443317277861841182091738819980027414195528
    gx = 34736706601617260336801089627448256371787243214661931571076381713565253696521
    gy = 5887497935320424287803691270199037907654978138532428031269063384390017951571
    n = 2550513000803
    E = EllipticCurve(GF(p), [a, b])
    G = E(gx, gy)
    return (G, E, n)


def keyGen(
    G: EllipticCurvePoint_finite_field, n: int
) -> Tuple[Any, EllipticCurvePoint_finite_field]:
    a = ZZ.random_element(n)
    A = a * G
    return (a, A)


def serialize_point_compressed(P):
    # no error in this code
    p = P.curve().base_field().order()
    byte_length = (p.nbits() + 7) // 8
    x_bytes = int(P[0]).to_bytes(byte_length, "big")
    prefix = b"\x02" if int(P[1]) % 2 == 0 else b"\x03"
    return prefix + x_bytes


def deserialize_point_compressed(data, E) -> EllipticCurvePoint_finite_field:
    # no error in this code
    prefix = data[0]
    if prefix not in (2, 3):
        raise ValueError("Invalid compression prefix")

    x_bytes = data[1:]
    x = int.from_bytes(x_bytes, "big")
    xF = E.base_field()(x)

    # lift_x returns a point with given x and the correct y parity
    try:
        P = E.lift_x(xF, all=False)
    except ValueError:
        raise ValueError("Invalid x: no point found on the curve")

    # Check parity
    if (int(P[1]) % 2 == 0 and prefix == 2) or (int(P[1]) % 2 == 1 and prefix == 3):
        return P
    else:
        # Flip to the other y if parity doesn't match
        return -P


def encrypt(A, M, G, n):
    r = ZZ.random_element(n)
    rA = r * A
    k = HKDF(serialize_point_compressed(rA), 32, b"", SHA256, num_keys=1)
    cipher = AES.new(k, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(M)
    return (serialize_point_compressed(r * G), (cipher.nonce, ciphertext, tag))


def decrypt(a, rg, nonce, ciphertext, tag):
    (_, E, _) = params()
    rA = deserialize_point_compressed(rg, E) * a
    k = HKDF(serialize_point_compressed(rA), 32, b"", SHA256, num_keys=1)
    cipher = AES.new(k, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


def main_encrypt():
    (G, E, n) = params()
    (a, A) = keyGen(G, n)
    M = b"hello world!"
    serialized_public_key = serialize_point_compressed(A)
    (c_0, (nonce, ciphertext, tag)) = encrypt(A, M, G, n)
    pprint(
        {
            "serialized_public_key": b64encode(serialized_public_key),
            "c_0": b64encode(c_0),
            "nonce": b64encode(nonce),
            "ciphertext": b64encode(ciphertext),
            "tag": b64encode(tag),
        }
    )


def main_decrypt():
    (G, E, n) = params()
    (a, A) = keyGen(G, n)
    M = b"hello world!"
    (c_0, (nonce, ciphertext, tag)) = encrypt(A, M, G, n)
    print(decrypt(a, c_0, nonce, ciphertext, tag))


def main_break():
    (G, E, n) = params()
    serialized_public_key = b64decode(b"Azyzwrbtosf/8mammt4UnselajQ9GjSmr7j6PoLXbzb4")
    A = deserialize_point_compressed(serialized_public_key, E)
    c_0 = b64decode(
        b"Ala4UlRJwW/OGXSd2vjiil+cAbe8BB6Icnmg1lY7od58"
    )  # part rG of the ciphertext
    rG = deserialize_point_compressed(c_0, E)
    nonce = b64decode(b"Itf6J9b2Bf3GaS+X4nDYYg==")
    ciphertext = b64decode(
        b"ouQOI1X8w/CdAUizv+A7Npg7jppKF/HqXcZnKctSEuz4TtGPK/FDt1iyQWi7OBKZt63QmIeJwbUHrKa7N/WSQuvKvbT3"
    )
    tag = b64decode(b"vYXO0dhqATLPO+3dsMBd6A==")
    # fortunately, both a and r can be found using the dicrete log.
    # Only one of the values is needed and the computation can be expensive so
    # the rest is commented for now. If we absolutely needed to optimize this
    # we could use multithreading to race both computation and work with the
    # first result.

    # a = G.discrete_log(A)
    a = A.log(G)
    # r = G.discrete_log(rG)
    # r = rG.log(G)
    print(decrypt(a, c_0, nonce, ciphertext, tag))


if __name__ == "__main__":
    # main_encrypt()
    # main_decrypt()
    main_break()
