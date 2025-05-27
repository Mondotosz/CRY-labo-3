# https://pycryptodome.readthedocs.io/en/latest/src/cipher/oaep.html
from Crypto.Cipher import PKCS1_OAEP

# https://pycryptodome.readthedocs.io/en/latest/src/public_key/rsa.html
from Crypto.PublicKey import RSA
from base64 import b64decode, b64encode

from sage.all import random_prime, next_prime, ZZ, inverse_mod, gcd, isqrt, is_square


def encrypt(m: bytes, key: RSA.RsaKey) -> bytes:
    cipher = PKCS1_OAEP.new(key)
    return cipher.encrypt(m)


def decrypt(c: bytes, key: RSA.RsaKey) -> bytes:
    cipher = PKCS1_OAEP.new(key)
    return cipher.decrypt(c)


def keygen():
    phi = 65537
    e = 65537
    n = 1
    while gcd(phi, e) != 1:
        n = 1
        phi = 1
        p = random_prime(2 ^ 1048)
        q = next_prime(
            p + ZZ.random_element(2 ^ 15)
        )  # to ensure that both primes have similar sizes
        n = p * q
        phi = (p - 1) * (q - 1)
    return RSA.construct(
        (int(n), int(e), int(inverse_mod(e, phi))), consistency_check=True
    )


def main_decrypt():
    key = keygen()
    M = b"Hello world!"
    c = encrypt(M, key)
    m = decrypt(c, key)
    if m == M:
        print(f"successfully decrypted: {m}")
    else:
        print("decrypted result doesn't match expected value.")
        print(f"expected: {M}")
        print(f"actual  : {m}")


def fermat_factor(N):
    # https://en.wikipedia.org/wiki/Fermat%27s_factorization_method
    a = isqrt(N)
    b2 = a * a - N
    is_sqrt = is_square(b2, root=True)
    while not is_sqrt[0]:
        a = a + 1
        b2 = a * a - N
        is_sqrt = is_square(b2, root=True)
    return a - is_sqrt[1], a + is_sqrt[1]


def main_break():
    key_data = b"-----BEGIN PUBLIC KEY-----\nMIIBKDANBgkqhkiG9w0BAQEFAAOCARUAMIIBEAKCAQcA3KThls9LRMAbCNt4OdSx\nhlVvY7MOGaUo5Ug3lGL2w/BmR6C396j32/+tRibWrryJYv78xHFulNYqmR7ivvRU\nACc3KOxU+mR2f4/e9si18qSK0OkqZ5nzl4GTMXfMz4TulOek4Sbo3j4oukHNrSCi\nLX5qhfnSVRCHQD6vXEIqlEhks9FuFnAMcC1lg6FM5yODBe9SJaiMY0yq28eca6u/\ngHRM0VyMh7b61vizRXDb85U0n0dV9AIooMpITJFJz2yPM0L7PziwpofRKR4JnllV\n3UwFuXKAC5BS7gUpqdvpW/alzk90Q11e/78ry8YM2gT0wSZ9nhQqDrboMQXni49f\n8BRplcEtAQIDAQAB\n-----END PUBLIC KEY-----"
    pub_key = RSA.import_key(key_data)
    p, q = fermat_factor(pub_key.n)
    e = 65537
    phi = (p - 1) * (q - 1)
    priv_key = RSA.construct(
        (int(pub_key.n), int(e), int(inverse_mod(e, phi))), consistency_check=True
    )

    c = b64decode(
        b"BC/TJMwJydzYQ/L4Z7/Obb89q0EMHpQVsHbxwoiz2AiQnYr2tiJaf5RYoRKR84ly9MX2axSRoaJtrZXlQLx8LdsjrBosUhJyYwgrbh15z3DAQk73LOJykUwX6hjy0I2UITtPA6uqoBL8XYDWgb9xgtCs7q7nLFovDCGxJNwwV3spQHmFDhwC87lO5BJopMidgQlE+N3lp8JP0HMpYCR04bwCs8BTYpScuW2c5Mhz5bLBNEiimbrPR/0THbd5WDU7CFpVKvgdkbvnz+ldXNT9AL97v1Rt/7Wc1n7ty6SJod7tMdTzpZd7UqpLE0JMO4vUqlx+SKidNWhAq6pD3i4aIiBzM7JfnA=="
    )

    print(decrypt(c, priv_key))


def main_brute_force():
    key_data = b"-----BEGIN PUBLIC KEY-----\nMIIBKDANBgkqhkiG9w0BAQEFAAOCARUAMIIBEAKCAQcA3KThls9LRMAbCNt4OdSx\nhlVvY7MOGaUo5Ug3lGL2w/BmR6C396j32/+tRibWrryJYv78xHFulNYqmR7ivvRU\nACc3KOxU+mR2f4/e9si18qSK0OkqZ5nzl4GTMXfMz4TulOek4Sbo3j4oukHNrSCi\nLX5qhfnSVRCHQD6vXEIqlEhks9FuFnAMcC1lg6FM5yODBe9SJaiMY0yq28eca6u/\ngHRM0VyMh7b61vizRXDb85U0n0dV9AIooMpITJFJz2yPM0L7PziwpofRKR4JnllV\n3UwFuXKAC5BS7gUpqdvpW/alzk90Q11e/78ry8YM2gT0wSZ9nhQqDrboMQXni49f\n8BRplcEtAQIDAQAB\n-----END PUBLIC KEY-----"
    pub_key = RSA.import_key(key_data)
    n = pub_key.n

    q = isqrt(n)
    while n % q != 0:
        q = next_prime(q)

    p = n / q

    e = 65537
    phi = (p - 1) * (q - 1)
    priv_key = RSA.construct(
        (int(pub_key.n), int(e), int(inverse_mod(e, phi))), consistency_check=True
    )

    c = b64decode(
        b"BC/TJMwJydzYQ/L4Z7/Obb89q0EMHpQVsHbxwoiz2AiQnYr2tiJaf5RYoRKR84ly9MX2axSRoaJtrZXlQLx8LdsjrBosUhJyYwgrbh15z3DAQk73LOJykUwX6hjy0I2UITtPA6uqoBL8XYDWgb9xgtCs7q7nLFovDCGxJNwwV3spQHmFDhwC87lO5BJopMidgQlE+N3lp8JP0HMpYCR04bwCs8BTYpScuW2c5Mhz5bLBNEiimbrPR/0THbd5WDU7CFpVKvgdkbvnz+ldXNT9AL97v1Rt/7Wc1n7ty6SJod7tMdTzpZd7UqpLE0JMO4vUqlx+SKidNWhAq6pD3i4aIiBzM7JfnA=="
    )

    print(decrypt(c, priv_key))


if __name__ == "__main__":
    # main_decrypt()
    main_break()
    main_brute_force()
