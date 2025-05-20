from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from base64 import b64decode, b64encode

def encrypt(m, key):
    cipher = PKCS1_OAEP.new(key)
    return cipher.encrypt(m)


def keygen():
    phi = 65537
    e = 65537
    n = 1
    while gcd(phi, e) != 1:
        n = 1
        phi = 1
        p = random_prime(2^1048)
        q = next_prime(p + ZZ.random_element(2^15)) #to ensure that both primes have similar sizes
        n = p*q
        phi = (p-1)*(q-1)
    return RSA.construct((int(n), int(e), int(inverse_mod(e,phi))), consistency_check=True)
    

