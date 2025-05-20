from Crypto.Random import get_random_bytes
from Crypto.Signature.pss import MGF1
from Crypto.Hash import SHA256
from Crypto.Util.strxor import strxor
from Crypto.Util.Padding import pad, unpad


BIT_LEN_PRIME = 1024#2048
BYTE_LEN_RANDOMNESS = 128
REDUNDANCY = 10


def keyGen():
    p = 1
    while p %4 != 3: 
        p = random_prime(2**BIT_LEN_PRIME, proof = False, lbound = 2**(BIT_LEN_PRIME-1)) #proof = False for performances
    q = 1
    while q % 4 != 3: 
        q = random_prime(2**BIT_LEN_PRIME, proof = False, lbound = 2**(BIT_LEN_PRIME-1)) #proof = False for performances
    return (p, q, p*q)


def mgf(seed, length):
    #This function is correct and you don't need to look at it
    #It generates a mask of given length using the seed as input
    return MGF1(seed, length, SHA256)

def encrypt(m, n):
    BYTE_LEN_MESSAGE_PART = int(log(n,2))//8 - BYTE_LEN_RANDOMNESS
    if len(m) > BYTE_LEN_MESSAGE_PART - REDUNDANCY - 1 :
        raise Exception("Message too long. Maximum " + str(BYTE_LEN_MESSAGE_PART - REDUNDANCY - 1) + " bytes")
    m = pad(m, BYTE_LEN_MESSAGE_PART, style = 'iso7816')
    r = get_random_bytes(BYTE_LEN_RANDOMNESS)
    h = mgf(r, BYTE_LEN_MESSAGE_PART)
    m = strxor(m, h) + r
    return (int.from_bytes(m, 'little')**2) % n

