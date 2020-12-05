from Crypto.PublicKey import RSA
import Crypto.Util.number

from hashlib import sha1
from Cryptodome.Hash import SHA256

def RSA_data_Encryption(plaintext, e, n):
    #plaintext = open(plaintextPath, "rb").read()
    return pow(plaintext, e, n)

def RSA_data_Decryption(ciphertext, d, n):
    #ciphertext = open(textPath, "rb").read()
    return pow(ciphertext, d, n)

def RSA_data_Sign(path, d, n):
    plaintext = open(path, "rb").read()
    r = SHA256.new(plaintext).hexdigest()
    r = int(r,16)
    s = pow(int(r), d, n)
    return s

def RSA_data_CheckSign(signature, e, n, textPath):
    t = pow(signature, e, n)
    text = open(textPath, "rb").read()
    r = SHA256.new(text)
    r = int(r.hexdigest(),base=16)%n

    if (r==t):
        return True
    return False