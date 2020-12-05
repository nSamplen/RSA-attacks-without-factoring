
from argparser import parser
import os
import asn1

from aesusage import *
from rsausage import *
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Util.number import getPrime, inverse, GCD, getRandomRange
#from generatedRsaParams import e, p, q, n, f_n, d
import asnGenerator
import millerrabin
#from aesusage import iv, key_size

keyLen = 32

def getPrimePair(bits=128):
    q = millerrabin.gen_prime(bits)
    p = millerrabin.gen_prime_range(q+1, 2*q)
    return p,q

def encryptFile(path, e, n1, n2, n3):
    # Generate secret key
    #key_s = os.urandom(keyLen)
    #key_s = b'vdu\x16a\xb1$\x83\x82\x9f\xa3\x0bW13\x92\x04\xddC\xdc\xf4\xf8\x05\xa1\xf9C\xeb\xad\x04&\r\xab'
    key_s = b'Th\x84v\xc3\x1c\xb8_\xf2\x9e\x03\x9b\xd5U\x896'
    
    #key_s = b'3\x83\xfd\xe1"8\x1d\xa8\xb3q\xca\xc5\xab\xbdZ\xb5\xbd\xeb\xc0b\xff@\x0fI\xdc\xac\xaek\xb6\x81\x1d\xe8'
    print('Key s = ', int.from_bytes(key_s, byteorder='big'))
    #key_s=b'{\xba]\x8a\xf0+i\xb7'
    #input = open(path,'rb').read()
    #key_s = b'\xb3\xec_T\x1b[\x19^OJ\x83\x8ew\xb5\x19\x92\x84\x9b\x8c\xf1\x9e\x11\x07\x0eY\xa0G2eRi"'
    #
    #print('Key s = ', hex(int.from_bytes(key_s, "big")))
    #print('Plaintext:\n')
    #print(input)
    #iv = Random.new().read(AES.block_size)
    encryptedDataAES, iv, lenCip  = AES_data_Encryption(path, key_s)
    print("iv = ",iv)
    
    #print('Encrypted AES data:\n')
    #print(encryptedDataAES)
   #print("key_s = ", int.from_bytes(key_s, byteorder='big'))
    encryptedKey_S_1 = RSA_data_Encryption(
        int.from_bytes(key_s, byteorder='big'), 
        int(e),
        int(n1)
    )
    print("enc_key_s_1 = ", encryptedKey_S_1)
    encryptedKey_S_2 = RSA_data_Encryption(
        int.from_bytes(key_s, byteorder='big'), 
        int(e),
        int(n2)
    )
    print("enc_key_s_2 = ", encryptedKey_S_2)
    encryptedKey_S_3 = RSA_data_Encryption(
        int.from_bytes(key_s, byteorder='big'), 
        int(e),
        int(n3)
    )
    print("enc_key_s_3 = ", encryptedKey_S_3)

    asnCodedText = asnGenerator.encode(
        n1,
        n2,
        n3,
        e,
        encryptedKey_S_1,
        encryptedKey_S_2,
        encryptedKey_S_3,
        iv,
        lenCip,#len(encryptedDataAES),
        encryptedDataAES
    )

    output = open(path+'.ecrypted','wb')
    output.write(asnCodedText)
    output.close()

    #print('exp = ', e)
    #print('n = ', n)
    #print('d = ',d)


def decryptFile(path, d):
    #input = open(path,'rb').read()
    n_fromCipher, e_fromCipher, key_S_fromCipher, iv_fromCipher = asnGenerator.decode(path)
    #print('n = ', n_fromCipher)
    #print('e = ', e_fromCipher)
    #print('key_s = ', key_S_fromCipher)
   
    print('d = ', d)
    print('Enc Key s = ', key_S_fromCipher)
    decryptedKey_S = RSA_data_Decryption(
        key_S_fromCipher, 
        d,
        n_fromCipher
    )

    decryptedKey_S = decryptedKey_S.to_bytes(keyLen, 'big')
    print('Dec Key s = ', decryptedKey_S)

    with open('~tmp', 'rb') as file:
        data = file.read()
        #print('Cipher:\n')
        #print(data)
        print('Decrypted:\n')
        decryptedText = AES_data_Decryption(data, decryptedKey_S, iv_fromCipher)
            #pad(data,AES.block_size), decryptedKey_S, iv_fromCipher)
        decryptedText = unpad(decryptedText, AES.block_size)

    print(decryptedText)
    os.remove('~tmp')

    output = open(path+'.decrypted','wb')
    output.write(decryptedText)
    output.close()

def addSignature(path, n, d):

    #input = open(path,'rb').read()
    sign_RSA = RSA_data_Sign(path, d, n)

    #signature = addSignatureRSA(path, int(d_sig, 16), int(n_sig, 16))

    encodedBytes = asnGenerator.encode_sign(n, d, sign_RSA)

    with open(path + '.sign', 'wb') as file:
        file.write(encodedBytes)
    
    return

def checkSignature(filePath, signPath, e):

    n_fromSign, Sign_fromSign = asnGenerator.decode_sign(signPath)
    #input = open(filePath,'rb').read()
    return RSA_data_CheckSign(
        Sign_fromSign, 
        e, 
        n_fromSign,
        filePath
        )

def main():

    print("Generating parameters...\n")
    print("e = 3\n")
    
    
    p1, q1 = getPrimePair()
    p2, q2 = getPrimePair()
    p3, q3 = getPrimePair()
    e = 3
    n1 = p1*q1 #667
   
    n2 = p2*q2 #1927
    n3 = p3*q3 #3127


    if (GCD(n1,n2)!=1 or GCD(n1,n3)!=1 or GCD(n2,n3)!=1):
        print("NE OK")

    print("user1:")
    print("p = ",p1)
    print("q = ",q1)
    print("n = ", n1)

    print("\nuser2:")
    print("p = ",p2)
    print("q = ",q2)
    print("n = ", n2)

    print("\nuser3:")
    print("p = ",p3)
    print("q = ",q3)
    print("n = ", n3)
    #k = 0
    #while(k<5):
    #path = str(input("\nInput filepath: "))
    encryptFile('wallpapers1.jpg', e, n1, n2, n3)
       # elif k == 2:
       #     encryptFile('wallpapers2.jpg', e, n2)
       # elif k == 3:
        #    encryptFile('wallpapers3.jpg', e, n3)

    #print("x = ", 3323547697.0)
    #print("key_s = ", int.from_bytes(key_s, byteorder='big'))
    #encryptedKey_S = RSA_data_Encryption(
    #    int.from_bytes(key_s, byteorder='big'), 
    #    int(e),
    #    int(n)
    #)
    #print("enc_key_s = ",encryptedKey_S)
    #encryptFile("wallpapers3.jpg")
    # decryptFile(args.filepath)

    
if __name__ == '__main__':
    main()