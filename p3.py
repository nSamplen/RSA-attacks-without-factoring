from Cryptodome.Util.number import getPrime, inverse, GCD, getRandomRange
from decimal import Decimal, localcontext
import os
from Cryptodome.Random.random import randint
from argparser import parser
from generatedRsaParams import p, q
from generateRsaParams import generate_e_d_P1, generate_e_d_P2
import asnGenerator
from chinese_remainder_theorem import crt
from aesusage import *
import gmpy2
import millerrabin




#key_s = b'\xb3\xec_T\x1b[\x19^OJ\x83\x8ew\xb5\x19\x92\x84\x9b\x8c\xf1\x9e\x11\x07\x0eY\xa0G2eRi"'
# x =  3323547697.0

#-----------------user1-----------------
#e = 3
#p = 23
#q = 29
#n = 667
#f_n = 616
#d = 411

#-----------------user2-----------------
#e = 3
#p = 41
#q = 47
#n = 1927
#f_n = 1840
#d = 1227


#-----------------user3-----------------
#e = 3
#p = 53
#q = 59
#n = 3127
#f_n = 3016
#d = 2011


def getPrimePair(bits=128):
    q = millerrabin.gen_prime(bits)
    p = millerrabin.gen_prime_range(q+1, 2*q)
    return p,q

def kto(n1,n2,n3,c1,c2,c3,iv_fromCipher, kol):
    print("IV = ", iv_fromCipher)
    if (GCD(n1,n2)!=1 or GCD(n1,n3)!=1 or GCD(n3,n2)!=1):
        print('wrong ni ')
        return False
    M_0 = n1*n2*n3
    #print("n1*n2*n3 = ",n1," * ",n2," * ",n3," = ",M_0)
    #print("c1 = ", c1)
    #print("c2 = ", c2)
    #print("c3 = ", c3)
    M_1 = M_0 // n1
    M_2 = M_0 // n2
    M_3 = M_0 // n3
    #print("M1 = ", M_1)
    #print("M2 = ", M_2)
    #print("M3 = ", M_3)

    M_1_y=M_1 % n1
    M_2_y=M_2 % n2
    M_3_y=M_3 % n3
    #print("b1 = ", M_1_y)
    #print("b2 = ", M_2_y)
    #print("b3 = ", M_3_y)


    y1, y2, y3 =1, 1, 1

    while(y1<=n1):
        if (M_1_y*y1)%n1 == c1:
            break
        y1+=1

    while(y2<=n2):
        if (M_2_y*y2)%n2 == c2:
            break
        y2+=1

    while(y3<=n3):
        if (M_3_y*y3)%n3 == c3:
            break
        y3+=1

    x = (M_1*y1 + M_2*y2 + M_3*y3) % M_0
    print("x = ", x)

    gmpy2.get_context().precision = 200
    m = int(gmpy2.root(x,3))
    print("m = ", m)

    print("x^(1/3) ", round(pow(x,1/3)))
    decryptedKey_S = m.to_bytes(16, 'big')
    print('Dec Key s = ', decryptedKey_S)
    
    b = bytearray()
    with open('~tmp'+"wallpapers1.jpg.ecrypted", 'rb') as file:
        data = file.read()
        #print('Cipher:\n')
        #print(data)
        print('Decrypted:\n')
        decryptedText = AES_data_Decryption(data, decryptedKey_S, iv_fromCipher)
        print("kol = ",kol)
        print("len(cip) = ", len(decryptedText))
        kol2 = len(decryptedText)
       # i=0
       # while i<kol:
       #     b.append(decryptedText[i])
       #     i=i+1
            #pad(data,AES.block_size), decryptedKey_S, iv_fromCipher)
        #decryptedText = unpad(decryptedText, AES.block_size)
        

    #print(decryptedText)
    os.remove('~tmp'+"wallpapers1.jpg.ecrypted")

    output = open("wallpapers1.jpg.encrypted"+'.decrypted','wb')
    output.write(b)
    output.close()
    

def _keylessDecryption_broadcast_msg (path):

    n_1, n_2, n_3, e, key_S_1, key_S_2, key_S_3, iv_1, kol1 = asnGenerator.decode(path)
    #n_2, e_2, key_S_2, iv_2, kol2 = asnGenerator.decode("wallpapers2.jpg.ecrypted")
    #n_3, e_3, key_S_3, iv_3, kol3 = asnGenerator.decode("wallpapers3.jpg.ecrypted")

    m = (n_1, n_2, n_3)
    a = (key_S_1, key_S_2, key_S_3)

    x = crt(m, a)
    #print("x ==== ", x)
    print("\n\nX = ",x)
    #print("x^(1/3) = ", pow(x,1/3)+1)
    gmpy2.get_context().precision = 200
    m = int(gmpy2.root(x,3))
    print("m = ", m)

    decryptedKey_S = m.to_bytes(16, 'big')
    print('Dec Key s = ', decryptedKey_S)
    print("IV = ", iv_1)
    
    b = bytearray()
    with open('~tmp'+path, 'rb') as file:
        data = file.read()
        #print('Cipher:\n')
        #print(data)
        print('Decrypted:\n')
        decryptedText = AES_data_Decryption(data, decryptedKey_S, iv_1)
        #print("kol = ",kol1)
        #print("len(cip) = ", len(decryptedText))
        kol2 = len(decryptedText)
        i=0
        while i<kol1:
            b.append(decryptedText[i])
            i=i+1
            #pad(data,AES.block_size), decryptedKey_S, iv_fromCipher)
        #decryptedText = unpad(decryptedText, AES.block_size)
        

    #print(decryptedText)
    os.remove('~tmp'+path)

    output = open(path+".decrypted",'wb')
    output.write(b)#decryptedText)
    output.close()

    #kto(n_1,n_2,n_3,key_S_1,key_S_2,key_S_3, iv_1, kol1)




if __name__ == "__main__":
    #s = os.urandom(16)
    #print(s) 
    args = parser.parse_args()
    _keylessDecryption_broadcast_msg(args.filepath)
   


    

    
    
