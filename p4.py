from Cryptodome.Util.number import getPrime, inverse, GCD, getRandomRange
from decimal import Decimal, localcontext
import os
from Cryptodome.Random import get_random_bytes
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


def getPrimePair(bits=1024):
    q = millerrabin.gen_prime(bits)
    p = millerrabin.gen_prime(bits)
    return p,q

def good_parameters():
    p, q = getPrimePair()
    n = p * q
    f_n = (p - 1) * (q - 1)

    while(True):
        e = randint(1,f_n-1)
        if (GCD(e,f_n)==1):
            d = inverse(e,f_n)
            if 36*pow(d,4) > n:
                break

    
    print("p = {}".format(p))
    print("q = {}".format(q))
    print("n = {}".format(n))
    print("e = {}".format(e))
    print("d = {}".format(d))

if __name__ == "__main__":
    #s = os.urandom(16)
    #print(s) 
    good_parameters()
   


    

    
    
