from Cryptodome.Util.number import getPrime, inverse, GCD, getRandomRange
from decimal import Decimal, localcontext
import os
from Cryptodome.Random.random import randint
from argparser import parser
from generatedRsaParams import p, q
from generateRsaParams import generate_e_d_P1, generate_e_d_P2
from math import log2, log


def _continuedFraction (e, n, f):

    if e==0 or n==0:
        return True
    if e == 1:
        f.append(n)
        return True
    if n == 1:
        f.append(e)
        return True
    
    if (e>=n):
        f.append(e // n)
        n = e % n
        temp = e
        e = n
        n = temp
    else:
        f.append(n // e)
        n = n % e
        temp = e
        e = n
        n = temp
    _continuedFraction(e, n , f)


def _vinner_attack():
    
    print("Generating vulnerable parameters...")
    n, e_a, d_a = generate_e_d_P2()
    print("n = ",n)
    print("e_a = ",e_a)
    print("d_a = ",d_a)
    
    l = round(log2(n))
    a_i = []
    if e_a < n:
        a_i.append(0)
    
    _continuedFraction(e_a, n, a_i)     # 1) (e/n) -> [0; a0, a1, ... al]
    p_i = []
    q_i = []
    
    p_i.append(1)
    p_i.append(0)
    q_i.append(0)
    q_i.append(1)
    d = 0
    i = 1                               # 2) for i = 1, ... , l
                                        #       pi/qi
    while i<len(a_i):
        
        new_p_i = a_i[i]*p_i[i]+p_i[i-1] # pi = ai*p_i-1 + p_i-2
        new_q_i = a_i[i]*q_i[i]+q_i[i-1] # qi = ai*q_i-1 + q_i-2
        nod = GCD(new_p_i, new_q_i)
        new_p_i //= nod
        new_q_i //= nod
        p_i.append(new_p_i)
        q_i.append(new_q_i)
       
        m = randint(pow(2,5), pow(2,16))
        m_q = pow(m,new_q_i*e_a,n)       # (m^e)^qi =? m (mod n)
         
        if (m_q == m):
            d = new_q_i
            break
        i = i+1
        if i==len(a_i):
            d = new_q_i
    if (d == d_a):
        print("Success")
    else:
        print("d_a = ",d_a)
        print("d = ",d)
        print("Failure")
    return True


if __name__ == "__main__":

    _vinner_attack()
    
    
