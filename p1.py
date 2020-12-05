from Cryptodome.Util.number import getPrime, inverse, GCD, getRandomRange
from decimal import Decimal, localcontext
import os
from Cryptodome.Random.random import randint
from argparser import parser
from generatedRsaParams import p, q
from generateRsaParams import generate_e_d_P1, getPrimePair, generators
import millerrabin

def get_f_s_from_N (N):

    f = 0
    copyN = N
    while (N % 2 == 0):
        f = f + 1
        N = N // 2
    
    s = N

    #print("N = (2^f)*s")
    #print(copyN," = (2^",f,") * ",s,"\n")
    return f, s

def find_l (b, n):
    l = 0
    pow_b = pow(2, l)
    kv_pow = pow(b,pow_b)
    while (pow(b,pow_b,n)!=1):
        print("b^2^",l," = ",pow(b,pow_b,n))
        l = l+1
        pow_b = pow(2, l)
    return l

def _common_module_attack(n, e_b, d_b, e_a):

    N = (e_b * d_b) - 1             # 1) N <- (e_b*d_b)-1
    f, s = get_f_s_from_N(N)        #    N = (2^f)*s

    a = randint(1, n-1)             # 2) a <- rand (Z/nZ)
    b = pow(int(a), int(s), int(n))                #    b <- a^s (mod n)
    print ("b = ", b)
    l_and_t_found = False
    print("start finding l")
    l = find_l(b, int(n))
    
    while (not l_and_t_found):      # 3) b^(2^l) = 1 (mod n)
                                    #    if (b^(2^(l-1)) = -1 (mod n))
        pow_b = pow(2, l-1)         #       new rand a, go to 2)
        if (pow(b,pow_b,n)==-1):    #    else 
            a = randint(1, n-1)     #       t <- b^(2^(l-1)) (mod n)
            b = pow(a, s, n)
            l = find_l(b)
        else:
            t = pow(b,pow_b,n)
            l_and_t_found = True

    p = GCD(t+1, n)                 # 4) p <- gcd(t+1,n)
    q = GCD(t-1, n)                 #    q <- gcd(t-1,n)

    f_n_2 = (p-1)*(q-1)
    d_a = inverse(e_a, f_n_2)
    while (d_a == d_b):
        d_a = inverse(e_b, f_n_2)
    if d_b != d_a:
        print("Attack for common module: Success")
    else:
        print("Attack for common module: Failed")


    
    
    
    




if __name__ == "__main__":
    p, q = getPrimePair()
    print("p = ",p)
    print("q = ",q)
    print("LENS = ", len(generators(q)))
  
    #n, e_a, d_a = generate_e_d_P1(p, q)
    #n, e_b, d_b = generate_e_d_P1(p, q)
    #_common_module_attack(int(n),int(e_b),int(d_b), int(e_a))
