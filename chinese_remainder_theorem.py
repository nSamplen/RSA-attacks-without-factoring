from functools import reduce
from operator import mul, mod
from decimal import getcontext
from decimal import Decimal

def egcd(a,b):
    if a==0:
        return b, 0, 1
    else:
        g, y, x = egcd(b%a, a)
        return g, x- (b//a)*y, y

def crt(m,a):
    getcontext().prec = 300
    M = reduce(mul, m)
    #print("M = ", M)
    m_i = [Decimal(M) / Decimal(item) for item in m]
    #print("M_1 = ", m_i[0])
    #print("M_2 = ", m_i[1])
    #print("M_3 = ", m_i[2])

    b = map(mod, m_i, m)
    #print("b = " ,b)

    g, k, l = map(egcd, b, m)

    g, k, l = zip(g, k, l)
    t = map(mod, k, m)
    e = map(mul, m_i, t)

    x_sum = sum(map(mul, a, e))
    x = x_sum % M
    return x if x > 0 else x + M