import pq_ntru
from pq_ntru.NTRUdecrypt import NTRUdecrypt

def factorint(n):
    """
    Return a dictionary of the prime factorization of n.

    The keys of the dictionary are the prime factors of n, and the values are their
    multiplicities (i.e. the power to which each prime factor appears in the factorization).
    """
    factors = {}
    d = 2
    while n > 1:
        while n % d == 0:
            if d in factors:
                factors[d] += 1
            else:
                factors[d] = 1
            n //= d
        d += 1
        if d*d > n:
            if n > 1:
                if n in factors:
                    factors[n] += 1
                else:
                    factors[n] = 1
            break
    return factors


ntru = NTRUdecrypt()
ntru.genPubPriv()
# print(ntru.h)

factors = factorint(ntru.h[-1])
print(f"Result of factorint(): {factors}")

if len(factors) > 1:
    print("Public key is vulnerable to integer factorization attack")
else:
    print("Public key is secure against integer factorization attack")

###
possible_keys = 2**(ntru.df)*(ntru.df+1)**2*2**(ntru.dg)*(ntru.dg+1)*2**(ntru.dr)*(ntru.dr+1)

print(f"Number of possible keys: {possible_keys}")
if possible_keys > 2**80:
    print("System is secure against meet-in-the-middle attack")
else:
    print("System is vulnerable to meet-in-the-middle attack")
