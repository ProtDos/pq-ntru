from pq_ntru.NTRUdecrypt import NTRUdecrypt
from colorama import Fore


def factor_int(n):
    """
    Return a dictionary of the prime factorization of n.
    The keys of the dictionary are the prime factors of n, and the values are their
    multiplicities (i.e. the power to which each prime factor appears in the factorization).
    """
    factors_ = {}
    d = 2
    while n > 1:
        while n % d == 0:
            if d in factors_:
                factors_[d] += 1
            else:
                factors_[d] = 1
            n //= d
        d += 1
        if d*d > n:
            if n > 1:
                if n in factors_:
                    factors_[n] += 1
                else:
                    factors_[n] = 1
            break
    return factors_


ntru = NTRUdecrypt()
print(Fore.BLUE + "Generating keys..." + Fore.RESET)
ntru.genPubPriv()

# What is a factorization attack?
"""
In cryptography, factorization attack is a type of attack that exploits the fact that some cryptographic algorithms 
rely on the difficulty of factoring large numbers into their prime factors. The most common example is the RSA algorithm, 
which is widely used in many applications such as encryption, digital signatures, and key exchange.

The basic idea behind the factorization attack is to factorize the modulus (the product of two large prime 
numbers used in the RSA algorithm) and obtain the private key. Once the private key is obtained, an attacker can 
easily decrypt the encrypted messages or forge digital signatures.

The most common method used in factorization attacks is the General Number Field Sieve (GNFS), which is an 
algorithm that is specifically designed to factorize large numbers. The GNFS algorithm works by first finding a 
smooth number (a number that can be factored into small prime factors) that is close to the square root of the 
modulus. Then, it constructs a matrix using the smooth numbers and uses linear algebra techniques to solve for 
the factors of the modulus.

To prevent factorization attacks, it is important to use sufficiently large prime numbers in the RSA algorithm. 
The size of the modulus is directly related to the security of the system, and larger modulus sizes require more 
computational resources to factorize. Additionally, there are other cryptographic algorithms that are not vulnerable 
to factorization attacks, such as elliptic curve cryptography.
"""

factors = factor_int(ntru.h[-1])
print(Fore.BLUE + f"Result of factor_int(): {factors}" + Fore.RESET)

possible_keys = 2 ** ntru.df * (ntru.df + 1) ** 2 * 2 ** ntru.dg * (ntru.dg + 1) * 2 ** ntru.dr * (ntru.dr + 1)
# => 972_133_357_001_824_106_960_988_760_732_336_128 (36 digits) > 1_208_925_819_614_629_174_706_176 (2^80) (25 digits)


# Why 2^80?
""""
A key length of 2^80 is often used as a benchmark for security against meet-in-the-middle attacks 
because it is considered to be infeasible to mount such an attack against a system using a key of that length.

The reason for this is that a meet-in-the-middle attack requires precomputing a large number 
of possible intermediate results, which increases exponentially with the key length. 
For example, if the key length is 80 bits, there are 2^80 possible keys. If the attacker needs to precompute intermediate 
results for each key, this would require 2^80 computations, which is considered to be impractical with current technology.

In general, the length of a key needed to prevent meet-in-the-middle attacks depends on 
the specific cryptographic algorithm used and the specific implementation. 
However, a key length of 2^80 is often used as a conservative benchmark to ensure that a system is secure against this type of attack.
"""


# What is a meet-in-the-middle attack?
"""
In cryptography, the meet-in-the-middle attack is a type of attack that exploits the fact that some cryptographic 
algorithms are vulnerable to being attacked from both ends simultaneously. The attack is based on the principle of 
finding a middle point where the two attacks can meet and merge together to reveal the secret key or plaintext.

The meet-in-the-middle attack is most commonly used against block ciphers that use a fixed-length block 
of plaintext and a fixed-length key to produce a fixed-length ciphertext. The attack is based on the 
idea of breaking the encryption process into two parts: an encryption function that operates on the plaintext 
using the first half of the key, and a decryption function that operates on the ciphertext using the second half of the key.

The attack works by precomputing all possible combinations of the encryption function using a reduced 
key length, and then storing the results in a lookup table. Then, the attacker performs a similar 
computation using the decryption function, but with a different reduced key length. The attacker 
then compares the results of both computations to find matching pairs. These matching pairs represent 
possible combinations of the full key.

Once the matching pairs are found, the attacker can then try each possible combination of the full 
key to decrypt the ciphertext and recover the plaintext.

To prevent meet-in-the-middle attacks, it is important to use longer key lengths and avoid using weak keys. 
Additionally, using cryptographic algorithms that are not vulnerable to the attack, 
such as stream ciphers, can also prevent this type of attack.
"""

print(Fore.BLUE + f"Number of possible keys: {possible_keys}" + Fore.RESET)
if possible_keys > 2**80:
    print(Fore.GREEN + "System is secure against meet-in-the-middle attack" + Fore.RESET)
else:
    print(Fore.RED + "System is vulnerable to meet-in-the-middle attack" + Fore.RESET)

if len(factors) > 1:
    print(Fore.RED + "Public key is vulnerable to integer factorization attack" + Fore.RESET)
else:
    print(Fore.GREEN + "Public key is secure against integer factorization attack" + Fore.RESET)
