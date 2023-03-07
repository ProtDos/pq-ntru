from pq_ntru.NTRUencrypt import NTRUencrypt
from pq_ntru.NTRUdecrypt import NTRUdecrypt

prog_description = """

An implementation of the NTRU encryption algorithm in python3.

Based on the original NTRU paper by Hoffstein, Pipher and Silverman [1].

"""

prog_epilog = """

References:
[1] Hoffstein J, Pipher J, Silverman JH. NTRU: A Ring-Based Public Key Cryptosystem. In: International Algorithmic Number Theory Symposium. Springer; 1998. p. 267--288.

"""


def generate_keys(name="key", mode="highest"):
    if mode not in ["moderate", "high", "highest"]:
        raise ValueError("Input string must be 'moderate', 'high', or 'highest'")
    """
    :param name: name of file output
    :param mode: moderate, high, highest
    :return:
    """
    N1 = NTRUdecrypt()
    if mode == "moderate":
        N1.setNpq(N=107, p=3, q=64, df=15, dg=12, d=5)
    elif mode == "high":
        N1.setNpq(N=167, p=3, q=128, df=61, dg=20, d=18)
    elif mode == "highest":
        N1.setNpq(N=503, p=3, q=256, df=216, dg=72, d=55)
    N1.genPubPriv(name)


def encrypt(name: str, string: str):
    """
    :param name: name of key file
    :param string: message to encrypt as a string
    :return:
    """
    E = NTRUencrypt()
    E.readPub(name + ".pub")
    to_encrypt = string
    E.encryptString(to_encrypt)

    return E.Me


def decrypt(name: str, cipher: str):
    """
    :param name: name of key file
    :param cipher: encrypted message
    :return:
    """
    D = NTRUdecrypt()
    D.readPriv(name + ".priv")
    to_decrypt = cipher
    D.decryptString(to_decrypt)

    return D.M
