from pq_ntru.NTRUencrypt import NTRUencrypt
from pq_ntru.NTRUdecrypt import NTRUdecrypt
from pq_ntru.NTRUutil import factor_int

prog_description = """

An implementation of the NTRU encryption algorithm in python3.

Based on the original NTRU paper by Hoffstein, Pipher and Silverman [1].

"""

prog_epilog = """

References:
[1] Hoffstein J, Pipher J, Silverman JH. NTRU: A Ring-Based Public Key Cryptosystem. In: International Algorithmic Number Theory Symposium. Springer; 1998. p. 267--288.

"""


def generate_keys(name="key", mode="highest", skip_check=False, debug=False):
    if mode not in ["moderate", "high", "highest"]:
        raise ValueError("Input string must be 'moderate', 'high', or 'highest'")
    """
    :param name: name of file output
    :param mode: moderate, high, highest
    :return:
    """
    if debug:
        print("[i] Starting generation...")
        i = 0
        while True:
            i += 1
            print(f"[i] Round {i} of key generation started")
            N1 = NTRUdecrypt()
            print("[i] Initialised function.")
            print("Choosing mode:", mode)
            if mode == "moderate":
                N1.setNpq(N=107, p=3, q=64, df=15, dg=12, d=5)
            elif mode == "high":
                N1.setNpq(N=167, p=3, q=128, df=61, dg=20, d=18)
            elif mode == "highest":
                N1.setNpq(N=503, p=3, q=256, df=216, dg=72, d=55)

            print("[i] Generating keys")
            N1.genPubPriv(name)
            print("[i] Created.")


            if skip_check:
                print("[-] Skipping security check")
                break

            print("[i] Getting factors:")
            factors = factor_int(N1.h[-1])
            print("[i] Factors:", factors)
            possible_keys = 2 ** N1.df * (N1.df + 1) ** 2 * 2 ** N1.dg * (N1.dg + 1) * 2 ** N1.dr * (N1.dr + 1)
            print("[i] Checking if key is long enough.")
            if len(factors) == 0 and possible_keys > 2**80:  # see 'security_check.py' for more information
                print("Security passed")
                break
            else:
                print("[-] Security check not passed. Trying again.")
        print("[+] Done.")
    else:
        while True:
            N1 = NTRUdecrypt()
            if mode == "moderate":
                N1.setNpq(N=107, p=3, q=64, df=15, dg=12, d=5)
            elif mode == "high":
                N1.setNpq(N=167, p=3, q=128, df=61, dg=20, d=18)
            elif mode == "highest":
                N1.setNpq(N=503, p=3, q=256, df=216, dg=72, d=55)
            N1.genPubPriv(name)

            if skip_check:
                break

            factors = factor_int(N1.h[-1])
            possible_keys = 2 ** N1.df * (N1.df + 1) ** 2 * 2 ** N1.dg * (N1.dg + 1) * 2 ** N1.dr * (N1.dr + 1)
            if len(factors) == 0 and possible_keys > 2**80:  # see 'security_check.py' for more information
                break


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
