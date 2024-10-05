import time
import logging
import numpy as np
from math import log, gcd
import sys
from sympy import Poly, symbols
from utils import *


class NTRUdecrypt:
    """
    A class to decrypt data with the NTRU method.

    This class can also generate the private key used for decryption (which can be saved to
    an external file) and the public key used for encryption (which can also be saved to
    an external file).
    """

    def __init__(self, logger, N=503, p=3, q=256, df=61, dg=20, d=18, debug=True, check_time=True):
        """
        Initialize with some default N, p, q parameters and set debug & time checking.

        INPUTS:
        =======
        N  : Integer, order of the polynomial ring.
        p  : Integer, modulus of inverse of f polynomial for fp.
        q  : Integer, modulus of inverse of f polynomial for fq.
        df : Integer, number of coefficients 1 in polynomial f.
        dg : Integer, number of coefficients 1 in polynomial g.
        d  : Integer, number of coefficients 1 in the random polynomial (used in encryption).
        debug : Boolean, enable debug logging.
        check_time : Boolean, enable time checking for function execution.
        """
        self.N = N
        self.p = p
        self.q = q
        self.df = df
        self.dg = dg
        self.dr = d
        self.debug = debug
        self.check_time = check_time

        self.f = np.zeros((self.N,), dtype=int)
        self.fp = np.zeros((self.N,), dtype=int)
        self.fq = np.zeros((self.N,), dtype=int)
        self.g = np.zeros((self.N,), dtype=int)
        self.h = np.zeros((self.N,), dtype=int)

        self.I = np.zeros((self.N + 1,), dtype=int)
        self.I[self.N] = -1
        self.I[0] = 1

        self.M = None

        self.logger = logger

        if self.debug:
            self.logger.debug("Initialized NTRUdecrypt with parameters: N={}, p={}, q={}, df={}, dg={}, d={}".format(
                N, p, q, df, dg, d))

    @staticmethod
    def time_function(func):
        """
        Decorator to time functions and log if check_time is True.
        """
        def wrapper(self, *args, **kwargs):
            if self.check_time:
                start_time = time.time()
            result = func(self, *args, **kwargs)
            if self.check_time:
                end_time = time.time()
                self.logger.time("Function '{}' executed in {:.6f} seconds".format(func.__name__, end_time - start_time))
            return result
        return wrapper

    @time_function
    def setNpq(self, N=None, p=None, q=None, df=None, dg=None, d=None):
        """
        Set the N, p and q values and perform checks on their validity.
        """
        if N is not None:
            if not checkPrime(N):
                sys.exit("\n\nERROR: Input value of N not prime\n\n")
            else:
                if df is None and 2 * self.df > N:
                    sys.exit("\n\nERROR: Input N too small compared to default df " + str(self.df) + "\n\n")
                if dg is None and 2 * self.dg > N:
                    sys.exit("\n\nERROR: Input N too small compared to default dg " + str(self.dg) + "\n\n")
                if d is None and 2 * self.dr > N:
                    sys.exit("\n\nERROR: Input N too small compared to default dr " + str(self.dr) + "\n\n")
                self.N = N
                self.reset_polynomials()

        if (p is None and q is not None) or (p is not None and q is None):
            sys.exit("\n\nError: Can only set p and q together, not individually")
        elif (p is not None) and (q is not None):
            if ((8 * p) > q):
                sys.exit("\n\nERROR: We require 8p <= q\n\n")
            elif (gcd(p, q) != 1):
                sys.exit("\n\nERROR: Input p and q are not coprime\n\n")
            else:
                self.p = p
                self.q = q

        if df is not None:
            if 2 * df > self.N:
                sys.exit("\n\nERROR: Input df such that 2*df>N\n\n")
            else:
                self.df = df

        if dg is not None:
            if 2 * dg > self.N:
                sys.exit("\n\nERROR: Input dg such that 2*dg>N\n\n")
            else:
                self.dg = dg

        if d is not None:
            if 2 * d > self.N:
                sys.exit("\n\nERROR: Input dr such that 2*dr>N\n\n")
            else:
                self.dr = d

        if self.debug:
            self.logger.debug("setNpq called with parameters: N={}, p={}, q={}, df={}, dg={}, d={}".format(
                self.N, self.p, self.q, self.df, self.dg, self.dr))

    def reset_polynomials(self):
        """ Reset polynomial arrays after changing N """
        self.f = np.zeros((self.N,), dtype=int)
        self.fp = np.zeros((self.N,), dtype=int)
        self.fq = np.zeros((self.N,), dtype=int)
        self.g = np.zeros((self.N,), dtype=int)
        self.h = np.zeros((self.N,), dtype=int)
        self.I = np.zeros((self.N + 1,), dtype=int)
        self.I[self.N] = -1
        self.I[0] = 1

    @time_function
    def invf(self):
        """
        Invert the f polynomial with respect to input p and q values.
        Return True if inverses w.r.t. p and q exist (after setting self.fp and self.fq).
        Return False if inverse w.r.t. either/or p/q does not exist.
        """
        fp_tmp = poly_inv(self.f, self.I, self.p)
        fq_tmp = poly_inv(self.f, self.I, self.q)

        if len(fp_tmp) > 0 and len(fq_tmp) > 0:
            self.fp = np.array(fp_tmp)
            self.fq = np.array(fq_tmp)
            if len(self.fp) < self.N:
                self.fp = np.concatenate([np.zeros(self.N - len(self.fp), dtype=int), self.fp])
            if len(self.fq) < self.N:
                self.fq = np.concatenate([np.zeros(self.N - len(self.fq), dtype=int), self.fq])
            return True
        else:
            return False

    @time_function
    def genfg(self):
        """
        Randomly generate f and g for the private key and their inverses.
        """
        maxTries = 100
        self.g = genRand10(self.N, self.dg, self.dg)

        for i in range(maxTries):
            self.f = genRand10(self.N, self.df, self.df - 1)

            invStat = self.invf()
            if invStat:
                break
            elif i == maxTries - 1:
                sys.exit("Cannot generate required inverses of f")

    @time_function
    def genh(self):
        """
        Generate the public key from the class values (that must have been generated previously).
        """
        x = symbols('x')
        while True:
            self.h = Poly((Poly(self.p * self.fq, x).trunc(self.q) * Poly(self.g, x)).trunc(self.q) \
                          % Poly(self.I, x)).all_coeffs()

            if len(factor_int(self.h[-1])) == 0:
                break
            self.genfg()

    @time_function
    def writePub(self, filename="key"):
        """
        Write the public key file.
        """
        pubHead = "p ::: " + str(self.p) + "\nq ::: " + str(self.q) + "\nN ::: " + str(self.N) \
                  + "\nd ::: " + str(self.dr) + "\nh :::"
        np.savetxt(filename + ".pub", self.h, newline=" ", header=pubHead, fmt="%s")

    @time_function
    def readPub(self, filename="key.pub"):
        """
        Read a public key file.
        """
        with open(filename, "r") as f:
            self.p = int(f.readline().split(" ")[-1])
            self.q = int(f.readline().split(" ")[-1])
            self.N = int(f.readline().split(" ")[-1])
            self.dr = int(f.readline().split(" ")[-1])
            self.h = np.array(f.readline().split(" ")[3:-1], dtype=int)
        self.I = np.zeros((self.N + 1,), dtype=int)
        self.I[self.N] = -1
        self.I[0] = 1

    @time_function
    def writePriv(self, filename="key"):
        """
        Write the private key file.
        """
        privHead = "p ::: " + str(self.p) + "\nq ::: " + str(self.q) + "\nN ::: " \
                   + str(self.N) + "\ndf ::: " + str(self.df) + "\ndg ::: " + str(self.dg) \
                   + "\nd ::: " + str(self.dr) + "\nf/fp/fq/g :::"
        np.savetxt(filename + ".priv", (self.f, self.fp, self.fq, self.g), header=privHead, newline="\n", fmt="%s")

    @time_function
    def readPriv(self, filename="key.priv"):
        """
        Read a public key file.
        """
        with open(filename, "r") as f:
            self.p = int(f.readline().split(" ")[-1])
            self.q = int(f.readline().split(" ")[-1])
            self.N = int(f.readline().split(" ")[-1])
            self.df = int(f.readline().split(" ")[-1])
            self.dg = int(f.readline().split(" ")[-1])
            self.dr = int(f.readline().split(" ")[-1])
            tmp = f.readline()
            self.f = np.array(f.readline().split(" "), dtype=int)
            self.fp = np.array(f.readline().split(" "), dtype=int)
            self.fq = np.array(f.readline().split(" "), dtype=int)
            self.g = np.array(f.readline().split(" "), dtype=int)
        self.I = np.zeros((self.N + 1,), dtype=int)
        self.I[self.N] = -1
        self.I[0] = 1

    @time_function
    def genPubPriv(self, keyfileName="key"):
        """
        Generate the public and private keys from class N, p and q values.
        Also write output files for the public and private keys.
        """
        self.genfg()
        self.genh()
        self.writePub(keyfileName)
        self.writePriv(keyfileName)

    @time_function
    def decrypt(self, e):
        """
        Decrypt the message given as an input array e into the decrypted message m and return.
        """
        if len(e) > self.N:
            sys.exit("Encrypted message has degree > N")
        x = symbols('x')
        a = ((Poly(self.f, x) * Poly(e, x)) % Poly(self.I, x)).trunc(self.q)
        b = a.trunc(self.p)
        c = ((Poly(self.fp, x) * b) % Poly(self.I, x)).trunc(self.p)

        return np.array(c.all_coeffs(), dtype=int)

    @time_function
    def decryptString(self, E):
        """
        Decrypt a message encoded using the requisite public key from an encoded to a decoded string.
        """
        Me = np.fromstring(E, dtype=int, sep=' ')
        if np.mod(len(Me), self.N) != 0:
            sys.exit("\n\nERROR : Input decrypt string is not integer multiple of N\n\n")

        Marr = np.array([], dtype=int)
        for D in range(len(Me) // self.N):
            Marr = np.concatenate((Marr, padArr(self.decrypt(Me[D * self.N:(D + 1) * self.N]), self.N)))

        self.M = bit2str(Marr)

        if self.debug:
            self.logger.debug("Decrypted string: {}".format(self.M))
