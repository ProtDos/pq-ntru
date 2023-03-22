import pq_ntru
from pq_ntru.NTRUdecrypt import *
import time

a = time.time()

N1 = NTRUdecrypt()

N1.setNpq(N=1499, p=3, q=2048, df=79, dg=499, d=55)
N1.genPubPriv()

print(time.time()-a)
# this takes quite a long time. It's time to optimise it...
