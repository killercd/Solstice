#!/usr/bin/python
 

from scapy.all import *
import sys
import fire
 
Timeout=2
 
def arping(ip, timeout=2):
    answered,unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip),timeout=timeout,verbose=False)

    if len(answered) > 0:
        import pdb; pdb.set_trace()
        print(answered[0][0].getlayer(ARP).pdst, "is up")
    elif len(unanswered) > 0:
        print(unanswered[0].getlayer(ARP).pdst, " is down")
if __name__ == "__main__":
    fire.Fire(arping)
    
