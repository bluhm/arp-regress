#!/usr/local/bin/python2.7
# send Gratuitous Address Resolution Protocol Reply
# expect no answer
# RFC 2002  IP Mobility Support
# 4.6. ARP, Proxy ARP, and Gratuitous ARP

import os
from addr import *
from scapy.all import *

arp=ARP(op='is-at', hwsrc=SRC_MAC, psrc=DST_IN,
    hwdst=SRC_MAC, pdst=DST_IN)
eth=Ether(src=SRC_MAC, dst="ff:ff:ff:ff:ff:ff")/arp

e=srp1(eth, iface=SRC_IF, timeout=2)

if e and e.type == ETH_P_ARP:
	a=e.payload
	a.show()
	print "ARP REPLY"
	exit(1)

print "no arp reply"
exit(0)
