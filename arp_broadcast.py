#!/usr/local/bin/python2.7
# send Address Resolution Protocol Request to Ethernet broadcast address
# expect no answer

import os
from addr import *
from scapy.all import *

arp=ARP(op='who-has', hwsrc="ff:ff:ff:ff:ff:ff", psrc=SRC_OUT,
    hwdst="ff:ff:ff:ff:ff:ff", pdst=DST_IN)
eth=Ether(src=SRC_MAC, dst="ff:ff:ff:ff:ff:ff")/arp

e=srp1(eth, iface=SRC_IF, timeout=2)

if e and e.type == ETH_P_ARP:
	a=e.payload
	a.show()
	print "ARP REPLY"
	exit(1)

print "no arp reply"
exit(0)
