#!/usr/local/bin/python2.7
# send Address Resolution Protocol Request 
# expect Address Resolution Protocol response and check all fields
# RFC 826  An Ethernet Address Resolution Protocol
# Packet Generation

import os
from addr import *
from scapy.all import *

arp=ARP(op='who-has', hwsrc=SRC_MAC, psrc=SRC_OUT,
    hwdst="ff:ff:ff:ff:ff:ff", pdst=DST_IN)
eth=Ether(src=SRC_MAC, dst="ff:ff:ff:ff:ff:ff")/arp

e=srp1(eth, iface=SRC_IF, timeout=2)

if e and e.type == ETH_P_ARP:
	a=e.payload
	if a.hwtype != ARPHDR_ETHER:
		print "HWTYPE=%#0.4x != ARPHDR_ETHER" % (a.hwtype)
		exit(1)
	if a.ptype != ETH_P_IP:
		print "PTYPE=%#0.4x != ETH_P_IP" % (a.ptype)
		exit(1)
	if a.hwlen != 6:
		print "HWLEN=%d != 6" % (a.hwlen)
		exit(1)
	if a.plen != 4:
		print "PLEN=%d != 4" % (a.plen)
		exit(1)
	if a.op != 2:
		print "OP=%s != is-at" % (a.op)
		exit(1)
	if a.hwsrc != DST_MAC:
		print "HWSRC=%s != DST_MAC" % (a.hwsrc)
		exit(1)
	if a.psrc != DST_IN:
		print "PSRC=%s != DST_IN" % (a.psrc)
		exit(1)
	if a.hwdst != SRC_MAC:
		print "HWDST=%s != SRC_MAC" % (a.hwdst)
		exit(1)
	if a.pdst != SRC_OUT:
		print "PDST=%s != SRC_OUT" % (a.pdst)
		exit(1)
	exit(0)

print "NO ARP REPLY"
exit(2)
