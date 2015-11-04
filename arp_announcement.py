#!/usr/local/bin/python2.7
# send Address Resolution Protocol Announcement
# expect Address Resolution Protocol response and check all fields
# RFC 5227  IPv4 Address Conflict Detection
# 2.3.  Announcing an Address

import os
from addr import *
from scapy.all import *

arp=ARP(op='who-has', hwsrc=SRC_MAC, psrc=DST_IN,
    hwdst="00:00:00:00:00:00", pdst=DST_IN)
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
	# XXX we should get a request from the defender, rfc5227 2.4 (3)
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
	if a.pdst != DST_IN:
		print "PDST=%s != DST_IN" % (a.pdst)
		exit(1)
	print "arp reply"
	exit(0)

print "NO ARP REPLY"
exit(2)
