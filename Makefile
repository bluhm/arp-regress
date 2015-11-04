#	$OpenBSD$

# The following ports must be installed:
#
# python-2.7          interpreted object-oriented programming language
# py-libdnet          python interface to libdnet
# scapy               powerful interactive packet manipulation in python

# Check wether all required python packages are installed.  If some
# are missing print a warning and skip the tests, but do not fail.
PYTHON_IMPORT != python2.7 -c 'from scapy.all import *' 2>&1 || true
.if ! empty(PYTHON_IMPORT)
regress:
	@echo '${PYTHON_IMPORT}'
	@echo install python and the scapy module for additional tests
.endif

# This test needs a manual setup of two machines
# Set up machines: SRC DST
# SRC is the machine where this makefile is running.
# DST is running OpenBSD with ARP to test the Address Resolution Protocol.
#
# +---+   1   +---+
# |SRC| ----> |DST|
# +---+       +---+
#     out    in

# Configure Addresses on the machines.
# Adapt interface and addresse variables to your local setup.
#
SRC_IF ?=
SRC_MAC ?=
DST_MAC ?=
DST_SSH ?=

SRC_OUT ?=
DST_IN ?=

.if empty (SRC_IF) || empty (SRC_MAC) || empty (DST_MAC) || \
    empty (DST_SSH) || empty (SRC_OUT) || empty (DST_IN)
regress:
	@echo this tests needs a remote machine to operate on
	@echo SRC_IF SRC_MAC DST_MAC DST_SSH SRC_OUT DST_IN are empty
	@echo fill out these variables for additional tests
.endif

depend: addr.py

# Create python include file containing the addresses.
addr.py: Makefile
	rm -f $@ $@.tmp
	echo 'SRC_IF = "${SRC_IF}"' >>$@.tmp
	echo 'SRC_MAC = "${SRC_MAC}"' >>$@.tmp
	echo 'DST_MAC = "${DST_MAC}"' >>$@.tmp
.for var in SRC_OUT DST_IN
	echo '${var} = "${${var}}"' >>$@.tmp
.endfor
	mv $@.tmp $@

# Set variables so that make runs with and without obj directory.
# Only do that if necessary to keep visible output short.
.if ${.CURDIR} == ${.OBJDIR}
PYTHON =	python2.7 ./
.else
PYTHON =	PYTHONPATH=${.OBJDIR} python2.7 ${.CURDIR}/
.endif

# Clear arp cache and ping all addresses.  This ensures that
# the ip addresses are configured and all routing table are set up
# to allow bidirectional packet flow.
TARGETS +=	ping
run-regress-ping:
	@echo '\n======== $@ ========'
	${SUDO} arp -da
.for ip in SRC_OUT DST_IN
	@echo Check ping ${ip}:
	ping -n -c 1 ${${ip}}
.endfor

TARGETS +=	arp-request
run-regress-arp-request:
	@echo '\n======== $@ ========'
	@echo Send ARP Request for DST_IN ${DST_IN} and set SRC_OUT ${SRC_OUT}
	ssh -t ${REMOTE_SSH} ${SUDO} arp -d ${SRC_OUT}
	${SUDO} ${PYTHON}arp_request.py
	ssh -t ${REMOTE_SSH} ${SUDO} arp -an >arp.log
	grep '^${SRC_OUT} .* ${SRC_MAC} ' arp.log

TARGETS +=	arp-multicast
run-regress-arp-multicast:
	@echo '\n======== $@ ========'
	@echo Send ARP from SRC_OUT ${SRC_OUT} with multicast ethernet address
	ssh -t ${DST_SSH} logger -t "arp-regress[$$$$]" $@
	ssh -t ${REMOTE_SSH} ${SUDO} arp -s ${SRC_OUT} ${SRC_MAC} temp
	scp ${DST_SSH}:/var/log/messages old.log
	${SUDO} ${PYTHON}arp_multicast.py
	scp ${DST_SSH}:/var/log/messages new.log
	ssh -t ${REMOTE_SSH} ${SUDO} arp -an >arp.log
	ssh -t ${REMOTE_SSH} ${SUDO} arp -d ${SRC_OUT}
	diff old.log new.log | grep '^> ' >diff.log
	grep 'bsd: arp info overwritten for ${SRC_OUT} by 33:33:33:33:33:33' diff.log
	grep '^${SRC_OUT} .* ${SRC_MAC} ' arp.log

TARGETS +=	arp-probe
run-regress-arp-probe:
	@echo '\n======== $@ ========'
	@echo Send ARP Probe for ${DST_IN} and expect reply from ${DST_MAC}
	${SUDO} ${PYTHON}arp_probe.py

TARGETS +=	arp-broadcast
run-regress-arp-broadcast:
	@echo '\n======== $@ ========'
	@echo Send ARP Request with ethernet broadcast sender hardware address
	ssh -t ${DST_SSH} logger -t "arp-regress[$$$$]" $@
	scp ${DST_SSH}:/var/log/messages old.log
	${SUDO} ${PYTHON}arp_broadcast.py
	scp ${DST_SSH}:/var/log/messages new.log
	diff old.log new.log | grep '^> ' >diff.log
	grep 'bsd: arp: ether address is broadcast for IP address ${SRC_OUT}' diff.log

TARGETS +=	arp-announcement
run-regress-arp-announcement:
	@echo '\n======== $@ ========'
	@echo Send ARP Announcement for DST_IN ${DST_IN} 
	ssh -t ${DST_SSH} logger -t "arp-regress[$$$$]" $@
	scp ${DST_SSH}:/var/log/messages old.log
	${SUDO} ${PYTHON}arp_announcement.py
	scp ${DST_SSH}:/var/log/messages new.log
	diff old.log new.log | grep '^> ' >diff.log
	grep 'bsd: duplicate IP address ${DST_IN} sent from ethernet address ${SRC_MAC}' diff.log

TARGETS +=	arp-gratuitous
run-regress-arp-gratuitous:
	@echo '\n======== $@ ========'
	@echo Send Gratuitous ARP for DST_IN ${DST_IN} 
	ssh -t ${DST_SSH} logger -t "arp-regress[$$$$]" $@
	scp ${DST_SSH}:/var/log/messages old.log
	${SUDO} ${PYTHON}arp_gratuitous.py
	scp ${DST_SSH}:/var/log/messages new.log
	diff old.log new.log | grep '^> ' >diff.log
	grep 'bsd: duplicate IP address ${DST_IN} sent from ethernet address ${SRC_MAC}' diff.log

REGRESS_TARGETS =	${TARGETS:S/^/run-regress-/}

CLEANFILES +=		addr.py *.pyc *.log

.include <bsd.regress.mk>
