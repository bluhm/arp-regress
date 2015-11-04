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
# Set up machines: LOCAL REMOTE
# LOCAL is the machine where this makefile is running.
# REMOTE is running OpenBSD with ARP to test the Address Resolution Protocol.
# FAKE is an non existing machine, its IP is used in the tests.

# Configure Addresses on the machines.
# Adapt interface and addresse variables to your local setup.
#
LOCAL_IF ?=
LOCAL_MAC ?=
REMOTE_MAC ?=
REMOTE_SSH ?=

LOCAL_ADDR ?=
REMOTE_ADDR ?=

.if empty (LOCAL_IF) || empty (LOCAL_MAC) || empty (REMOTE_MAC) || \
    empty (REMOTE_SSH) || empty (LOCAL_ADDR) || empty (REMOTE_ADDR) || \
    empty (FAKE_ADDR)
regress:
	@echo this tests needs a remote machine to operate on
	@echo LOCAL_IF LOCAL_MAC REMOTE_MAC REMOTE_SSH
	@echo LOCAL_ADDR REMOTE_ADDR FAKE_ADDR are empty
	@echo fill out these variables for additional tests
.endif

depend: addr.py

# Create python include file containing the addresses.
addr.py: Makefile
	rm -f $@ $@.tmp
	echo 'LOCAL_IF = "${LOCAL_IF}"' >>$@.tmp
	echo 'LOCAL_MAC = "${LOCAL_MAC}"' >>$@.tmp
	echo 'REMOTE_MAC = "${REMOTE_MAC}"' >>$@.tmp
.for var in LOCAL_ADDR REMOTE_ADDR FAKE_ADDR
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
.for ip in LOCAL_ADDR REMOTE_ADDR
	@echo Check ping ${ip}
	ping -n -c 1 ${${ip}}
.endfor

TARGETS +=	arp-request
run-regress-arp-request: addr.py
	@echo '\n======== $@ ========'
	@echo Send ARP Request for REMOTE_ADDR ${REMOTE_ADDR} and set LOCAL_ADDR ${LOCAL_ADDR}
	ssh -t ${REMOTE_SSH} ${SUDO} arp -d ${LOCAL_ADDR}
	${SUDO} ${PYTHON}arp_request.py
	ssh -t ${REMOTE_SSH} ${SUDO} arp -an >arp.log
	grep '^${LOCAL_ADDR} .* ${LOCAL_MAC} ' arp.log

TARGETS +=	arp-multicast
run-regress-arp-multicast: addr.py
	@echo '\n======== $@ ========'
	@echo Send ARP from LOCAL_ADDR ${LOCAL_ADDR} with multicast ethernet address
	ssh -t ${REMOTE_SSH} logger -t "arp-regress[$$$$]" $@
	ssh -t ${REMOTE_SSH} ${SUDO} arp -s ${LOCAL_ADDR} ${LOCAL_MAC} temp
	scp ${REMOTE_SSH}:/var/log/messages old.log
	${SUDO} ${PYTHON}arp_multicast.py
	scp ${REMOTE_SSH}:/var/log/messages new.log
	ssh -t ${REMOTE_SSH} ${SUDO} arp -an >arp.log
	ssh -t ${REMOTE_SSH} ${SUDO} arp -d ${LOCAL_ADDR}
	diff old.log new.log | grep '^> ' >diff.log
	grep 'bsd: arp info overwritten for ${LOCAL_ADDR} by 33:33:33:33:33:33' diff.log
	grep '^${LOCAL_ADDR} .* ${LOCAL_MAC} ' arp.log

TARGETS +=	arp-probe
run-regress-arp-probe: addr.py
	@echo '\n======== $@ ========'
	@echo Send ARP Probe for ${REMOTE_ADDR} and expect reply from ${REMOTE_MAC}
	${SUDO} ${PYTHON}arp_probe.py

TARGETS +=	arp-broadcast
run-regress-arp-broadcast: addr.py
	@echo '\n======== $@ ========'
	@echo Send ARP Request with ethernet broadcast sender hardware address
	ssh -t ${REMOTE_SSH} logger -t "arp-regress[$$$$]" $@
	scp ${REMOTE_SSH}:/var/log/messages old.log
	${SUDO} ${PYTHON}arp_broadcast.py
	scp ${REMOTE_SSH}:/var/log/messages new.log
	diff old.log new.log | grep '^> ' >diff.log
	grep 'bsd: arp: ether address is broadcast for IP address ${LOCAL_ADDR}' diff.log

TARGETS +=	arp-announcement
run-regress-arp-announcement: addr.py
	@echo '\n======== $@ ========'
	@echo Send ARP Announcement for REMOTE_ADDR ${REMOTE_ADDR}
	ssh -t ${REMOTE_SSH} logger -t "arp-regress[$$$$]" $@
	scp ${REMOTE_SSH}:/var/log/messages old.log
	${SUDO} ${PYTHON}arp_announcement.py
	scp ${REMOTE_SSH}:/var/log/messages new.log
	ssh -t ${REMOTE_SSH} ${SUDO} arp -an >arp.log
	diff old.log new.log | grep '^> ' >diff.log
	grep 'bsd: duplicate IP address ${REMOTE_ADDR} sent from ethernet address ${LOCAL_MAC}' diff.log
	grep '^${REMOTE_ADDR} .* ${REMOTE_MAC} .* permanent ' arp.log

TARGETS +=	arp-gratuitous
run-regress-arp-gratuitous: addr.py
	@echo '\n======== $@ ========'
	@echo Send Gratuitous ARP for REMOTE_ADDR ${REMOTE_ADDR}
	ssh -t ${REMOTE_SSH} logger -t "arp-regress[$$$$]" $@
	scp ${REMOTE_SSH}:/var/log/messages old.log
	${SUDO} ${PYTHON}arp_gratuitous.py
	scp ${REMOTE_SSH}:/var/log/messages new.log
	ssh -t ${REMOTE_SSH} ${SUDO} arp -an >arp.log
	diff old.log new.log | grep '^> ' >diff.log
	grep 'bsd: duplicate IP address ${REMOTE_ADDR} sent from ethernet address ${LOCAL_MAC}' diff.log
	grep '^${REMOTE_ADDR} .* ${REMOTE_MAC} .* permanent ' arp.log

TARGETS +=	arp-permanent
run-regress-arp-permanent: addr.py
	@echo '\n======== $@ ========'
	@echo Send ARP Request to change permanent fake address
	ssh -t ${REMOTE_SSH} logger -t "arp-regress[$$$$]" $@
	ssh -t ${REMOTE_SSH} ${SUDO} arp -s ${FAKE_ADDR} 12:23:56:78:9a:bc permanent
	scp ${REMOTE_SSH}:/var/log/messages old.log
	${SUDO} ${PYTHON}arp_fake.py
	scp ${REMOTE_SSH}:/var/log/messages new.log
	ssh -t ${REMOTE_SSH} ${SUDO} arp -an >arp.log
	ssh -t ${REMOTE_SSH} ${SUDO} arp -d ${FAKE_ADDR}
	diff old.log new.log | grep '^> ' >diff.log
	grep 'bsd: arp: attempt to overwrite permanent entry for ${FAKE_ADDR} by ${LOCAL_MAC}' diff.log
	grep '^${FAKE_ADDR} .* 12:23:56:78:9a:bc .* permanent' arp.log

REGRESS_TARGETS =	${TARGETS:S/^/run-regress-/}

CLEANFILES +=		addr.py *.pyc *.log

.include <bsd.regress.mk>
