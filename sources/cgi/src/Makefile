##############################################################################
##
## $Id: Makefile,v 1.1 1998/06/16 21:23:04 chris Exp $
## Makefile for the CGI
##
##############################################################################
CC = gcc
LD = gcc -s

# The user the virtual domains package runs under
VPOPUSER=vpopmail

# The group the virtual domains package runs under
VPOPGRP=vchkpw

# The top level of the CGI
CGIROOT=/home/chris/sys/qmail/vchkpw/devel/cgi

# How long should cookies be valid for? (minutes)
TIMEOUT=20

##############################################################################
##
## No user servicable parts below this point
##
##############################################################################

DEFS=-DVPOPUSER=\"$(VPOPUSER)\" -DCGIROOT=\"$(CGIROOT)\" -DTIMEOUT=$(TIMEOUT)
OPTS=-Wall -O2

all: vchkexpire vchkaccess

vchkaccess: vchkaccess.o safestring.o
	$(LD) vchkaccess.o safestring.o -o vchkaccess

vchkexpire: vchkexpire.o safestring.o
	$(LD) vchkexpire.o safestring.o -o vchkexpire

vchkaccess.o: vchkaccess.c safestring.h
	$(CC) -c vchkaccess.c -o vchkaccess.o $(DEFS) $(OPTS)

vchkexpire.o: vchkexpire.c safestring.h
	$(CC) -c vchkexpire.c -o vchkexpire.o $(DEFS) $(OPTS)

safestring.o: safestring.c
	$(CC) -c safestring.c -o safestring.o $(OPTS)

install:
	cp vchkaccess vchkexpire ..
	chown $(VPOPUSER).$(VPOPGRP) ../vchkaccess ../vchkexpire
	chmod 6711 ../vchkaccess
	chmod 0700 ../vchkexpire

clean:
	rm -f vchkaccess vchkexpire
	rm -f vchkaccess.o vchkexpire.o
	rm -f safestring.o

distclean: clean
	rm -f ../vchkaccess
	rm -f ../vchkexpire
