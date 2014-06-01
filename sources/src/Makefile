###############################################################################
##
## $Id: Makefile,v 1.4 1999/06/05 13:04:40 chris Exp $
## Makefile for vchkpw
##
## Chris Johnson, July 1998
## Email: sixie@nccnet.co.uk
##
##    This program is free software; you can redistribute it and/or modify
##    it under the terms of the GNU General Public License as published by
##    the Free Software Foundation; either version 2 of the License, or
##    (at your option) any later version.
##
##    This program is distributed in the hope that it will be useful,
##    but WITHOUT ANY WARRANTY; without even the implied warranty of
##    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
##    GNU General Public License for more details.
##
##    You should have received a copy of the GNU General Public License
##    along with this program; if not, write to the Free Software
##    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
##
###############################################################################
SHELL=/bin/sh

# To use shadow passwords under Linux, uncomment the next two lines.
# To use shadow passwords under Solaris, uncomment the SHADOWOPTS line.
SHADOWLIBS=-lshadow
SHADOWOPTS=-DUSESHADOW

# If you want to use a different pop user name other than vpopmail, uncomment
# and change the line below. You'll also need to modify several scripts. Unless
# you have a reason to change this, don't bother - it may be more hassle than
# its worth.
# POPACCT=-DPOPUSER=\"vpopmail\"

# Who is the mail admin? Change the line below accordingly...
ADMIN=-DADMIN=\"postmaster@misconfigured.host\"

# Do you want to use APOP? If so, define this to be the full pathname of the
# file containing the APOP secrets. Read the README.APOP file for more
# information. 
APOP=-DAPOP=\"/etc/apop-secrets\"
# You will also need to uncomment this line
MDLIB=md5.o

# You need at least one authentication meachanism. Defining this will make
# vchkpw use standard user/password authentication. You can define both this
# and APOP if you want both mechanisms available.
PASSWD=-DPASSWD

# Do you want to disable syslog messages? Comment the line below if you do.
# If so why? If something keels over in the system, this would be the first
# place to look...Logging is done at mail.notice.
SYSLOG=-DSYSLOG

# Libraries...if it complains about a missing crypt() function, try compiling
# with the option below. If you need any other libs, also tag them onto this.
# LIBS=-lcrypt
LIBS=

# Do you want to be able to use CDB databases? CDB is a database format so
# that quick lookups can be achieved. The CDB support in vchkpw creates a 
# database of the password file. Then look at the CDB defines below.
HAVECDB=-Dcdb

# Where does your CDB package hide out? By default, it expects to find the
# CDB source in a directory called 'cdb' in the vchkpw source tree. This can
# be a sym-link to the actual location, or you can just change this line...
CDB=cdb
CDBINC=-I$(CDB)
CDBLIBS=$(CDB)/libcdb.a $(CDB)/libcdbmake.a

# Do you want debug? This can break some clients as the debug output is verbose
# and has output POP clients don't expect. Use with telnet for best results :)
DEBUG=-DDEBUG

# Any other C flags you want to use, append on here.
OPTS=-Wall -Wshadow -O2 $(POPACCT) $(CDBINC) $(DEBUG)

# Top level of the virtual domains package?
INSTDIR=/home/popusers

# Compiler and linker (leave unless you don't have gcc)
CC=gcc $(CFLAGS) $(OPTS)
LD=gcc -s

###############################################################################
##
## No user servicable parts below
##
###############################################################################
VERSION	= 3.2.0

LLIST	= $(LIBS) $(SHADOWLIBS)
OLIST	= libvchk.a $(CDBLIBS)
LIBLIST	= $(LLIST) $(OLIST)

PW	= $(APOP) $(PASSWD)

OBJS	= vchkpw.o vmkpasswd.o vdelivermail.o vmkcdb.o valias.o \
		safestring.o common.o md5.o libvchk.a
		
PRGS	= vchkpw vmkpasswd vdelivermail vmkcdb

SCRT	= vadduser vdeluser vaddomain vdeldomain vpasswd fixvpasswd splitmboxes

all: $(PRGS)

vchkpw: vchkpw.o $(LIBLIST)
	$(LD) -o vchkpw vchkpw.o $(LIBLIST)

vdelivermail: vdelivermail.o $(LIBLIST)
	$(LD) -o vdelivermail vdelivermail.o $(LIBLIST)

vmkpasswd: vmkpasswd.o $(LIBLIST)
	$(LD) -o vmkpasswd vmkpasswd.o $(LIBLIST)

vmkcdb: vmkcdb.o $(LIBLIST)
	$(LD) -o vmkcdb vmkcdb.o $(LIBLIST)

libvchk.a: md5.o safestring.o common.o valias.o
	ar cr libvchk.a md5.o safestring.o common.o valias.o
	ranlib libvchk.a

valias.o: valias.c common.h safestring.h
	$(CC) -c valias.c $(SYSLOG)

vchkpw.o: vchkpw.c common.h safestring.h
	$(CC) -c vchkpw.c $(SHADOWOPTS) $(FGETPWENT) $(PW) $(SYSLOG)

vmkpasswd.o: vmkpasswd.c safestring.h
	$(CC) -c vmkpasswd.c

vdelivermail.o: vdelivermail.c common.h safestring.h
	$(CC) -c vdelivermail.c $(FGETPWENT) $(ADMIN)

vmkcdb.o: vmkcdb.c common.h safestring.h
	$(CC) -c vmkcdb.c -o vmkcdb.o

common.o: common.c common.h
	$(CC) -c common.c -o common.o $(SYSLOG)

md5.o: md5.c md5.h
	$(CC) -c md5.c -o md5.o

safestring.o: safestring.c
	$(CC) -c safestring.c -o safestring.o

clean:
	rm -f $(OBJS)
	rm -f $(PRGS)

copy:
	cp $(PRGS) ../bin
	chmod 700 ../bin/*

install: copy
	for i in $(PRGS); do cp ../bin/$$i $(INSTDIR)/bin; done
	for i in $(SCRT); do cp ../bin/$$i $(INSTDIR)/bin; done
	chmod 711 $(INSTDIR)/bin/*

distclean: clean
	cd ../bin; rm -f $(PRGS)

archive:
	cd .. ; tar cvf vchkpw-$(VERSION)-local.tar .
