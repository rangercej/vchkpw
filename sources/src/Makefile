#
# $Id: Makefile,v 1.2 1998/06/17 23:10:09 chris Exp $
#
# To use shadow passwords under Linux, uncomment the next two lines.
# To use shadow passwords under Solaris, uncomment the SHADOWOPTS line.
SHADOWLIBS=-lshadow
SHADOWOPTS=-DPW_SHADOW

# If you want to use a different pop user name other than vpopmail, uncomment
# and change the line below. You'll also need to modify several scripts.
# POPACCT=-DPOPUSER=\"vpopmail\"

# Who is the mail admin? Change the line below accordingly...
ADMIN=-DADMIN=\"sixie@nccnet.co.uk\"

# Does your system support fgetpwent (SysV based systems probably will, BSD
# based systems may not. I know FreeBSD does not have this function). If you
# need external support, uncomment these two lines.
# FGETPWENT=-DNEED_FGETPW
# FGETPWLIB=fgetpwent.o

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

# Do you want sysloging abilities? LOG_FAIL should be defined to log failed
# login attempts, LOG_OKAY should be defined to you want to log successful
# logins. LOG_FAIL logs at mail.notice, LOG_OKAY logs at mail.info.
LOG_FAIL=-DLOG_FAIL
LOG_OKAY=-DLOG_OKAY

# Libraries...if it complains about a missing crypt() function, try compiling
# with the option below. If you need any other libs, also tag them onto this.
# LIBS=-lcrypt
LIBS=

# Any other C flags you want to use, append on here...
OPTS=

# Top level of the virtual domains package?
INSTDIR=/home/popusers

# Compiler and linker (leave unless you don't have gcc)
CC=gcc $(POPACCT) $(OPTS) $(LIBS) -Wall -O2 -DDEBUG

# Some machines (currently, I've had reports of Redhat 5.1) may require
# $(LIBS) for the linker as well...choose the linker that works for you below
LD=gcc -s
# LD=gcc -s $(LIBS)

###############################################################################
##
## No user servicable parts below
##
###############################################################################

all: vchkpw vmkpasswd vdelivermail

vchkpw: vchkpw.o safestring.o $(FGETPWLIB) $(MDLIB)
	$(LD) -o vchkpw vchkpw.o safestring.o $(FGETPWLIB) $(MDLIB) $(SHADOWLIBS)

vdelivermail: vdelivermail.o safestring.o $(FGETPWLIB)
	$(LD) -o vdelivermail vdelivermail.o safestring.o $(FGETPWLIB)

vmkpasswd: vmkpasswd.o safestring.o
	$(LD) -o vmkpasswd vmkpasswd.o safestring.o

vchkpw.o: vchkpw.c safestring.h
	$(CC) -c vchkpw.c $(SHADOWOPTS) $(FGETPWENT) $(APOP) $(PASSWD) $(LOG_FAIL) $(LOG_OKAY)

vmkpasswd.o: vmkpasswd.c safestring.h
	$(CC) -c vmkpasswd.c

vdelivermail.o: vdelivermail.c safestring.h
	$(CC) -c vdelivermail.c $(FGETPWENT) $(ADMIN)

fgetpwent.o: fgetpwent.c
	$(CC) -c fgetpwent.c -o fgetpwent.o

md5.o: md5.c md5.h global.h
	$(CC) -c md5.c -o md5.o

safestring.o: safestring.c
	$(CC) -c safestring.c -o safestring.o

clean:
	rm -f vchkpw vchkpw.o
	rm -f vmkpasswd vmkpasswd.o
	rm -f vdelivermail vdelivermail.o
	rm -f fgetpwent.o
	rm -f md5.o
	rm -f safestring.o

copy:
	cp vchkpw ../bin
	cp vmkpasswd ../bin
	cp vdelivermail ../bin
	chmod 700 ../bin/*

install:
	cp ../bin/* $(INSTDIR)/bin
	chmod 711 $(INSTDIR)/bin/*

distclean: clean
	rm -f ../bin/vchkpw
	rm -f ../bin/vmkpasswd
	rm -f ../bin/vdelivermail
