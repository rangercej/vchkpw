# To use shadow passwords under Linux, uncomment the next two lines.
# To use shadow passwords under Solaris, uncomment the SHADOWOPTS line.
# SHADOWLIBS=-lshadow
# SHADOWOPTS=-DPW_SHADOW

# If you want to use a different pop user name other than vpopmail, uncomment
# and change the line below. You'll also need to modify the vadduser and
# vpasswd shell scripts manually
# POPACCT=-DPOPUSER=\"vpopmail\"

# Who is the mail admin? Change the line below accordingly...
ADMIN=-DADMIN=\"postmaster@nccnet.co.uk\"

# If you want the program installed elsewhere, or different permissions on
# the executable, then change line below
INSTDIR=/home/alpha/b2/users/vpopmail/bin
INSTPERM=711

# Any other C flags you want to use, append on here...
OPTS=

CC=gcc $(SHADOWOPTS) $(POPACCT) $(OPTS) -Wall -O2
LD=gcc -s

all: vchkpw vmkpasswd vdelivermail

vchkpw: vchkpw.o
	$(LD) -o vchkpw vchkpw.o $(SHADOWLIBS)

vchkpw.o: vchkpw.c
	$(CC) -c vchkpw.c

vmkpasswd: vmkpasswd.o
	$(LD) -o vmkpasswd vmkpasswd.o

vmkpasswd.o: vmkpasswd.c
	$(CC) -c vmkpasswd.c

vdelivermail: vdelivermail.o
	$(LD) -o vdelivermail vdelivermail.o

vdelivermail.o: vdelivermail.c
	$(CC) $(ADMIN) -c vdelivermail.c

clean:
	rm -f vchkpw vchkpw.o
	rm -f vmkpasswd vmkpasswd.o
	rm -f vdelivermail vdelivermail.o

install: vchkpw
	cp vchkpw $(INSTDIR)/vchkpw ; chmod $(INSTPERM) $(INSTDIR)/vchkpw
	cp vmkpasswd $(INSTDIR)/vmkpasswd ; chmod $(INSTPERM) $(INSTDIR)/vmkpasswd
	cp vdelivermail $(INSTDIR)/vdelivermail ; chmod $(INSTPERM) $(INSTDIR)/vdelivermail
	cp vpasswd $(INSTDIR)/vpasswd ; chmod $(INSTPERM) $(INSTDIR)/vpasswd
	cp vadduser $(INSTDIR)/vadduser ; chmod $(INSTPERM) $(INSTDIR)/vadduser
