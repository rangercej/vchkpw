$Id: README,v 1.2 1998/06/17 23:11:25 chris Exp $
-------------------------------------------------------------------------------

vchkpw 3.0
==========
Chris Johnson, Jan 1998
sixie@nccnet.co.uk, http://homepages.shu.ac.uk/~cjohnso0/

These utilities enable qmail to have virtual domains and virtual users,
running under a single *real* user.

Read all the documentation before use! Installation instructions are in the
file doc/INSTALL.

All programs are Copyright (C) 1998 Chris Johnson (sixie@nccnet.co.uk),
apart from the RSA Data Security, Inc. MD5 Message-Digest Algorithm in files:

  * md5.c
  * md5.h
  * global.h

which are Copyright (C) 1991-2, RSA Data Security, Inc.

This package may be used and distributed under the terms of the GNU General
Public License. See the file LICENSE for further details.

All source code is protected by the terms of the General Public License
except for the following:

* md5.c
* md5.h
* global.h

For the license governing these files, please read the file 'LICENSE.MD5'

Email sixie@nccnet.co.uk for more details.

If you find this package useful, please email me and let me know!

Bug reports welcome (I suppose) :)

-------------------------------------------------------------------------------

MANIFEST
--------
Useful documentation:

* LICENSE		Your license for use/modification/distribution
* LICENSE.MD5		The license governing the MD5 soure code
* README		This file
* doc/INSTALL		Installation instructions
* doc/README.APOP	Information about APOP
* doc/Popdomain-HOWTO	How to setup virtual domains
* doc/Popuser-HOWTO	How to setup virtual users
* doc/Vchkpw.doc	Vchkpw semi-manual
* cgi/README.CGI	Information about the CGI front end
* cgi/doc/INSTALL.CGI	How to install the CGI front end
* cgi/doc/SECURITY	How to make this CGI secure
* cgi/doc/TEMPLATES	How to create HTML templates for the CGI

Useless documentation:

* doc/BLURB		An overview of vchkpw
* doc/CREDITS		Thanks go to...
* doc/SYSTEMS		List of systems that I know vchkpw compiles on
* doc/TODO		What I may do one day...
* doc/VERSION		Version of the vchkpw package
* doc/WHATSNEW		What's new in this version

Scripts:
* setup			Set the system up initially
* bin/fixvpasswd	Fixes the values in the [ug]id fields of vpasswd
* bin/splitmboxes	Split mailboxes into a maildir for the system
* bin/vaddomain		Add a virtual domain
* bin/vadduser		Add a virtual user
* bin/vpasswd		Change a virtual users password
* bin/vdeldomain	Delete a virtual domain
* bin/vdeluser		Delete a virtual user

* src/Makefile		The building instructions for the compiler
* src/fgetpwent.c	\_ Support for systems that don't have a
* src/fgetpwent.h	/  fgetpwent() function
* src/global.h		\
* src/md5.c		|- The MD5 source code ((C)RSA)
* src/md5.h		/
* src/safestring.c	\_ Replacements for strcpy() and strcat()
* src/safestring.h	/
* src/vchkpw.c		Check POP passwords
* src/vdelivermail.c	Deliver POP mail
* src/vmkpasswd.c	Create passwords

CGI Source code:

* cgi/src/Makefile	The building instructions for the compiler
* cgi/src/safestring.c	\_ Replacements for strcpy() and strcat()
* cgi/src/safestring.h	/
* cgi/src/vchkaccess.c	Allow the CGI to access vpasswd
* cgi/src/vchkexpire.c	Expire cookies

CGI Perl scripts

* cgi/domains		The control for the CGI
* cgi/lib/qm_config.pl	Configuration details for the CGI
* cgi/lib/qm_misc.pl	General library routines
* cgi/lib/qm_passwd.pl	Password file based routines
* cgi/lib/six-cgi.pl	General CGI routine

CGI HTML Templates

* cgi/html/add_fail.tmpl	Adding a user failed
* cgi/html/add_okay.tmpl	Adding a user succeeded
* cgi/html/adduser.tmpl	Add user page
* cgi/html/del_fail.tmpl	Deleting a user failed
* cgi/html/del_okay.tmpl	Deleting a user succeeded
* cgi/html/deluser.tmpl	Delete user page
* cgi/html/menu.tmpl	Main menu
* cgi/html/passwd.tmpl	Change a password page
* cgi/html/portcullus.tmpl	Authorisation page
* cgi/html/pw_fail.tmpl	Password change failed
* cgi/html/pw_okay.tmpl	Password change succeeded


Chris Johnson, 16 April 1998

-------------------------------------------------------------------------------
