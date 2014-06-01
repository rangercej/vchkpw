$Id: INSTALL.CGI,v 1.1 1998/06/16 21:25:23 chris Exp $
------------------------------------------------------------------------------

Installing the CGI
==================
Chris Johnson, April 1998

First off, I recommend you read the file 'SECURITY' so you understand the
implications and possible risks of this CGI.

There is no automatic script to install the CGI - I feel it can be very
site specific with different CGI configurations, different httpd servers,
and different policies regarding security, groups and users.

1. The entire CGI tree can be moved to the point of installation. My personal
suggestion is to put it in a sub-directory 'cgi' under the home directory
of vpopmail - just to keep everything together :) Another place you may
want to put it in is in your web servers cgi-bin directory.

2. In the directory 'src', edit the Makefile and change whatever you think
needs changing.
	VPOPUSER and VPOPGRP should be okay unless you decided to change
	those when installing vchkpw.

	CGIROOT will almost definately need changing to point to the top level
	of where the CGI is to be installed.

	TIMEOUT defines the length of time (in minutes) that an authentication
	cookie is valid for before the user of the CGI has to re-authenticate.
	This is *NOT* idle-time, it is the time from initial authentication.

3. Type 'make' in the src directory.

4. Type 'make install'. This will create a SUID & SGID program vchkaccess.
(see the file SECURITY).

5. Edit the file 'domains' in the CGI root - the file path for qm-config.pl
should be changed, as should the path for perl in the first line of the 
script.

6. Edit the file lib/qm-config.pl - ensure that QMAILCGI, VIRTUSER and URL are
set correctly.

7. Run 'domains' manually - if you get a page of HTML scroll up, then so far
so good. If not, there is a problem somewhere - check the configuration, then
if all looks well, contact me (might be a bug, might not :-)

8. Set up the cookies directory with either 733 or 730 permissions (read 
SECURITY).

9. In either vchkpw's or root's crontab, place an entry to run vchkexpire. This
will expire old cookies when ran.

10. If needed, reconfigure your web-server so that the CGI 'domains' can run
where it is, then restart it/send it a HUP...

11. Load netscape, and run the CGI (http://<host>/<cgi-path>/domains). If all
is well, you should be presented with the portcullus. If you have a virtual
domain setup with a 'postmaster' user, then attempt to log in with the
postmaster password. If all is well, then you'll be taken to the main menu.
If something breaks, then there may be a configuration problem, or more likely
a permissions problem.

12. Now you can personalise the pages (read TEMPLATES for details).

All done!
------------------------------------------------------------------------------
