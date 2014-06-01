##############################################################################
##
## $Id: qm-config.pl,v 1.1 1998/06/16 21:19:41 chris Exp $
## Configuration & initial setup information
##
## Chris Johnson, Copyright (C) April 1998
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
##############################################################################

##############################################################################
## Most of this will need configuring...its all rather site specific
##############################################################################

## Location of all the CGI's related to this package
$QMAILCGI='/home/chris/sys/qmail/vchkpw/devel/cgi';

## Name of virtual domains user
$VIRTUSER='vpopmail';

## A safe path is needed
$ENV{'PATH'}='/bin';

## URL of the main script
$URL='http://localhost/qmail-cgi/domains';

##############################################################################
## That's it -- no more to do...there are no user servicable parts below this
## point. Test the CGI by running it from the command line. You should get
## the portcullus page. If not and it dies beforehand, then there is a problem.
## Check your configuration in this file before contacting me!!
##############################################################################

## This is a quick check to see if the virtual domains user exists. If this
## fails, then the result will be a "Server Error" in Netscape. Run CGI from
## the command line to test this.
($x, $x, $x, $x, $x, $x, $x, $VIRTHOME) = getpwnam($VIRTUSER)
	or die "Internal Error: FATAL: Server configuration problem";

$TRUE=1;
$FALSE=0;

## Remove buffering -- this fixes a few problems -- chief one being the 
## bi-directional IPC which gave Netscape (actually, httpd - lynx also
## suffered) some grief.
$|=1;

return $TRUE;
