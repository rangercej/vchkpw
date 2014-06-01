###############################################################################
##
## $Id: six-cgi.pl,v 1.1 1998/06/16 21:19:41 chris Exp $
## Sixie's personal CGI lib :-)
##
## Chris Johnson, Copyright (C) 1998
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

sub print_header {
	print "Content-type: text/html\nExpires: now\n\n";
}

sub init_cgi {
	my ($part, $key, $formdata, @keyval);
	$METHOD=$ENV{'REQUEST_METHOD'};
	if ( $METHOD eq 'POST' ) {
		$formdata=<>;
	} else {
		$formdata=$ENV{'QUERY_STRING'};
	}
	@_ = split (/&/,$formdata);
	foreach $part (@_) {
		$part =~ s/\+/ /g;
		@keyval = split(/=/,$part);
		%FORM = ($keyval[0],$keyval[1],%FORM);
		foreach $key (keys %FORM) {
			$FORM{"$key"} =~ s/\%([0-9A-Fa-f][0-9A-Fa-f])/chr(hex("$1"))/ge,$_;
		}
	}
}

sub html_head {
	my ($title);
	($title) = @_;
	print "<HTML><HEAD><TITLE>$title</TITLE></HEAD>\n";
}

sub html_end {
	print "\n</HTML>\n";
}

sub html_message {
	my ($title, $message);
	($title, $message) = @_;
	html_head($title);
	print "<BODY><H1>$message</H1></BODY>";
	&html_end;
}

sub html_die {
	my ($message);
	($message) = @_;
	html_head("CGI: Fatal Error");
	print "<BODY><H1>$message</H1></BODY>";
	&html_end;
	exit;
}

%FORM=();
$METHOD='';

return 1;
