##############################################################################
##
## $Id: qm-passwd.pl,v 1.1 1998/06/16 21:19:41 chris Exp $
## Qmail domains management: Password and cookie routines
##
## Copyright (C) Chris Johnson, April 1998
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

sub talk {
	($message) = @_;

	$program = "$QMAILCGI/vchkaccess";
	$pid = &open2 (\*PWIN, \*PWOUT, "$program")
		or html_die 'Internal Error: FATAL: Could not start comms: $!';
	if ($pid) {
		select PWOUT;
		$| = 1;
		print "$message\n";
		$in = <PWIN>;
		select STDOUT;
		close PWIN; close PWOUT;
	}
	wait;
	$stat = $?;
	if ( $stat != 0 ) {
		return "?$in";
	} else {
		return $in;
	}
}

sub checkpassword {
	my ($password, $mkcookie, $result, $time, $domain, $cookie, $cookie_file);
	($domain, $password, $mkcookie) = @_;

	$result = talk "vpostmaster:$domain:$password";
	if ($result =~ /^\?/) {
		return $FALSE;
	}

	if ($mkcookie) {
		$time = time();
		$cookie = "$time.$domain";
		$cookie_file = "$QMAILCGI/cookies/$cookie-$ENV{'REMOTE_ADDR'}";
		system "/bin/touch", $cookie_file;
		return $cookie;
	} else {
		return $TRUE;
	}
}

sub checkcookie {
	($cookie) = @_;
	$cookie_file = "$QMAILCGI/cookies/$cookie-$ENV{'REMOTE_ADDR'}";
	if ( -e $cookie_file ) {
		return $cookie;
	}
	return $FALSE;
}


sub getusers {
	($cookie, $domain) = @_;

	$userlist = talk ("u$cookie:$domain");
	if ($userlist =~ /^\?/) {
		html_die "Internal Error: FATAL: Talk error fetching users: $!<BR>$userlist";
	}
	return $userlist;
}

sub changepassword {
	($cookie, $user, $domain, $newpw, $type) = @_;

	$result = talk ("p$cookie:$user:$domain:$newpw:$type");
	if ($result =~ /^\?/) {
		html_die "Internal Error: FATAL: Talk error changing passwords: $!<BR>$result";
	}
	return $result;
}

sub adduser {
	($cookie, $user, $domain, $passwd, $type) = @_;

	$result = talk("a$cookie:$user:$domain:$passwd:$type");
	if ($result =~ /^\?/) {
		html_die "Internal Error: FATAL: Talk error adding user: $!<BR>$result";
	}
	return $result;
}

sub deluser {
	($cookie, $user, $domain) = @_;

	$result = talk("d$cookie:$user:$domain");
	if ($result =~ /^\?/) {
		html_die "Internal Error: FATAL: Talk error deleting user: $!<BR>$result";
	}
	return $result;
}

return $TRUE;
