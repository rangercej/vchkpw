##############################################################################
##
## $Id: qm-misc.pl,v 1.1 1998/06/16 21:19:41 chris Exp $
## Miscalleanous routines
##
## Chris Johnson, Copyright (C) April 1998
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

sub make_hash {
	my ($rs, $fs, $list, $part, @keyval);
	($rs, $fs, $list) = @_;
	%ARRAY=();
	@_ = split (/$rs/, $list);
	foreach $part (@_) {
		@keyval = split (/$fs/,$part);
		%ARRAY = ($keyval[0],$keyval[1],%ARRAY);
	}
	return %ARRAY;
}

sub show_tmpl {
	my ($filename, $sub, @auth);
	($filename, $sub) = @_;
	open (HTMLFILE, "<$QMAILCGI/html/$filename") or html_die ("Could not open file $filename");
	%subvals = make_hash('&','=',$sub);
	while ($line = <HTMLFILE>) {
		if (defined($subvals{'userlist'}) and $line =~ /\%\%USERLIST/) {
			@users=split(/:/,$subvals{'userlist'});
			$line =~ s/\%\%USERLIST/\<SELECT NAME=user SIZE=1\>/;
			foreach $userid (@users) {
				$line =~ s/$/\<OPTION\>$userid/;
			}
			$line =~ s/$/\<\/SELECT\>/;
		}
		$line =~ s/\%\%AUTH/\<INPUT TYPE=hidden NAME=cookie VALUE=$subvals{'auth'}\>/g;
		$line =~ s/\%\%DOMAIN/$subvals{'domain'}/g;
		$line =~ s/\%\%URL/$subvals{'url'}/g;
		$line =~ s/\%\%USER/$subvals{'user'}/g;
		$line =~ s/\%\%MESSAGE/$subvals{'message'}/g;
		print $line;
	}
}

return $TRUE;
