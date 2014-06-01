/******************************************************************************
**
** $Id: vmkpasswd.c,v 1.2 1998/06/16 21:04:05 chris Exp $
** Creates/changes an enrypted password (up to 8 characters max)
**
** Chris Johnson, Copyright (C) Jan 1998
** Email: sixie@nccnet.co.uk
**
**    This program is free software; you can redistribute it and/or modify
**    it under the terms of the GNU General Public License as published by
**    the Free Software Foundation; either version 2 of the License, or
**    (at your option) any later version.
**
**    This program is distributed in the hope that it will be useful,
**    but WITHOUT ANY WARRANTY; without even the implied warranty of
**    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
**    GNU General Public License for more details.
**
**    You should have received a copy of the GNU General Public License
**    along with this program; if not, write to the Free Software
**    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
**
*******************************************************************************
**
** Old password is given on the command line, new password is returned on
** stdout - all other messages go to stderr or direct to the tty
**
** Requiered by vadduser and vpasswd
**
******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pwd.h>
#include <time.h>
#include "safestring.h"
#ifndef POPUSER
#define POPUSER "vpopuser"
#endif

static char rcsid[] = "$Id: vmkpasswd.c,v 1.2 1998/06/16 21:04:05 chris Exp $";

char randltr(void)
{
	char rand;
	char retval = 'a';

	rand = random() % 64;
	
	if (rand < 26)
		retval = rand + 'a';
	if (rand > 25)
		retval = rand - 26 + 'A';
	if (rand > 51)
		retval = rand - 52 + '0';
	if (rand == 62)
		retval = ';';
	if (rand == 63)
		retval = '.';

	return retval;
}

int main(int argc, char *argv[])
{
	char crypted[1024];
	char old_passwd[1024];
	char cur_pw[1024];
	char newpasswd[1024];
	char andagain[1024];
	char salt[3];
	time_t tm;

	if (argc > 2) {
		_exit(1);
	} else {
		if (argc == 2) {
			scopy (cur_pw,argv[1],sizeof(cur_pw));
		} else {
			scopy (cur_pw,"",sizeof(cur_pw));
		}
	}

	time(&tm);
	srandom (tm % 65536);

	salt[0] = randltr();
	salt[1] = randltr();
	salt[2] = 0;

	if (argc != 1) {
		scopy (old_passwd,getpass ("Enter old POP password: "),sizeof(old_passwd));
		if (!*old_passwd) {
			fputs ("Aborting change\n",stderr);
			puts (cur_pw);
			exit(2);
		}
		if (strcmp(crypt(old_passwd,argv[1]),argv[1])) {
			fputs ("Incorrect password\n",stderr);
			puts (cur_pw);
			exit(3);
		}
	}

	scopy (newpasswd,getpass ("Enter new POP password: "),sizeof(newpasswd));

	if (newpasswd[0] == 0) {
		fputs ("Cannot have NULL password...aborting\n",stderr);
		puts (cur_pw);
		exit(5);
	}

	if (argc != 1) {
		if (!strcmp(crypt(newpasswd,argv[1]),argv[1])) {
			fputs ("Old and new passwords are the same...aborting\n",stderr);
			puts (cur_pw);
			exit(6);
		}
	}
		
	scopy (andagain,getpass ("Enter new POP password again: "),sizeof(andagain));
	if (strcmp(newpasswd,andagain)) {
		fputs ("Passwords don't match...aborting\n",stderr);
		puts (cur_pw);
		exit(7);
	}

	scopy(crypted,crypt(newpasswd,salt),sizeof(crypted));

	puts (crypted);

	return 0;
}
