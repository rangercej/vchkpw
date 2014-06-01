/******************************************************************************
**
** Creates/changes an enrypted password (up to 8 characters max)
**
** Old password is given on the command line, new password is returned on
** stdout - all other messages go to stderr or direct to the tty
**
** Requiered by vadduser and vpasswd
**
** Chris Johnson, Jan 1998
**
******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pwd.h>
#include <time.h>
#include <string.h>
#ifndef POPUSER
#define POPUSER "vpopuser"
#endif

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
			strcpy (cur_pw,argv[1]);
		} else {
			strcpy (cur_pw,"");
		}
	}

	time(&tm);
	srandom (tm % 65536);

	salt[0] = randltr();
	salt[1] = randltr();
	salt[2] = 0;

	if (argc != 1) {
		strcpy (old_passwd,getpass ("Enter old POP password: "));
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

	strcpy (newpasswd,getpass ("Enter new POP password: "));

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
		
	strcpy (andagain,getpass ("Enter new POP password again: "));
	if (strcmp(newpasswd,andagain)) {
		fputs ("Passwords don't match...aborting\n",stderr);
		puts (cur_pw);
		exit(7);
	}

	strcpy(crypted,crypt(newpasswd,salt));

	puts (crypted);

	return 0;
}
