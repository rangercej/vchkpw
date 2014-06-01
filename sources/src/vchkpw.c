/*****************************************************************************
**
** $Id: vchkpw.c,v 1.6 1999/06/05 13:05:29 chris Exp $
** Vchkpw version 3.0 - dropin replacement for checkpassword
**
** Chris Johnson, Copyright (C) April 1998
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
*****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#ifdef SYSLOG
#include <syslog.h>
#endif
#ifdef USESHADOW
#include <shadow.h>
#endif
#ifdef APOP
#include "md5.h"
#endif
#include "safestring.h"
#include "common.h"

#ifndef APOP
#ifndef PASSWD
#error --------------------------------------------------------
#error You have not defined a password mechanism...should I use
#error password authentication, APOP or both?
#error .
#error Please check your Makefile and try again.
#error --------------------------------------------------------
#endif
#endif

#ifndef ATCHARS
#define ATCHARS "@%_"
#endif

const static char rcsid[] = "$Id: vchkpw.c,v 1.6 1999/06/05 13:05:29 chris Exp $";

/*****************************************************************************
** User logged in as 'user@host', this returns host, or NULL if user logged in
** as 'user'
*****************************************************************************/
char *get_user_domain(char *user)
{
        int i,j;
        static char *host = NULL;

        for (i=0; (host == NULL) && (user[i] != 0); i++) {
                for (j=0; (host == NULL) && ( j < strlen(ATCHARS)); j++) {
                        if (user[i] == ATCHARS[j]) {
                                user[i] = 0;
                                host = user + i + 1;
                        }
                }
        }

        if (host == NULL)
                host = user + i;

        return host;
}

#ifdef APOP
/*****************************************************************************
** decimal to hex conversion (hence dec2hex :-)
*****************************************************************************/
char *dec2hex(unsigned char *digest)
{
	static char ascii[33];
	char *hex="0123456789abcdef";
	int i,j,k;

	bzero(ascii,sizeof(ascii));
	for (i=0; i < 16; i++) {
		j = digest[i]/16;
		k = digest[i]%16;
		ascii[i*2] = hex[j];
		ascii[(i*2)+1] = hex[k];
	}

	return ascii;
}
#endif

/*****************************************************************************
** This is the guts of the operation -- lots of #ifdefs depending on what the
** user had decided he needs.
**
** supp = passwd given by user; curr = password stored on file
** apop = apop hash stored on file ; type is described below
*****************************************************************************/
int pw_comp(char *supp, char *curr, char *apop, int type)
{
	/* Type can be: 0 -- try both APOP and user/passwd
			1 -- user/passwd only
			2 -- only do an APOP check
	   If only APOP or PASSWD auth is compiled in (ie, not both), then the
	   type field is ignored.
	*/
#ifdef APOP
	char buf[100];
	unsigned char digest[16];
	char ascii[33];
	MD5_CTX context;
#endif

#ifdef DEBUG
	fprintf (stderr,"pw_comp: on entry: %s -- %s -- %s -- %d\n",supp,curr,apop,type);
#endif

#ifndef APOP
	type = 1;
#endif

#ifndef PASSWD
	type = 2;
#endif

#ifdef APOP
	bzero(ascii,sizeof(ascii));
	if (type != 1) {
		scopy(buf,apop,sizeof(buf));
		scat(buf,curr,sizeof(buf));
#ifdef DEBUG
		fprintf (stderr,"pw_comp: making digest for %s\n",buf);
#endif
		MD5Init (&context);
		MD5Update (&context,buf,strlen(buf));
		MD5Final (digest, &context);
		scopy(ascii,dec2hex(digest),sizeof(ascii));
#ifdef DEBUG
		fprintf (stderr,"pw_comp: comparing digests %s and %s\n",ascii,supp);
#endif
		if (!strcmp(ascii,supp))
			return 1;
	}
#endif

#ifdef PASSWD
	if (type != 2) {
#ifdef DEBUG
		fprintf (stderr,"pw_comp: Comparing %s (%s) with %s\n",supp,crypt(supp,curr),curr);
#endif

		if (!strcmp(curr,crypt(supp,curr))) return 2;
	}
#endif

#ifdef DEBUG
	fprintf (stderr,"pw_comp: Bugger -- nothing passwd :-/\n");
#endif
	/* If we got this far, one of the checks failed */
	return 0;
}

/*****************************************************************************
** Get a POP user's entry from the password database
*****************************************************************************/
struct passwd *checkpopusers(char *login, char *passwd, char *apop)
{
	static struct passwd *popacct;
	struct passwd *retval = NULL;
	char buf[20];
	char host[100];
	int gid,uid,x;

	popacct=getpwnam(POPUSER);
	if (!popacct) ack(50,"pop: vpop user does not exist");

	uid = popacct->pw_uid;
	gid = popacct->pw_gid;
	scopy (host,get_user_domain(login),sizeof(host));

	popacct = vgetpw(login,host,popacct,0);

	if (!*popacct->pw_passwd) ack(53,"pop: Password field is empty");

	/* The uid field in vpasswd acts as the auth type (apop, passwd) */
#ifdef DEBUG
	fprintf (stderr,"pop: The UID is %d (%u)\n",popacct->pw_uid,popacct->pw_uid);
#endif

	if ((x=pw_comp(passwd,popacct->pw_passwd,apop,popacct->pw_uid))==0) {
		ack (54,"(virtual) Failed login attempt with '%s@%s'",login,host);
	}

#ifdef SYSLOG
	switch (x) {
		case 1: scopy(buf,"APOP",sizeof(buf)); break;
		case 2: scopy(buf,"USER/PASS",sizeof(buf)); break;
		default: scopy(buf,"unknown auth",sizeof(buf));
	}
	hmm ("(virtual, %s) Login from %s@%s",buf,login,host);
#endif
	popacct->pw_uid = uid;
	popacct->pw_gid = gid;
	retval = popacct;
	return retval;
}

/*****************************************************************************
** Get a real users entry from /etc/passwd, and maybe read the secret from
** /etc/apop-secrets.
*****************************************************************************/
struct passwd *checkrealusers(char *name, char *passwd, char *apop)
{
	char currpw[80];
	char buf[100];
	int x,apmatch=1;
	static struct passwd *pwent;
#ifdef APOP
	int i;
	FILE *apopf;
#endif

#ifdef USESHADOW
	struct spwd *spwent;
#endif

	if ((pwent = getpwnam(name)) == NULL)
		return NULL;

#ifdef USESHADOW
	if ((spwent = getspnam(name)) == NULL)
		return NULL;
	scopy(currpw,spwent->sp_pwdp,sizeof(currpw));
#else
	scopy(currpw,pwent->pw_passwd,sizeof(currpw));
#endif

#ifdef APOP
	if ((apopf=fopen(APOP,"r")) == NULL) ack(22,"real: could not open APOP secrets");
	fgets(buf,sizeof(buf),apopf);
	while ((apmatch != 2) && !feof(apopf)) {
		for (i=0; buf[i] >= ' '; i++) /* do nothing */;
		buf[i] = 0;
		if (strstr(buf,name) == buf) {
			for (i=0; buf[i] != ':'; i++) /* do nothing */; 
			if (i == strlen(name)) {
				i++;
				scopy(currpw,&buf[i],sizeof(currpw));
				apmatch = 2;
			}
		}
		fgets(buf,sizeof(buf),apopf);
	}
	fclose(apopf);
#endif

	if (!*currpw) ack(20,"real: password is empty");
	if ((x=pw_comp(passwd,currpw,apop,apmatch)) == 0) {
#ifdef SYSLOG
		syslog(LOG_NOTICE,"(real) Failed login with '%s'",name);
#endif
		ack(21,"real: passwords don't match");
	}

#ifdef SYSLOG
	switch (x) {
		case 1: scopy(buf,"APOP",sizeof(buf)); break;
		case 2: scopy(buf,"USER/PASS",sizeof(buf)); break;
		default: scopy(buf,"unknown auth",sizeof(buf));
	}
	syslog(LOG_INFO,"(real, %s) Login from %s",buf,name);
#endif
	return pwent;
}

/*****************************************************************************
** Where it all starts and ends
*****************************************************************************/
int main(int argc, char *argv[])
{
	char buf[300];
	char *name;
	char *passwd;
	char *apop;
	int len,i=0;
	struct passwd *pwent;

	do {
		if ((len = read(3,buf,sizeof(buf))) == -1) ack(1,"main: Read error");
	} while (len == 0);

	close(3);

	name = buf;
	for (i=0; buf[i] != 0; i++); passwd = buf+i+1; i++;
	for (; buf[i] != 0; i++); apop = buf+i+1;

#ifdef DEBUG
	fprintf (stderr,"main: name = :%s:\n",name);
	fprintf (stderr,"main: pass = :%s:\n",passwd);
	fprintf (stderr,"main: apop = :%s:\n",apop);
#endif

	if (!*name) ack(1,"main: No username given");
	if (!*passwd) ack(2,"main: No password given");

#ifdef SYSLOG
	opensyslog("vchkpw");
#ifdef DEBUG
	fprintf (stderr,"main: opened syslog\n");
#endif
#endif

	if ((pwent = checkrealusers(name,passwd,apop)) == NULL)
		if ((pwent = checkpopusers(name,passwd,apop)) == NULL)
			ack(3,"main: No user found");

	if (setgid(pwent->pw_gid) == -1) ack(4,"main: setgid() failed");
	if (setuid(pwent->pw_uid) == -1) ack(5,"main: setuid() failed");
	if (chdir(pwent->pw_dir) == -1) ack(6,"main: chdir() failed");

#ifdef DEBUG
	fprintf (stderr,"main: argc = %d\n",argc);
	fprintf (stderr,"main: argv as follows:\n");
	for (i=0; i < argc; i++) {
		fprintf (stderr,"   argv[%d] => %s\n",i,argv[i]);
	}
#endif

	execvp(argv[1],argv+1);
	ack(10,"main: execvp() failed");

	return 0;
}
