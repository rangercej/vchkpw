/*****************************************************************************
**
** $Id: vchkpw.c,v 1.3 1998/06/17 23:03:11 chris Exp $
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

/* #define DEBUG */

/****************************************************************************
** No user servicable parts below
****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#ifdef LOG_FAIL
#include <syslog.h>
#endif
#ifdef LOG_OKAY
#include <syslog.h>
#endif
#ifdef PW_SHADOW
#include <shadow.h>
#endif
#ifdef NEED_FGETPW
#include "fgetpwent.h"
#endif
#ifdef APOP
#include "global.h"
#include "md5.h"
#endif
#include "safestring.h"

#ifdef LOG_FAIL
#define VCHK_SYSLOG
#endif
#ifdef LOG_OKAY
#ifndef VCHK_SYSLOG
#define VCHK_SYSLOG
#endif
#endif

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

#ifndef POPUSER
#define POPUSER "vpopmail"
#endif

#ifndef ATCHARS
#define ATCHARS "@%_"
#endif

#ifdef DEBUG
#define ack(x,y) { fputs(x,stderr); fputs ("\n",stderr); _exit(y); }
#else
#ifdef LOG_FAIL
#define ack(x,y) { syslog(LOG_NOTICE,x); _exit(y); }
#else
#define ack(x,y) { _exit(y); }
#endif
#endif

static char rcsid[] = "$Id: vchkpw.c,v 1.3 1998/06/17 23:03:11 chris Exp $";

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

char *which_file(char *host, char *pophome)
{
        static char file[1024];
        struct stat info;

        scopy(file,pophome,sizeof(file));
        scat(file,"/domains/",sizeof(file));
        scat(file,host,sizeof(file));
        scat(file,"/vpasswd",sizeof(file));
        if (stat (file, &info) == -1) {
                scopy(file,pophome,sizeof(file));
                scat(file,"/vpasswd",sizeof(file));
        }

        return file;
}

#ifdef APOP
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
#endif
	}

#ifdef DEBUG
	fprintf (stderr,"pw_comp: Bugger -- nothing passwd :-/\n");
#endif
	/* If we got this far, one of the checks failed */
	return 0;
}

struct passwd *checkpopusers(char *login, char *passwd, char *apop)
{
	static struct passwd *popacct;
	struct passwd *retval = NULL;
	char pwfile[255],buf[20];
	char host[100];
	int gid,uid,x;
	FILE *poppwfile;

	popacct=getpwnam(POPUSER);
	if (!popacct) ack("pop: vpop user does not exist",50);

	uid = popacct->pw_uid;
	gid = popacct->pw_gid;
	scopy (host,get_user_domain(login),sizeof(host));
	scopy (pwfile,which_file(host,popacct->pw_dir),sizeof(pwfile));
	if ((poppwfile=fopen(pwfile,"r")) == NULL) ack("pop: Failed to open vpasswd file",51);

	popacct = fgetpwent(poppwfile);
	while (!feof(poppwfile) && strcmp(popacct->pw_name,login)) {
		popacct = fgetpwent(poppwfile);
	}

	if (feof(poppwfile)) {
#ifdef LOG_FAIL
		syslog(LOG_NOTICE,"Failed login attempt with unknown '%s@%s'",login,host);
#endif
		ack("pop: Failed to find user in vpasswd",52);
	}

	if (!*popacct->pw_passwd) ack("pop: Password field is empty",53);

	/* The uid field in vpasswd acts as the auth type (apop, passwd) */
#ifdef DEBUG
	fprintf (stderr,"pop: The UID is %d (%u)\n",popacct->pw_uid,popacct->pw_uid);
#endif
	if ((x=pw_comp(passwd,popacct->pw_passwd,apop,popacct->pw_uid))==0) {
#ifdef LOG_FAIL
		syslog(LOG_NOTICE,"(virtual) Failed login attempt with '%s@%s'",login,host);
#endif
		ack ("pop: Passwords don't match",54);
	}

#ifdef LOG_OKAY
	switch (x) {
		case 1: scopy(buf,"APOP",sizeof(buf)); break;
		case 2: scopy(buf,"USER/PASS",sizeof(buf)); break;
		default: scopy(buf,"unknown auth",sizeof(buf));
	}
	syslog(LOG_INFO,"(virtual, %s) Login from %s@%s",buf,login,host);
#endif
	popacct->pw_uid = uid;
	popacct->pw_gid = gid;
	retval = popacct;
	fclose(poppwfile);
	return retval;
}

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

#ifdef PW_SHADOW
	struct spwd *spwent;
#endif

	if ((pwent = getpwnam(name)) == NULL)
		return NULL;

#ifdef PW_SHADOW
	if ((spwent = getspnam(name)) == NULL)
		return NULL;
	scopy(currpw,spwent->sp_pwdp,sizeof(currpw));
#else
	scopy(currpw,pwent->pw_passwd,sizeof(currpw));
#endif

#ifdef APOP
	if ((apopf=fopen(APOP,"r")) == NULL) ack("real: could not open APOP secrets",22);
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

	if (!*currpw) ack("real: password is empty",20);
	if ((x=pw_comp(passwd,currpw,apop,apmatch)) == 0) {
#ifdef LOG_FAIL
		syslog(LOG_NOTICE,"(real) Failed login with '%s'",name);
#endif
		ack("real: passwords don't match",21);
	}

#ifdef LOG_OKAY
	switch (x) {
		case 1: scopy(buf,"APOP",sizeof(buf)); break;
		case 2: scopy(buf,"USER/PASS",sizeof(buf)); break;
		default: scopy(buf,"unknown auth",sizeof(buf));
	}
	syslog(LOG_INFO,"(real, %s) Login from %s",buf,name);
#endif
	return pwent;
}

int main(int argc, char *argv[])
{
	char buf[300];
	char *name;
	char *passwd;
	char *apop;
	int len,i=0;
	struct passwd *pwent;

	do {
		if ((len = read(3,buf,sizeof(buf))) == -1) ack("main: Read error",111);
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

	if (!*name) ack("main: No username given",1);
	if (!*passwd) ack("main: No password given",2);

#ifdef VCHK_SYSLOG
	openlog("vchkpw",LOG_PID,LOG_MAIL);
#ifdef DEBUG
	fprintf (stderr,"main: opened syslog\n");
#endif
#endif

	if ((pwent = checkrealusers(name,passwd,apop)) == NULL)
		if ((pwent = checkpopusers(name,passwd,apop)) == NULL)
			ack("main: No user found",3);
#ifdef DEBUG
	fprintf (stderr,"main: doing setgid()\n");
#endif
	if (setgid(pwent->pw_gid) == -1) ack("main: setgid() failed",4);

#ifdef DEBUG
	fprintf (stderr,"main: doing setuid()\n");
#endif
	if (setuid(pwent->pw_uid) == -1) ack("main: setuid() failed",5);

#ifdef DEBUG
	fprintf (stderr,"main: doing chdir()\n");
#endif
	if (chdir(pwent->pw_dir) == -1) ack("main: chdir() failed",6);

#ifdef DEBUG
	fprintf (stderr,"main: doing putenv(USER)\n");
#endif
	scopy(buf,"USER=",sizeof(buf)); scat(buf,pwent->pw_name,sizeof(buf)); 
	if (putenv(buf) == -1) ack("main: putenv(USER) failed",7); 

#ifdef DEBUG
	fprintf (stderr,"main: doing putenv(HOME)\n");
#endif
	scopy(buf,"HOME=",sizeof(buf)); scat(buf,pwent->pw_dir,sizeof(buf)); 
	if (putenv(buf) == -1) ack("main: putenv(HOME) failed",8);

#ifdef DEBUG
	fprintf (stderr,"main: doing putenv(SHELL)\n");
#endif
	scopy(buf,"SHELL=",sizeof(buf)); scat(buf,pwent->pw_shell,sizeof(buf)); 
	if (putenv(buf) == -1) ack("main: putenv(SHELL) failed",9);

#ifdef DEBUG
	fprintf (stderr,"main: about to execvp()\n");
#endif
	execvp(argv[1],argv+1);
	ack("main: execvp() failed",10);
}
