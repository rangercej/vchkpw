/*****************************************************************************
**
** $Id: common.c,v 1.1 1999/02/21 13:25:18 chris Exp $
** Routines that are in user by more than one program
**
** Chris Johnson, Copyright (C) July 1998
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
#include <stdarg.h>
#include <unistd.h>
#include <syslog.h>
#include <cdb.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "common.h"
#include "safestring.h"

int usesyslog = 0;

/******************************************************************************
** Open the syslog, and set a flag saying that syslog is in use 
******************************************************************************/
void opensyslog(char *ident)
{
	openlog(ident,LOG_PID,LOG_MAIL);
	usesyslog = 1;
}

/******************************************************************************
** Log a message to syslog and/or log a message to stderr. Deja'vu - was part
** of hmm() below, but as hmm() was also being called by ack() and yikes(),
** the vsnprintf() processing happened twice in these cases - the second time
** being useless (as the string had already been formatted).
******************************************************************************/
void logme (char *msg)
{
	if (usesyslog) {
#ifdef DEBUG
		fputs(msg,stderr);
		fputs("\n",stderr);
#endif
#ifdef SYSLOG
		syslog(LOG_NOTICE,msg);
#endif
	} else {
		fputs(msg,stderr);
		fputs("\n",stderr);
	}
}

/******************************************************************************
** Log a message to syslog and/or log a message to stderr and return cleanly
******************************************************************************/
void hmm(char *msg, ...)
{
	va_list args;
	char fmsg[2048];

	va_start(args,msg);
	vsnprintf(fmsg,sizeof(fmsg),msg,args);
	va_end(args);

	logme(fmsg);
}

/******************************************************************************
** As hmm(), but abort the program as well
******************************************************************************/
void ack(int err, char *msg, ...)
{
        va_list args;
	char fmsg[2048];

	va_start(args,msg);
	vsnprintf(fmsg,sizeof(fmsg),msg,args);
	va_end(args);

	logme(fmsg);
	exit(err);
}

/******************************************************************************
** A mix of hmm() and ack() - if <ret> is nonzero, functions returns, else
** calls exit() and programs ends.
******************************************************************************/
void yikes(int err, int ret, char *msg, ...)
{
        va_list args;
	char fmsg[2048];

	va_start(args,msg);
	vsnprintf(fmsg,sizeof(fmsg),msg,args);
	va_end(args);

	logme(fmsg);
	if (!ret) exit(err);
}

/******************************************************************************
** vgetpw - reads a user entry from the appropriate password file or CDB
******************************************************************************/
struct passwd *vgetpw(char *user, char *domain, struct passwd *popacct, int ret)
{
	static struct passwd pwent;
	static char line[2048];
	struct stat junk;
	char *ptr = NULL, *uid = NULL, *gid = NULL;
	int cdb,match = 0;
	unsigned long int dlen;
	FILE *pwf;

#ifdef DEBUG
	fprintf (stderr,"vgetpw: db: user is %s, domain is %s\n",user,domain);
#endif

	if (chdir(popacct->pw_dir)) {
		yikes (111,ret,"vgetpw: could not chdir() to ~vpopmail (%s) (#4.2.1)",popacct->pw_dir);
		return NULL;
	}
	if (domain) {
		if (chdir("domains")) {
			yikes (111,ret,"vgetpw: could not chdir() to domains/ (#4.2.1)");
			return NULL;
		}
		if (!stat(domain,&junk)) {
			if (chdir(domain)) {
				yikes (111,ret,"vgetpw: could not chdir() to domain %s (#4.2.1)",domain);
				return NULL;
			}
		} else {
			yikes (100,ret,"vgetpw: could not find domain %s (#5.5.0)",domain);
			return NULL;
		}
	}

	cdb = 0;
	if (!stat("vpasswd",&junk)) {
		if (!stat("vpasswd.cdb",&junk)) {
			cdb = 1;
		} else {
			cdb = 2;
		}
	} else {
		if (cdb != 2) {
			yikes (111,ret,"vgetpw: could not find a password file for domain %s (#4.3.5)",domain);
			return NULL;
		} else {
			cdb = 0;
		}
	}
	if (cdb) {
		if ((pwf = fopen("vpasswd.cdb","r")) == NULL) {
			hmm ("vgetpw: could not open db for domain %s - reverting to ascii (#2.3.0)",domain);
			cdb = 0;
		}
	}

	if (!cdb) {
#ifdef DEBUG
		fprintf (stderr,"No database found - using normal passwd\n");
#endif
		if ((pwf = fopen("vpasswd","r")) == NULL) {
			yikes (111,ret,"vgetpw: could not open a pw file for domain %s (#4.3.0)",domain);
			return NULL;
		}
		fgets(line,sizeof(line),pwf);
		while (!feof(pwf) && !match) {
			ptr = line;
			while (*ptr != ':') { ptr++; }
			*ptr = 0;
			if ((match = smatch(line,user)) == 0)
				fgets(line,sizeof(line),pwf);
		}
		*ptr = ':';
		if (!match) {
			yikes (100,ret,"vgetpw: user %s@%s not found in vpasswd (#5.1.1)",user,domain);
			return NULL;
		}
	} else {
#ifdef DEBUG
		fprintf (stderr,"vgetpw: db: Found CDB file - looking up...\n");
#endif
		scopy(line,user,sizeof(line)); scat(line,":",sizeof(line));
		ptr = line;
		while (*ptr != ':') { ptr++; }
		ptr++;
		switch (cdb_seek(fileno(pwf),user,slen(user),&dlen)) {
			case -1:
				fclose(pwf);
				yikes (111,ret,"vgetpw: read error in database for %s@%s (#4.3.0)",user,domain);
				return NULL;
			case 0:
				fclose(pwf);
				yikes (100,ret,"vgetpw: user %s@%s not found in database (#5.1.1)",user,domain);
				return NULL;
		}
		if (fread(ptr,sizeof(char),dlen,pwf) != dlen) {
			yikes (111,ret,"vgetpw: read error in database for %s@%s (#4.3.0)",user,domain);
			return NULL;
		}
		fclose(pwf);
		line[(dlen+slen(user)+1)] = 0;
#ifdef DEBUG
		fprintf (stderr,"vgetpw: db: cdb: line is:\n  %s\n",line);
#endif
	}

	ptr = line;
	pwent.pw_name	= line;
	while (*ptr != ':') { ptr++; }
	*ptr = 0; ptr++; pwent.pw_passwd = ptr;
	while (*ptr != ':') { ptr++; }
	*ptr = 0; ptr++; uid = ptr;
	while (*ptr != ':') { ptr++; }
	*ptr = 0; ptr++; gid = ptr;
	while (*ptr != ':') { ptr++; }
	*ptr = 0; ptr++; pwent.pw_gecos = ptr;
	while (*ptr != ':') { ptr++; }
	*ptr = 0; ptr++; pwent.pw_dir = ptr;
	while (*ptr != ':') { ptr++; }
	*ptr = 0; ptr++; pwent.pw_shell = ptr;

	if (!*uid) { pwent.pw_uid = 0; } else { pwent.pw_uid = atoi(uid); }
	if (!*gid) { pwent.pw_gid = 0; } else { pwent.pw_gid = atoi(gid); }

#ifdef DEBUG
	fprintf (stderr,"vgetpw: db: results: pw_name   = %s\n",pwent.pw_name);
	fprintf (stderr,"                     pw_passwd = %s\n",pwent.pw_passwd);
	fprintf (stderr,"                     pw_uid    = %d\n",pwent.pw_uid);
	fprintf (stderr,"                     pw_gid    = %d\n",pwent.pw_gid);
	fprintf (stderr,"                     pw_gecos  = %s\n",pwent.pw_gecos);
	fprintf (stderr,"                     pw_dir    = %s\n",pwent.pw_dir);
	fprintf (stderr,"                     pw_shell  = %s\n",pwent.pw_shell);
#endif

	return &pwent;
}

