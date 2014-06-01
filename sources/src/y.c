/*****************************************************************************
**
** $Id: vdelivermail.c,v 1.1 1998/06/16 21:00:49 chris Exp $
** Deliver a mail to a virtual POP user - called from the .qmail-default file
** pointed to by users/assign
**
** Chris Johnson, Copyright (C) Jan '98
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

#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "safestring.h"
#ifdef NEED_FGETPW
#include "fgetpwent.h"
#endif

#ifndef POPUSER
#define POPUSER "vpopmail"
#endif
#ifndef ADMIN
#define ADMIN "postmaster@this.host.plase.change.this"
#endif
#ifndef QMAILLOCAL
#define QMAILLOCAL "/var/qmail/bin/qmail-local"
#endif

static char rcsid[] = "$Id: vdelivermail.c,v 1.1 1998/06/16 21:00:49 chris Exp $";

char tmp_file[256];

/****************************************************************************
** Delete the temporary file */
void delete_tmp()
{
	char message[1024];

	if (unlink(tmp_file) != 0) {
		switch (errno) {
			case EACCES:
				scopy (message,"EACCES: permission denied",sizeof(message));
				break;
			case EPERM:
				scopy (message,"EPERM: permission denied",sizeof(message));
				break;
			case ENOENT:
				scopy (message,"ENOENT: path doesn't exist",sizeof(message));
				break;
			case ENOMEM:
				scopy (message,"ENOMEM: out of kernel memory",sizeof(message));
				break;
			case EROFS:
				scopy (message,"EROFS: filesystem read-only",sizeof(message));
				break;
			default: sprintf (message,"Other code: %d",errno);
		}
		puts ("Yikes! Could create but can't delete temporary file!!");
		puts (message);
	}
}

/****************************************************************************
** Temporary fail (exit 111), & display message */
int failtemp(char *err, ...)
{
	va_list args;

	va_start(args,err);
	vprintf(err,args);
	va_end(args);

	if (*tmp_file)
		delete_tmp();

	exit(111);
}

/****************************************************************************
** Permanant fail (exit 100), & display message */
int failperm(char *err, ...)
{
	va_list args;

	puts ("Reason for failure: ");
	va_start(args,err);
	vprintf(err,args);
	va_end(args);

	if (*tmp_file)
		delete_tmp();

	exit(100);
}

/****************************************************************************
** Return the password file to use for domain */
char *which_password_file(char *domain, char *pophome)
{
	static char file[1024];
	struct stat info;

	scopy(file,pophome,sizeof(file));
	scat(file,"/domains/",sizeof(file));
	scat(file,domain,sizeof(file));
	scat(file,"/vpasswd",sizeof(file));
	if (stat(file,&info) == -1) {
		scopy(file,pophome,sizeof(file));
		scat(file,"/vpasswd",sizeof(file));
	}

	return file;
}

/****************************************************************************
** See if the POP user exists!! */
struct passwd* pop_user_exist(char *user, char *host, char *prefix, char *bounce)
{
	static struct passwd *pw_data;
	FILE *openfile;
	char pophome[1024];
	char filename[1024];
	char localuser[1024];

	int i=0;
	while (user[i] != 0) { user[i] = tolower(user[i]); i++; }

	if ((pw_data=getpwnam(POPUSER)) == NULL) {
		failperm("POP users have not been set up correctly on this system. Please\ncontact %s with this problem. (#4.3.0)\n",ADMIN);
	}

	scopy(pophome,pw_data->pw_dir,sizeof(pophome));
	if (*prefix) {
		scopy(localuser,prefix,sizeof(localuser));
		scat(localuser,user,sizeof(localuser));
	} else {
		scopy(localuser,user,sizeof(localuser));
	}
	scopy(filename,which_password_file(host,pophome),sizeof(filename));
	if ((openfile = fopen(filename,"r")) == NULL) {
		if (!*bounce) {
			failperm("Can't confirm users existance... (#5.1.1)\n");
		} else {
			pw_data = NULL;
		}
	} else {
		pw_data=fgetpwent(openfile);
		while (!feof(openfile) && strcmp(localuser,pw_data->pw_name)) {
			pw_data=fgetpwent(openfile);
		}
		fclose(openfile);
		if (!pw_data && !*bounce) {
			failperm ("Unknown local POP user %s (#5.1.1)\n",localuser);
		}
	}
	return pw_data;
}

/*****************************************************************************
** To process SIGALRM for 24hr timeout */
void sig_handler(int sig)
{
	delete_tmp();
	failtemp("Message timeout (#4.3.0)\n");
}

/*****************************************************************************
** Deliver mail to Maildir in directory 'deliverto' **
** Follows procedure outlined in maildir(5).        */
void deliver_mail(char *deliverto)
{
	struct stat statdata;
	char mailname[256];
	char hostname[128];
	char msgbuf[32768];
	time_t tm;
	int pid,i;
	int mailfile;
	size_t bytes;

	signal(SIGALRM,sig_handler);

	if (chdir(deliverto) == -1)
		failtemp ("Can't change to %s (#4.2.1)\n",deliverto);

	if (chdir("Maildir") == -1)
		failtemp ("Can't change to Maildir (#4.2.1)\n");

	gethostname(hostname,sizeof(hostname));
	pid=getpid();
	for (i=0; (i < 3) && (i > -1); i++) {
		time (&tm);
		sprintf(tmp_file,"tmp/%lu.%d.%s",tm,pid,hostname);
		sprintf(mailname,"new/%lu.%d.%s",tm,pid,hostname);
		if (stat(tmp_file,&statdata) == -1) {
			if (errno == ENOENT) {
				i=-2;	/* Not -1! Breaks program */
			}
		}
		if (i > -1) {
			sleep(2);
		}
	}
	if (i > 0)
		failtemp ("Unable to stat maildir (#4.3.0)\n");
	
	alarm(86400);
	if ((mailfile = creat(tmp_file,S_IREAD | S_IWRITE)) == -1)
		failtemp ("Can't create tempfile (#4.3.0)\n");

	scopy(msgbuf,getenv("RPLINE"),sizeof(msgbuf));
	scat(msgbuf,getenv("DTLINE"),sizeof(msgbuf));
	if (write(mailfile, msgbuf, strlen(msgbuf)) != strlen(msgbuf)) {
		delete_tmp();
		failtemp ("Failed to write RP & DT (#4.3.0)\n");
	}

	bytes=read(0,msgbuf,sizeof(msgbuf));
	while (bytes > 0) {
		if (write(mailfile,msgbuf,bytes) != bytes) {
			delete_tmp();
			failtemp ("Failed to write to tmp/ (#4.3.0)\n");
		}
		bytes=read(0,msgbuf,sizeof(msgbuf));
	}
	if (bytes < 0) {
		delete_tmp();
		failtemp("Error occoured reading message (#4.3.0)\n");
	}
	if (fsync(mailfile) == -1) {
		delete_tmp();
		failtemp("Unable to sync file (#4.3.0)\n");
	}
	if (close(mailfile) == -1) {
		delete_tmp();
		failtemp("Unable to close() tmp file (#4.3.0)\n");
	}
	if (link(tmp_file,mailname) == -1) {
		delete_tmp();
		failtemp("Unable to link tmp to new (#4.3.0)\n");
	}
	delete_tmp();
}

/*****************************************************************************
** The main bit :) If it gets to the end of here, delivery was successful   */
int main(int argc, char *argv[])
{
	struct passwd *pw_data;
	char *deliverto;
	char bounce[1024];
	char prefix[1024];
	int i;

	if (argc > 3) {
		failtemp ("Syntax: %s [prefix [bounceable_mail]]\n",argv[0]);
	}

	printf ("%s:%s:%s\n",getenv("EXT"),getenv("USER"),getenv("HOST"));

	*bounce = 0;
	*prefix = 0;
	*tmp_file = 0;
	if (argc > 1) {
		scopy(prefix,argv[1],sizeof(prefix));
		if (argc == 3) {
			scopy (bounce,argv[2],sizeof(prefix));
		}
	}

	pw_data=pop_user_exist(getenv("EXT"),getenv("HOST"),prefix,bounce);

	if (!pw_data) {
		printf ("POP user does not exist, but will deliver to %s\n",bounce);
		deliverto = bounce;
	} else {
		deliverto = pw_data->pw_dir;
	}

	deliver_mail(deliverto);
	
	exit (0);
}
