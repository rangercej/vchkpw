/*****************************************************************************
**
** $Id: vdelivermail.c,v 1.2 1999/02/21 13:24:42 chris Exp $
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
#include "common.h"
#ifndef ADMIN
#define ADMIN "postmaster@misconfigured.host"
#endif

const static char rcsid[] = "$Id: vdelivermail.c,v 1.2 1999/02/21 13:24:42 chris Exp $";

char tmp_file[256];


/******************************************************************************
** Delete the temporary file
******************************************************************************/
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
		hmm ("Yikes! Could create but can't delete temporary file!!");
		hmm (message);
	}
}

/******************************************************************************
** Temporary fail (exit 111), & display message 
******************************************************************************/
int failtemp(char *err, ...)
{
	va_list args;
	char fmsg[2048];

	puts ("Reason for failure: ");
	va_start(args,err);
	vsnprintf(fmsg,sizeof(fmsg),err,args);
	va_end(args);

	hmm (fmsg);
	puts (fmsg);
	if (*tmp_file) delete_tmp();

	exit(111);
}

/******************************************************************************
** Permanant fail (exit 100), & display message
******************************************************************************/
int failperm(char *err, ...)
{
	const char *prefix = "Reason for failure: ";
	va_list args;
	char fmsg[2048];
	char *ptr;

	scopy (fmsg,prefix,sizeof(fmsg));
	ptr = fmsg + slen(prefix);
	va_start(args,err);
	vsnprintf(ptr,sizeof(fmsg) - slen(prefix),err,args);
	va_end(args);

	hmm (fmsg);
	puts (fmsg);
	if (*tmp_file) delete_tmp();

	exit(100);
}

/******************************************************************************
** See if the POP user exists!! 
******************************************************************************/
struct passwd* pop_user_exist(char *user, char *host, char *prefix, char *bounce)
{
	static struct passwd *pw_data;
	char localuser[1024];

	if ((pw_data=getpwnam(POPUSER)) == NULL) {
		failperm("POP users have not been set up correctly on this system.\nPlease contact %s with this problem. (#4.3.5)\n",ADMIN);
	}

	if (*prefix) {
		scopy(localuser,prefix,sizeof(localuser));
		scat(localuser,user,sizeof(localuser));
	} else {
		scopy(localuser,user,sizeof(localuser));
	}
	pw_data = vgetpw(localuser,host,pw_data,*bounce);

	return pw_data;
}

/******************************************************************************
** To process SIGALRM for 24hr timeout
******************************************************************************/
void sig_handler(int sig)
{
	delete_tmp();
	failtemp("Message timeout (#4.3.0)\n");
}

/******************************************************************************
** Deliver mail to Maildir in directory 'deliverto'
** Follows six step procedure outlined in maildir(5).
******************************************************************************/
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

	/*********************************************************** Step 1 **/
	if (chdir(deliverto) == -1)
		failtemp ("Can't change to %s (#4.2.1)\n",deliverto);

	if (chdir("Maildir") == -1)
		failtemp ("Can't change to Maildir (#4.2.1)\n");

	/*********************************************************** Step 2 **/
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

		/*************************************************** Step 3 **/
		if (i > -1) {
			sleep(2);
		}
	}
	if (i > 0)
		failtemp ("Unable to stat maildir (#4.3.0)\n");
	
	/*********************************************************** Step 4 **/
	alarm(86400);
	if ((mailfile = creat(tmp_file,S_IREAD | S_IWRITE)) == -1)
		failtemp ("Can't create tempfile (#4.3.0)\n");

	/************************************************ Step 5 (NFS-safe) **/
	scopy(msgbuf,getenv("RPLINE"),sizeof(msgbuf));
	scat(msgbuf,getenv("DTLINE"),sizeof(msgbuf));
	if (write(mailfile, msgbuf, strlen(msgbuf)) != strlen(msgbuf)) {
		delete_tmp();
		failtemp ("Failed to write RP & DT (#4.3.0)\n");
	}

	bytes=read(0,msgbuf,sizeof(msgbuf));
	while (bytes > 0) {
		/************************************************* Step 5.1 **/
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

	/********************************************************* Step 5.2 **/
	if (fsync(mailfile) == -1) {
		delete_tmp();
		failtemp("Unable to sync file (#4.3.0)\n");
	}

	/********************************************************* Step 5.3 **/
	if (close(mailfile) == -1) {
		delete_tmp();
		failtemp("Unable to close() tmp file (#4.3.0)\n");
	}

	/*********************************************************** Step 6 **/
	if (link(tmp_file,mailname) == -1) {
		delete_tmp();
		failtemp("Unable to link tmp to new (#4.3.0)\n");
	}
	delete_tmp();
	hmm ("Success: mail has been delivered successfully.");
}

/******************************************************************************
** The main bit :) If it gets to the end of here, delivery was successful
******************************************************************************/
int main(int argc, char *argv[])
{
	struct passwd *pw_data;
	char *deliverto;
	char bounce[1024];
	char prefix[1024];

	opensyslog("vdelivermail");
	hmm ("Delivering email for %s-%s@%s",getenv("USER"),getenv("EXT"),getenv("HOST"));

	if (argc > 3) {
		failtemp ("Syntax: %s [prefix [bounceable_mail]]\n",argv[0]);
	}

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
		hmm ("POP user does not exist, but will deliver to %s\n",bounce);
		deliverto = bounce;
	} else {
		deliverto = pw_data->pw_dir;
	}

	deliver_mail(deliverto);
	
	puts ("vdelivermail: done");
	exit (0);
}
