/*****************************************************************************
**
** $Id: vchkaccess.c,v 1.3 1998/06/23 19:32:51 chris Exp $
** Vchkaccess -- Part of the CGI package for virtual domain admin.
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

/***************************************************************************
** No user servicable parts below
***************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <dirent.h>
#include <pwd.h>
#include "safestring.h"

static char rcsid[] = "$Id: vchkaccess.c,v 1.3 1998/06/23 19:32:51 chris Exp $";

char buf[200];
char VPOPROOT[NAME_MAX];

void ack(char *message, int die)
{
	printf ("%d: %s: %s\n",die,message,buf);
	fflush(stdout);
	_exit(die);
}

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

char *mkpasswd(char *passwd)
{
	static char pw[20];
	char salt[3];
	time_t tm;

        time(&tm);
        srandom (tm % 65536);

	bzero(pw,sizeof(pw));
	salt[0] = randltr();
	salt[1] = randltr();
	salt[2] = 0;

	scopy (pw, crypt(passwd,salt), sizeof(pw));

	return pw;
}

void gotodomain(char *domain)
{
	if (chdir (VPOPROOT) == -1) ack("Failed to cd to pop root",101);
	if (chdir ("domains") == -1) ack("Failed to cd to domains",102);
	if (chdir (domain) == -1) ack("Failed to cd to domain home",103);
}

void mklink()
{
	if (unlink ("vpasswd") == -1) ack("Failed to remove old passwd file",201);
	if (link ("vpasswd.new","vpasswd") == -1) ack("Failed to link new passwd file",202);
	if (unlink ("vpasswd.new") == -1) ack("Failed to remove passwd template",203);
}

void delfiles (char *dir)
{
	struct dirent **namelist;
	int n;

	if (chdir(dir) == -1) ack("Failed to cd to directory",301);
	n = scandir(".", &namelist, 0, alphasort);
	if (n < 0) ack ("Failed to scandir()",302);

#ifdef DEBUG
		fprintf(stderr,"delfiles: chdir to %s okay\n",dir);
#endif

	while(n--) {
#ifdef DEBUG
		fprintf(stderr,"delfiles: Deleting %s\n",namelist[n]->d_name);
#endif
		if (unlink(namelist[n]->d_name) == -1) {
			if (strcmp(namelist[n]->d_name,".") && strcmp(namelist[n]->d_name,".."))
				ack ("Failed to delete directory",303);
		}
	}
	if (chdir("..") == -1) ack("Failed to cd to parent",304);
	if (rmdir(dir) == -1) ack("Failed to remote directory",305);
}

void verify(char *info)
{
	FILE *pwfile;
	char *user, *domain, *pass;
	struct passwd *pw;
	int i,apop = 3;
	
#ifdef DEBUG
	fprintf (stderr,"verify: On entry: %s\n",info);
#endif

	user = info;
	for (i=0; info[i]!=':'; i++) /* nowt */; info[i]=0; i++; domain=&info[i];
	for (; info[i]!=':'; i++)  /*nowt */; info[i]=0; i++; pass=&info[i];

#ifdef DEBUG
	fprintf (stderr,"verify: Info is: %s -- %s -- %s\n",user,domain,pass);
#endif

	gotodomain(domain);
	if ((pwfile=fopen("vpasswd","r")) == NULL) ack("Failed to open passwd file",51);
	pw = fgetpwent(pwfile);
	while ((pw!=NULL) && strcmp(user,pw->pw_name)) {
		pw = fgetpwent(pwfile);
	}
	fclose(pwfile);

	if (pw == NULL) ack ("Failed to verify: user does not exist",52);
#ifdef DEBUG
	fprintf (stderr,"verify: Comparing %s and %s\n",pass,pw->pw_passwd);
#endif
	if (pw->pw_uid != 1) {
		if (strcmp(pw->pw_passwd,pass)) {
			apop = 1;
		} else {
			apop = 0;
		}
	}
			
	if (apop && (pw->pw_uid != 2)) {
		if (strcmp(pw->pw_passwd,crypt(pass,pw->pw_passwd))) {
			apop = 2;
		} else {
			apop = 0;
		}
	}

	if (apop) {
		if (apop == 1) ack("Failed to verify: secrets do not match",53);
		if (apop == 2) ack("Failed to verify: passwords do not match",54);
		ack("Failed to verify: unknown error",55);
	}
	puts ("ok");
	fflush (stdout);
}

void getusers(char *domain)
{
	FILE *fpwd;
	int i,j;
	char pwline[500];
	char userlist[16384];

	gotodomain(domain);
	
	if ((fpwd=fopen("vpasswd","r")) == NULL) ack("Failed to open passwd file",14);

	j=0;
	fgets(pwline,sizeof(pwline),fpwd);
	while (!feof(fpwd)) {
		i=0;
		while (pwline[i] != ':') {
			userlist[j++] = pwline[i++];
			if (j > sizeof(userlist)) ack("List size larger than buffer size",15);
		}
		userlist[j++] = ':';
		fgets(pwline,sizeof(pwline),fpwd);
	}
	fclose (fpwd);

	userlist[j-1] = '\0';
	write(fileno(stdout),userlist,j);
	fflush(stdout);
}

void chpass(char *info)
{
	FILE *fpwd,*npwd;
	char *user, *domain, *newpw, *type;
	char *pwuser,*pwpw,*pwuid,*pwrest;
	char line[500], temp[500];
	int i;

	bzero(line,sizeof(line));
	bzero(temp,sizeof(temp));

#ifdef DEBUG
	fprintf (stderr,"chpass: On entry: %s\n",info);
#endif
	user = info;
	for (i=0; info[i]!=':'; i++) /* nowt */; info[i]=0; i++; domain=&info[i];
	for (; info[i]!=':'; i++)  /*nowt */; info[i]=0; i++; newpw=&info[i];
	for (; info[i]!=':'; i++) /* nowt */; info[i]=0; i++; type=&info[i];
	
#ifdef DEBUG
	fprintf (stderr,"chpass: Info is: %s -- %s -- %s -- %s\n",user,domain,newpw,type);
#endif

	gotodomain(domain);
	if ((fpwd=fopen("vpasswd","r")) == NULL) ack("Failed to open passwd file",21); 
	if ((npwd=fopen("vpasswd.new","w")) == NULL) ack("Failed to create new passwd file",22); 

	fgets(line,sizeof(line),fpwd);
	while (!feof(fpwd)) {
		if (strstr(line,user) == line) {
#ifdef DEBUG
			fprintf (stderr,"chpass: found user %s\n",user);
#endif
			pwuser = line;
			for (i=0; line[i] != ':'; i++) /* nowt */; line[i] = 0;
			i++; pwpw = &line[i];
			for (; line[i] != ':'; i++) /* nowt */; line[i] = 0;
			i++; pwuid = &line[i];
			for (; line[i] != ':'; i++) /* nowt */; line[i] = 0;
			i++; pwrest = &line[i];

#ifdef DEBUG
			fprintf(stderr,"chpass: %s, %s, %s, %s\n",pwuser,pwpw,pwuid,pwrest);
#endif
			bzero(temp,sizeof(temp));
			scopy(temp,pwuser,sizeof(temp)); scat(temp,":",sizeof(temp));
			if (atoi(pwuid) < 2) {
				scat(temp,mkpasswd(newpw),sizeof(temp));
			} else {
				scat(temp,newpw,sizeof(temp));
			}
			scat(temp,":",sizeof(temp));
#ifdef DEBUG
			fprintf (stderr,"chpass: about to check type\n");
#endif
			if (atoi(type) == 0) {
#ifdef DEBUG
				fprintf (stderr,"chpass: keeping default info: %s\n",pwuid);
#endif
				scat(temp,pwuid,sizeof(temp));
			} else {
#ifdef DEBUG
				fprintf (stderr,"chpass: this is an APOP user\n");
#endif
				scat(temp,type,sizeof(temp));
			}
			scat(temp,":",sizeof(temp));
			scat(temp,pwrest,sizeof(temp));
			scopy(line,temp,sizeof(line));
		}
#ifdef DEBUG
		fprintf (stderr,"chpass: pwline: %s\n",line);
#endif
		fputs (line,npwd);
		fgets(line,sizeof(line),fpwd);
	}
	fclose (npwd); fclose(fpwd);
	mklink();
	puts ("ok");
	fflush(stdout);
}

void adduser (char *info)
{
	FILE *fpwd,*npwd;
	char *user, *domain, *newpw, *type;
	char line[500], temp[500], pw[50];
	int i;

	bzero(line,sizeof(line));
	bzero(temp,sizeof(temp));
	bzero(pw,sizeof(pw));

#ifdef DEBUG
	fprintf (stderr,"adduser: On entry: %s\n",info);
#endif
	user = info;
	for (i=0; info[i]!=':'; i++) /* nowt */; info[i]=0; i++; domain=&info[i];
	for (; info[i]!=':'; i++)  /*nowt */; info[i]=0; i++; newpw=&info[i];
	for (; info[i]!=':'; i++) /* nowt */; info[i]=0; i++; type=&info[i];
	
#ifdef DEBUG
	fprintf (stderr,"adduser: Info is: %s -- %s -- %s -- %s\n",user,domain,newpw, type);
#endif

	gotodomain(domain);

	if (mkdir(user,448) == -1) ack("Failed to mkdir user directory",33);
	if (chdir(user) == -1) ack("Failed to cd to user directory",34);
	if (mkdir("Maildir",448) == -1) ack("Failed to mkdir Maildir",35);
	if (chdir("Maildir") == -1) ack("Failed to cd to Maildir",36);
	if (mkdir("cur",448) == -1) ack("Failed to mkdir Maildir component",37);
	if (mkdir("new",448) == -1) ack("Failed to mkdir Maildir component",37);
	if (mkdir("tmp",448) == -1) ack("Failed to mkdir Maildir component",37);

	gotodomain(domain);

	if ((fpwd=fopen("vpasswd","r")) == NULL) ack("Failed to open passwd file",31); 
	if ((npwd=fopen("vpasswd.new","w")) == NULL) ack("Failed to create new passwd file",32); 

	fgets(line,sizeof(line),fpwd);
	while (!feof(fpwd)) {
		fputs (line,npwd);
		fgets(line,sizeof(line),fpwd);
	}
	if (atoi(type) < 2) {
		scopy(pw,mkpasswd(newpw),sizeof(pw));
	} else {
		scopy(pw,newpw,sizeof(pw));
	}
	fprintf(npwd,"%s:%s:%s::Pop User by CGI:%s/domains/%s/%s:NOLOGIN\n",user,pw,type,VPOPROOT,domain,user);
	fclose (npwd); fclose(fpwd);
	mklink();
	puts ("ok");
	fflush(stdout);
}
	
void deluser(char *info)
{
	FILE *fpwd,*npwd;
	char *user, *domain;
	char line[500];
	int i;

	bzero(line,sizeof(line));

#ifdef DEBUG
	fprintf (stderr,"deluser: On entry: %s\n",info);
#endif
	user = info;
	for (i=0; info[i]!=':'; i++) /* nowt */; info[i]=0; i++; domain=&info[i];
	
#ifdef DEBUG
	fprintf (stderr,"deluser: Info is: %s -- %s \n",user,domain);
#endif

	gotodomain(domain);

	if ((fpwd=fopen("vpasswd","r")) == NULL) ack("Failed to open passwd file",41); 
	if ((npwd=fopen("vpasswd.new","w")) == NULL) ack("Failed to create new passwd file",42); 

	fgets(line,sizeof(line),fpwd);
	while (!feof(fpwd)) {
		if (strstr(line,user) != line) {
#ifdef DEBUG
			fprintf (stderr,"deluser: Copying user %s\n",line);
#endif
			fputs (line,npwd);
		}
		fgets(line,sizeof(line),fpwd);
	}
	fclose (npwd); fclose(fpwd);
	mklink();

#ifdef DEBUG
	fprintf (stderr,"deluser: about to cd to %s\n",user);
#endif
	if (chdir(user) == -1) ack ("Failed to cd to user directory",43);
	if (chdir("Maildir") == -1) ack ("Failed to cd to Maildir",44);
	delfiles("new");
	delfiles("cur");
	delfiles("tmp");
	if (chdir("..") == -1) ack ("Failed to cd to .. (Maildir)",45);
	if (rmdir("Maildir") == -1) ack ("Failed to delete Maildir",46);
	if (chdir("..") == -1) ack ("Failed to cd to .. (user)",47);
	if (rmdir(user) == -1) ack ("Failed to delete user dir",48);

	puts ("ok");
	fflush(stdout);
}

void checklimit(char *info)
{
	FILE *flimit;
	int i, cur_lim, num_users; 
	char *lim, *domain;
	char line[20];

	bzero(line,sizeof(line));

	lim = info;
	for (i=0; info[i]!=':'; i++) /* nowt */; info[i]=0; i++; domain=&info[i];

	gotodomain(domain);

	if ((flimit=fopen("LIMIT","r")) == NULL) ack ("Failed to open LIMIT",50);
	fgets(line,sizeof(line),flimit);
	fclose(flimit);

	cur_lim = atoi(line);
	num_users = atoi(lim);

	if (cur_lim == 0) {
		puts ("ok");
		fflush (stdout);
		return;
	}

	if (num_users < cur_lim) {
		puts ("ok");
		fflush (stdout);
		return;
	}

	printf ("%d\n",cur_lim);
	fflush (stdout);
}

int main()
{
	FILE *ck;
	char cookie[50];
	int len,i;
	struct passwd *vp;

	umask(63);	/** Octal 077 **/

	bzero(VPOPROOT,sizeof(VPOPROOT));
	if ((vp=getpwnam(VPOPUSER)) == NULL) ack("Virtual pop user does not exist",6);
	scopy(VPOPROOT,vp->pw_dir,sizeof(VPOPROOT));

#ifdef DEBUG
	fprintf (stderr,"main: got vpoproot: %s\n",VPOPROOT);
#endif

	do {
		len = read (fileno(stdin), buf, sizeof(buf));
	} while ((len == -1) && (errno == EINTR));

	if (len == -1)
		ack("Failed to read stdin",1);

	len = 0;
	while (buf[len] >= ' ')
		len++;
	buf[len]='\0';

#ifdef DEBUG
	fprintf (stderr,"main: read from stdin: %s\n",buf);
#endif

	if (buf[0] != 'v') {
		bzero(cookie,sizeof(cookie));
		for (i=1; buf[i] != ':'; i++) cookie[i-1] = buf[i];

#ifdef DEBUG
		fprintf (stderr,"main: got cookie: %s\n",cookie);
#endif
		if (chdir(CGIROOT) == -1) ack("Failed to cd to CGI root",2);
		if (chdir("cookies") == -1) ack("Failed to cd to cookie jar",3);
		if ((ck = fopen(cookie,"r")) == NULL) ack("Failed to check cookie",4);
		fclose(ck);
#ifdef DEBUG
		fprintf (stderr,"main: cookie check passed\n");
#endif
		i++;
	} else {
#ifdef DEBUG
		fprintf (stderr,"main: password verification\n");
#endif
		i=1;
	}

	switch (buf[0]) {
		case 'v': verify(&buf[i]); break;
		case 'u': getusers(&buf[i]); break;
		case 'p': chpass(&buf[i]); break;
		case 'a': adduser(&buf[i]); break;
		case 'd': deluser(&buf[i]); break;
		case 'l': checklimit(&buf[i]); break;
		default:  ack("Unrecognised",5);
	}
#ifdef DEBUG
	fputs ("main: about to exit\n",stderr);
#endif
	_exit(0);
}
