/******************************************************************************
**
** vchkpw.c - Chris Johnson, Jan 1998
**
** This program is based on Dan Bernstein's checkpassword package for qmail.
**
** The big change: support for virtual users in a virtual user password file.
**
*****************************************************************************/

#include <errno.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#ifdef PW_SHADOW
#include <shadow.h>
#endif
#ifdef AIX
#include <userpw.h>
#endif

#ifndef POPUSER
#define POPUSER "vpopmail"
#endif

#ifndef ATCHARS
#define ATCHARS "@%_"
#endif

extern int errno;
extern char *crypt();
extern char *malloc();
extern char **environ;

char up[513];
int uplen;

char *str1e2(name,value) char *name; char *value;
{
	char *nv;
	nv = malloc(strlen(name) + strlen(value) + 2);
	if (!nv) _exit(111);
	strcpy(nv,name);
	strcat(nv,"=");
	strcat(nv,value);
	return nv;
}

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

	strcpy(file,pophome);
	strcat(file,"/domains/");
	strcat(file,host);
	strcat(file,"/vpasswd");
	if (stat (file, &info) == -1) {
		strcpy(file,pophome);
		strcat(file,"/vpasswd");
	}

	return file;
}

struct passwd *checkpopusers(char *login, char *passwd)
{
	static struct passwd *popacct;
	struct passwd *retval = NULL;
	char pwfile[255];
	char host[100];
	char *encrypted;
	int i,gid,uid;
	FILE *poppwfile;

	popacct=getpwnam(POPUSER);
	if (!popacct) {
		retval = NULL;
	} else {
		uid = popacct->pw_uid;
		gid = popacct->pw_gid;
		strcpy (host,get_user_domain(login));
		strcpy (pwfile,which_file(host,popacct->pw_dir));
		if ((poppwfile=fopen(pwfile,"r")) == NULL) {
			retval = NULL;
		} else {
			popacct = fgetpwent(poppwfile);
			while (!feof(poppwfile) && strcmp(popacct->pw_name,login)) {
				popacct = fgetpwent(poppwfile);
			}
			if (feof(poppwfile)) {
				retval = NULL;
			} else {
				encrypted = crypt(passwd,popacct->pw_passwd);
				for (i = 0; i < sizeof(up); ++i) up[i] = 0;
				if (!*popacct->pw_passwd || strcmp(encrypted,popacct->pw_passwd)) {
					retval = NULL;
				} else {
					popacct->pw_uid = uid;
					popacct->pw_gid = gid;
					retval = popacct;
				}
			}
			fclose(poppwfile);
		}
	}
	return retval;
}

struct passwd *check_dot_qmail(struct passwd *useracct)
{
	static struct passwd qmailacct;
	static struct passwd *retval = NULL;
	static char mdir[1024];
	char fname[1024];
	char line[1024];
	int i,linelen;
	FILE *qmail;

	bcopy(useracct,&qmailacct,sizeof (struct passwd));

	strcpy(fname,useracct->pw_dir);
	strcat(fname,"/.qmail");
	if ((qmail=fopen(fname,"r")) != NULL) {
		fgets(line,sizeof(line),qmail);
		while (!feof(qmail)) {
			for (i=0; line[i] >= ' '; i++);
			line[i] = 0;
			linelen = strlen(line) - 1;
			if (linelen > 0) {
				for (i=linelen-1; line[i] != '/'; i--);
				if (line[linelen]=='/') {
					line[i+1]=0;
					if (line[0] == '.') {
						strcpy(mdir,useracct->pw_dir);
						strcat(mdir,line+1);
						qmailacct.pw_dir = mdir;
					} else {
						strcpy(mdir,line);
						qmailacct.pw_dir = mdir;
					}
				}
			}
			fgets(line,sizeof(line),qmail);
		}
		retval = &qmailacct;
	} else {
		retval = useracct;
	}
	return retval;
}

void main(argc,argv)
int argc;
char **argv;
{
	struct passwd *pw,*pw2;
#ifdef PW_SHADOW
	struct spwd *spw;
#endif
#ifdef AIX
	struct userpw *spw;
#endif
	char *login;
	char *password;
	char *stored;
	char *encrypted;
	int r;
	int i;
	char **newenv;
	int numenv;

	if (!argv[1]) _exit(2);

	uplen = 0;
	for (;;)
		{
		 do
			r = read(3,up + uplen,sizeof(up) - uplen);
		 while ((r == -1) && (errno == EINTR));
		 if (r == -1) _exit(111);
		 if (r == 0) break;
		 uplen += r;
		 if (uplen >= sizeof(up)) _exit(1);
		}

	close(3);

	i = 0;
	login = up + i;
	while (up[i++]) if (i == uplen) _exit(2);
	password = up + i;
	if (i == uplen) _exit(2);
	while (up[i++]) if (i == uplen) _exit(2);

	pw = getpwnam(login);
	if (!pw) {		 /* XXX: unfortunately getpwnam() hides temporary errors */
		if ((pw=checkpopusers(login,password))==NULL)
			_exit(1);
	} else {
#ifdef PW_SHADOW
		spw = getspnam(login);
		if (!spw) _exit(1); /* XXX: again, temp hidden */
		stored = spw->sp_pwdp;
#else
#ifdef AIX
		spw = getuserpw(login);
		if (!spw) _exit(1); /* XXX: and again */
		stored = spw->upw_passwd;
#else
		stored = pw->pw_passwd;
#endif
#endif

		encrypted = crypt(password,stored);

		for (i = 0;i < sizeof(up);++i) up[i] = 0;

		if (!*stored || strcmp(encrypted,stored)) _exit(1);

		pw2=check_dot_qmail(pw);
		pw=pw2;
	}

	if (setgid(pw->pw_gid) == -1) _exit(1);
	if (setuid(pw->pw_uid) == -1) _exit(1);
	if (chdir(pw->pw_dir) == -1) _exit(111);

	numenv = 0;
	while (environ[numenv]) ++numenv;
	newenv = (char **) malloc((numenv + 4) * sizeof(char *));
	if (!newenv) _exit(111);
	for (i = 0;i < numenv;++i) newenv[i] = environ[i];
	newenv[numenv++] = str1e2("USER",pw->pw_name);
	newenv[numenv++] = str1e2("HOME",pw->pw_dir);
	newenv[numenv++] = str1e2("SHELL",pw->pw_shell);
	newenv[numenv] = 0;
	environ = newenv;

	execvp(argv[1],argv + 1);
	_exit(111);
}
