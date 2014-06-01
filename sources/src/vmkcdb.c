/******************************************************************************
**
** $Id: vmkcdb.c,v 1.1 1999/02/21 13:24:54 chris Exp $
** Change a domain's password file to a CDB database
**
** Chris Johnson, July 1998
**
******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/types.h>
#include <cdbmake.h>
#include "safestring.h"
#include "common.h"

const static char rcsid[] = "$Id: vmkcdb.c,v 1.1 1999/02/21 13:24:54 chris Exp $";

int main(int argc, char *argv[])
{
	struct passwd *vpopmail;
	char domain[256];
	char pwline[256];
	char packbuf[8];
	char *key;
	char *data;
	char *ptr;
	int i,j,h;
	int len;
	unsigned long keylen,datalen;
	uint32 pos,op;
	struct cdbmake cdbm;
	FILE *pwfile, *tmfile;

	/*************************************************** Initialisation **/
	if (argc != 2)
		ack (1,"Syntax error: %s <domain>\n",argv[0]);
	if ((vpopmail = getpwnam(POPUSER)) == NULL)
		ack (2,"Error: can't find the POP user (%s) on this system...!\n",POPUSER);
	scopy (domain,vpopmail->pw_dir,sizeof(domain));
	scat (domain,"/domains/",sizeof(domain));
	scat (domain,argv[1],sizeof(domain));
	if (chdir(domain) == -1)
		ack (17,"Error: can't cd to %s\n",domain);
	if ((pwfile = fopen("vpasswd","r")) == NULL)
		ack (3,"Error: can't open password file for domain %s\n",argv[1]);

	cdbmake_init(&cdbm);
	if ((tmfile = fopen("cdb.tmp","w")) == NULL)
		ack (4,"Error: could not create/open temporary file");
	for (i=0; i < sizeof(cdbm.final); i++)
		if (putc(' ',tmfile) == EOF)
			ack (5,"Error: write error writing temp file");
	pos = sizeof(cdbm.final);

	/********************************************************* Creation **/
	fgets(pwline,sizeof(pwline),pwfile);
	while (!feof(pwfile)) {
		key = pwline; ptr = pwline;
		while (*ptr != ':') { ptr++; }
		*ptr = 0; data = ptr; data++;
		while (*ptr != '\n') { ptr++; }
		*ptr = 0;
		keylen = slen(key); datalen = slen(data);
#ifdef DEBUG
		fprintf (stderr,"Got entry: keylen = %lu, key = %s\n           datalen = %lu, data = %s\n",keylen,key,datalen,data);
#endif

		cdbmake_pack(packbuf, (uint32)keylen);
		cdbmake_pack(packbuf + 4, (uint32)datalen);
		if (fwrite(packbuf,1,8,tmfile) < 8)
			ack (6,"Error: write error writing temp file");

		h = CDBMAKE_HASHSTART;
		for (i=0; i < keylen; i++) {
			h = cdbmake_hashadd(h,key[i]);
			if (putc(key[i],tmfile) == EOF)
				ack (19,"Error: write error writing temp file");
		}
		for (i=0; i < datalen; i++) {
			if (putc(data[i],tmfile) == EOF)
				ack (7,"Error: write error writing temp file");
		}
		if (!cdbmake_add(&cdbm,h,pos,malloc))
			ack (8,"Error: out of memory");
		op = pos;
		pos += (uint32)8;
		pos += (uint32)keylen;
		pos += (uint32)datalen;
		if (pos < op)
			ack (9,"Error: too much data");
		if (!cdbmake_split(&cdbm,malloc))
			ack (10,"Error: out of memory");
		fgets(pwline,sizeof(pwline),pwfile);
	}
	fclose(pwfile);

	if (!cdbmake_split(&cdbm,malloc))
		ack (21,"Error: out of memory");

	for (i=0; i < 256; i++) {
		len = cdbmake_throw(&cdbm,pos,i);
		for (j=0; j < len; j++) {
			cdbmake_pack(packbuf,cdbm.hash[j].h);
			cdbmake_pack(packbuf + 4, cdbm.hash[j].p);
			if (fwrite(packbuf,1,8,tmfile) < 8)
				ack (11,"Error: write error writing temp file");
			op = pos;
			pos += (uint32)8;
			if (pos < op)
				ack (12,"Error: too much data");
		}
	}
	if (fflush(tmfile) == EOF)
		ack (20,"Error: write error writing temp file");
	rewind(tmfile);
	if (fwrite(cdbm.final,1,sizeof(cdbm.final),tmfile) < sizeof(cdbm.final))
		ack (13,"Error: write error writing temp file");
	if (fflush(tmfile) == EOF)
		ack (14,"Error: write error writing temp file");
	

	/******************************************************* Demolition **/
	if (fsync(fileno(tmfile)) == -1)
		ack (15,"Error: error with fsync()");
	if (close(fileno(tmfile)) == -1)
		ack (16,"Error: error with close()");
	if (rename("cdb.tmp","vpasswd.cdb"))
		ack (18,"Error: could not rename cdb.tmp to vpasswd.cdb");
	return 0;
}
