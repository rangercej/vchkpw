/*****************************************************************************
**
** $Id: vchkexpire.c,v 1.1 1998/06/16 21:23:04 chris Exp $
** Expire cookies - part of the vchkpw CGI
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
#include <dirent.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>

#ifndef TIMEOUT
#define TIMEOUT 20
#endif

#ifndef CGIROOT
#error --------------------------------------------------------
#error Urk...CGIROOT is not defined. Check the Makefile!
#error --------------------------------------------------------
#endif

#define ack(x,y) { fputs(x,stderr); fputs("\n",stderr); _exit(y); }
#define ick(x) { fputs(x,stderr); }

static char rcsid[] = "$Id: vchkexpire.c,v 1.1 1998/06/16 21:23:04 chris Exp $";

int main()
{
	const time_t secs = TIMEOUT * 60;
	struct dirent **file;
	struct stat details;
	int i;
	time_t tm;

	if (chdir(CGIROOT) == -1) ack ("Could not cd to CGIROOT",1);
	if (chdir("cookies") == -1) ack ("Could not open cookie jar",2);

	time(&tm);
	tm=tm-secs;

	i = scandir(".", &file, 0, alphasort);
	if (i < 0) ack ("Error in scandir()",3);

	while (i--) {
		stat(file[i]->d_name, &details);
		if (details.st_mtime < tm) {
			if (unlink(file[i]->d_name)) {
				ick ("Unlink of ");
				ick (file[i]->d_name);
				ick ("failed");
			}
		}
	}
	return 0;
}
