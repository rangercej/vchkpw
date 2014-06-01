/*****************************************************************************
**
** $Id: vchkexpire.c,v 1.4 1999/04/07 20:34:26 chris Exp $
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
#include <sys/types.h>

#ifndef TIMEOUT
#define TIMEOUT 20
#endif

#ifndef CGIROOT
#error --------------------------------------------------------
#error Urk...CGIROOT is not defined. Check the Makefile!
#error --------------------------------------------------------
#endif

#define ack(x,y) { fputs(x,stderr); fputs("\n",stderr); exit(y); }
#define ick(x) { fputs(x,stderr); }

const static char rcsid[] = "$Id: vchkexpire.c,v 1.4 1999/04/07 20:34:26 chris Exp $";

int main()
{
	const time_t secs = TIMEOUT * 60;
	DIR *dir;
	struct dirent *file;
	struct stat details;
	time_t tm;

	if (chdir(CGIROOT) == -1) ack ("Could not cd to CGIROOT",1);
	if (chdir("cookies") == -1) ack ("Could not open cookie jar",2);

	time(&tm);
	tm=tm-secs;

	if ((dir = opendir(".")) == NULL) {
		ack ("Yikes! Could not open cookie jar for reading.",3);
	}

	while ((file = readdir(dir)) != NULL) {
		stat(file->d_name, &details);
		if ((details.st_mtime < tm) && (S_ISREG (details.st_mode))) {
			if (unlink(file->d_name)) {
				ick ("Unlink of ");
				ick (file->d_name);
				ick ("failed");
			}
		}
	}
	closedir(dir);

	return 0;
}
