/****************************************************************************
**
** $Id: fgetpwent.c,v 1.1 1998/06/16 20:55:12 chris Exp $
** Implementation of SysV fgetpwent()
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
**
****************************************************************************/

#include <pwd.h>
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>

static char rcsid[] = "$Id: fgetpwent.c,v 1.1 1998/06/16 20:55:12 chris Exp $";

struct passwd *fgetpwent(FILE *pw)
{
	static struct passwd pwent;
	static char line[200];
	int i=0,j=0;

	if (fgets(line,sizeof(line),pw) == NULL) {
		return NULL;
	}

	for (i=0; line[i] != 0; i++)
		if (line[i] == ':')
			j++;

	if (j != 6)
		return NULL;

	pwent.pw_name   = strtok(line,":");
	pwent.pw_passwd = strtok(NULL,":");
	pwent.pw_uid    = atoi(strtok(NULL,":"));
	pwent.pw_gid    = atoi(strtok(NULL,":"));
	pwent.pw_gecos  = strtok(NULL,":");
	pwent.pw_dir    = strtok(NULL,":");
	pwent.pw_shell  = strtok(NULL,":");

	return &pwent;
}
