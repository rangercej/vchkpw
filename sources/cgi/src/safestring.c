/*****************************************************************************
**
** $Id: safestring.c,v 1.1 1998/06/16 21:23:04 chris Exp $
** Replacements for strcpy() and strcat() that ensure bounds checking.
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
******************************************************************************
**
** Both of these will return -1 if the bound is reached. These functions will
** always put the last character of the string to 0, so the string length
** cannot be exceeded.
**
*****************************************************************************/

static char rcsid[] = "$Id: safestring.c,v 1.1 1998/06/16 21:23:04 chris Exp $";

int scopy(char *dest, const char *src, const int bound)
{
	int i;
	for (i=0; (src[i] != 0) && (i < (bound-1)); i++) {
		dest[i] = src[i];
	}
	dest[i] = 0;

	if (i >= bound) {
		return -1;
	}
	return 0;
}

int scat(char *dest, const char *src, const int bound)
{
	int i,j;
	for (i=0; dest[i] != 0; i++) /* nowt */;
	for (j=0; (src[j] != 0) && ((i+j) < (bound-1)); j++) {
		dest[i+j] = src[j];
	}
	dest[i+j] = 0;

	if ((i+j) >= (bound-1)) {
		return -1;
	}
	return 0;
}
