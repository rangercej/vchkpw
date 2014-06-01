/*****************************************************************************
**
** $Id: safestring.c,v 1.5 1999/06/21 18:03:34 chris Exp $
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
** scopy   == strcpy() with bounds checking
** scat    == strcat() with bounds checking
** slen    == strlen()
** smatch  == strcmp()
**
*****************************************************************************/

const static char rcsid[] = "$Id: safestring.c,v 1.5 1999/06/21 18:03:34 chris Exp $";

int scopy(char *dest, const char *src, const int bound)
{
	int i;

	if (!dest || !src)
		return -1;

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
	for (i=0; (dest[i] != 0) && (i < bound); i++) /* nowt */;
	for (j=0; (src[j] != 0) && ((i+j) < (bound-1)); j++) {
		if ((i+j) < bound)
			dest[i+j] = src[j];
	}
	dest[i+j] = 0;

	if ((i+j) >= (bound-1)) {
		dest[bound-1] = 0;
		return -1;
	}

	dest[i+j] = 0;

	return 0;
}

unsigned long slen(const char *src)
{
	int i;
	for (i=0; src[i] != 0; i++) /* do nowt */;
	return i;
}

int smatch(const char *s1, const char *s2)
{
	int i;
	for (i=0; s1[i] != 0; i++)
		if (s1[i] != s2[i])
			return 0;

	if (s1[i] != s2[i])
		return 0;

	return 1;
}
