/*****************************************************************************
**
** $Id: common.h,v 1.1 1999/02/21 13:25:33 chris Exp $
** Header file for common routines
**
** Chris Johnson, Copyright (C) July 1998
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

#include <pwd.h>

#ifndef POPUSER
#define POPUSER "vpopmail"
#endif

extern int usesyslog;

void opensyslog (char *);
void logme (char *);
void hmm (char *,...);
void ack (int,char *,...);
void yikes (int,int,char *,...);
struct passwd *vgetpw(char *, char*, struct passwd *,int);
