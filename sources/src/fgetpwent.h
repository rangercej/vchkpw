/*****************************************************************************
**
** $Id: fgetpwent.h,v 1.1 1998/06/16 20:56:03 chris Exp $
** Header file for fgetpwent() for systems that do not have the function
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
#include <pwd.h>

struct passwd *fgetpwent(FILE *stream);
