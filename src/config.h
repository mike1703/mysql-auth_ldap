/***************************************************************************
 *   Copyright (C) 2012 Infoscope Hellas, L.P.                             *
 *   Author: Charalampos Serenis serenis@dev.infoscope.gr                  *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.               *
 ***************************************************************************/

#include "options.h"

#define AUTH_LDAP_URI               "ldap://localhost:389"
#define AUTH_LDAP_BASE_DN           "ou=People,dc=infoscope,dc=gr"
// search levels. possible values base,one,subtree
#define AUTH_LDAP_LEVEL             "base"
#define AUTH_LDAP_OPENLDAP_SO       "/usr/lib64/libldap.so"

//
// Error logging level.
//
// Posible values:
// 	AUTH_LDAP_ERROR,
// 	AUTH_LDAP_INFO,
// 	AUTH_LDAP_DEBUG,
// 	AUTH_LDAP_DEVEL
//
//+====================================================================+
//|                            !Caution!                               |
//+====================================================================+
//
// Error loging should never be set to development when compiling the
// plugin for deployment in a production system. Having the macro set to
// development will leed in sensitive authentication credentials being
// logged in the system in plain text. Any user having access to these
// logs will be able to read user passwords!
//
#define AUTH_LDAP_ERROR_LEVEL       AUTH_LDAP_DEBUG
