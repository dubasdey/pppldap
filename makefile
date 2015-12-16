# Makefile for PPPD_LDAP plugin
#
#   main.c
#   LDAP plugin for pppd
#
#	This file is part of ppp_ldap.
#
#    ppp_ldap is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    ppp_ldap is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with ppp_ldap.  If not, see <http://www.gnu.org/licenses/>.
#

# Change this with your PPP plugin folder
DESTINATION=/usr/lib/pppd/2.4.5/pppd_ldap.so


# change Here the required dev source folders for ppp and openLDAP
CFLAGS=-I../.. -I../../../include -O2 -fPIC
LDFLAGS=-lldap -lc

get-deps:
	apt-get install libldap2-dev ppp-dev
	#apt-get install make gcc dpkg-dev

build:
	gcc $(CFLAGS) -c -o main.o main.c 				# compile main
	ld -shared -o pppd_ldap.so  main.o $(LDFLAGS) 	# build pppd_ldap.so

install:
	cp pppd_ldap.so $(DESTINATION)					# copy
clean:
	rm *.o *.so *~									# clean compiled files (locals)
	
	