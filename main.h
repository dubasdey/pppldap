/*
*   main.h
*   LDAP plugin for pppd
*
*	This file is part of ppp_ldap.
*
*    ppp_ldap is free software: you can redistribute it and/or modify
*    it under the terms of the GNU General Public License as published by
*    the Free Software Foundation, either version 3 of the License, or
*    (at your option) any later version.
*
*    ppp_ldap is distributed in the hope that it will be useful,
*    but WITHOUT ANY WARRANTY; without even the implied warranty of
*    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*    GNU General Public License for more details.
*
*    You should have received a copy of the GNU General Public License
*    along with ppp_ldap.  If not, see <http://www.gnu.org/licenses/>.
*/

#define MAX_BUF	1024
#define SEARCH_TIMEOUT 20
#define LDAP_ATTR_DIALUPACCESS 	"dialupAccess"
#define LDAP_FILT_MAXSIZ  1024

struct ldap_data {
        int			maxconnect; 		/* maximum connect time in sec */
        int			maxoctets; 			/* maximum number of octets, reserved */
        int			maxoctets_dir; 		/* limit direction, reserved */
        int			idle_time_limit; 	/* connection idle timeout in sec */
        int			mru; 				/* Maximum recieve unit, reserved  */
        u_int32_t	addr; 				/* peer's IP address in network format */
        bool		access_ok; 			/* 1 if username/password pair correct */
        bool		address_set; 		/* 1 if addr contains value */
        bool		rebind; 			/* set to 1, reserved */
};



/* plugin main functions */
static int  ldap_setoptions(LDAP *ld, LDAPMessage *mesg,struct ldap_data *ldap_data);

/* PAP Auth */
static int  ldap_pap_auth(char *user, char *password, char **msgp, struct wordlist **paddrs, struct wordlist **popts);
static int  ldap_pap_check();

/* IP allow*/
static void ldap_ip_choose(u_int32_t *addrp);
static int ldap_address_allowed(u_int32_t addr);

/* function to autenticate on LDAP with the user and password*/
static int ldap_auth(char *user, char *password);
