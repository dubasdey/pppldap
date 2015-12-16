/*
*   main.c
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

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/fcntl.h>
#include <netinet/in.h>
#include <ldap.h>

#include <pppd/pppd.h>
#include <pppd/fsm.h>
#include <pppd/ipcp.h>
#include <pppd/lcp.h>

#include "main.h"

//char pppd_version[] = VERSION;

static char rcsid[] = "$Id: main.c, v 0.13 2011/08/30 14:45:00 erodriguez Exp$";
static char ldap_host[MAX_BUF] = "localhost";
static int  ldap_port = LDAP_PORT;
static char ldap_dn[MAX_BUF];
static char ldap_pw[MAX_BUF];

static char userbasedn[MAX_BUF];
static char ldap_filter[MAX_BUF]="&(uid=%s)";

static int	ldap_timeout = 15;
static int	ldap_nettimeout = 10;
static bool	ldap_usetls = 0;


static struct ldap_data ldap_data;
//static struct chap_digest_type chap_digest_type;

static option_t ldap_options[] = {
	{ "ldaphost", 		o_string, 	ldap_host,
			"LDAP server host name",				OPT_PRIV | OPT_STATIC, NULL, (MAX_BUF - 1) },
	{ "ldapdn", 		o_string, 	ldap_dn,
			"DN to bind with to LDAP server",		OPT_PRIV | OPT_STATIC, NULL, (MAX_BUF - 1) },
	{ "ldappw", 		o_string, 	ldap_pw,
			"DN password",							OPT_PRIV | OPT_STATIC, NULL, (MAX_BUF - 1) },
	{ "ldapport", 		o_int, 		&ldap_port,
			"LDAP server port",						OPT_PRIV | OPT_STATIC },
	{ "userbasedn", 	o_string,	userbasedn ,
			"LDAP user base DN",					OPT_PRIV | OPT_STATIC, NULL, (MAX_BUF - 1) },
	{ "ldapfilter", 	o_string, 	ldap_filter,
			"LDAP filter"      ,					OPT_PRIV | OPT_STATIC, NULL, (MAX_BUF - 1) },
	{ "ldaptimeout", 	o_int, 		&ldap_timeout,
			"LDAP search timeout",					OPT_PRIV | OPT_STATIC },
	{ "ldapnettimeout", o_int, 		&ldap_nettimeout,
			"LDAP network activity timeout",		OPT_PRIV | OPT_STATIC },
	{ "ldapusetls", 	o_bool, 	&ldap_usetls,
			"Connect to LDAP server using TLS", 1 },
	{ NULL }
};

int plugin_init(){

	/* Add options*/
	add_options(ldap_options);

	/* PAP Hooks*/
	pap_check_hook = ldap_pap_check;
	pap_auth_hook  = ldap_pap_auth;

	/* To check ip allows */
	ip_choose_hook = ldap_ip_choose;
	allowed_address_hook = ldap_address_allowed;

	info("LDAP: plugin initialized. PAP Enabled");
}

/* to enable LDAP PAP */
static int ldap_pap_check(){
   return 1;
}


/* check IP */
static void ldap_ip_choose(u_int32_t *addrp) {
	if (ldap_data.address_set){
		*addrp = ldap_data.addr;
	}
}

/* check if IP is allowed */
static int ldap_address_allowed(u_int32_t addr) {

	if (ntohl(addr) == ldap_data.addr) {
		return 1;
	}

	/* if peer's address was specified in options allow it */
	if ((ipcp_wantoptions[0].hisaddr != 0) && (ipcp_wantoptions[0].hisaddr == addr)) {
		return 1;
	}

	return 0;
}

/* Perform PAP auth*/
static int ldap_pap_auth(char *user, char *password, char **msgp, struct wordlist **paddrs, struct wordlist **popts) {
	info("LDAP: Starting PAP authentication");
	return ldap_auth(user,password);
}



/* function to perform user check on LDAP */
static int ldap_auth (char *user, char *password) {

	info("LDAP: (ldap_auth)");

	int rc;
	int ldap_errno;
	LDAP *ldap;


	// Initiate session and bind to LDAP server
	info("LDAP: (ldap_auth - init)");
	if ( (ldap = ldap_init(ldap_host, ldap_port)) == NULL) {
		error("LDAP: failed to initialize session\n");
		return -1;
	}

	// Set LDAP specific options such as timeout, version and tls
	info("LDAP: (ldap_auth - set version to LDAP3)");
	int ldap_version =  LDAP_VERSION3;
	if (  (rc = ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION, &ldap_version)) != LDAP_OPT_SUCCESS) {
		error("LDAP: failed to set protocol version\n");
		return -1;
	}

	info("LDAP: (ldap_auth - set timeout)");
	if ( (rc = ldap_set_option(ldap, LDAP_OPT_NETWORK_TIMEOUT, &ldap_nettimeout)) != LDAP_OPT_SUCCESS) {
		error("LDAP: failed to set network timeout version\n");
		return -1;
	}

	info("LDAP: (ldap_auth - set time limit)");
	if ( (rc = ldap_set_option(ldap, LDAP_OPT_TIMELIMIT, &ldap_timeout)) != LDAP_OPT_SUCCESS) {
		error("LDAP: failed to set timeout option\n");
		return -1;
	}

	info("LDAP: (ldap_auth - USETLS)");
	if (ldap_usetls) {
		if (ldap_port == LDAPS_PORT) {
			int tls_opt = LDAP_OPT_X_TLS_HARD;
			if ( (rc = ldap_set_option(ldap, LDAP_OPT_X_TLS, (void *)&tls_opt)) != LDAP_SUCCESS) {
				ldap_get_option(ldap, LDAP_OPT_ERROR_NUMBER, &ldap_errno);
				error("LDAP: failed to set TLS option: %s\n", ldap_err2string(rc));
				return -1;
			}
		}
		info("LDAP: Setting TLS option -> ON\n");
		if( (rc = ldap_start_tls_s(ldap, NULL, NULL)) != LDAP_SUCCESS) {
			ldap_get_option(ldap, LDAP_OPT_ERROR_NUMBER, &ldap_errno);
			error("LDAP: failed to initiate TLS: %s\n", ldap_err2string(ldap_errno));
			return -1;
		}
	}

	/* Perform binding at last */
	info("LDAP: (ldap_auth - BIND)");
	if ( (rc = ldap_bind_s(ldap, ldap_dn, ldap_pw, LDAP_AUTH_SIMPLE)) != LDAP_SUCCESS) {
		ldap_get_option(ldap, LDAP_OPT_ERROR_NUMBER, &ldap_errno);
		error("LDAP: failed to bind: %s\n",ldap_err2string(rc));
		ldap_unbind(ldap);
		return -1;
	}

	info("LDAP: (ldap_auth - BUILD FILTER)");
	char filter[LDAP_FILT_MAXSIZ];
	/* Form a search filter from supplied peer's credentials */
	if ( (rc = snprintf(filter, LDAP_FILT_MAXSIZ,ldap_filter,user)) == -1) {
		error("LDAP: search filter too big: filter %s\n",filter);
		ldap_unbind(ldap);
		return -1;
	}
	info("LDAP: search filter: %s\n",filter);


	/* Perform search*/
	info("LDAP: (ldap_auth - SEARCH)");
	LDAPMessage *ldap_mesg;
	if ( (rc = ldap_search_s(ldap, userbasedn, LDAP_SCOPE_SUBTREE, filter,NULL, 0, &ldap_mesg)) != LDAP_SUCCESS) {
		ldap_get_option(ldap, LDAP_OPT_ERROR_NUMBER, &ldap_errno);
		error("LDAP: Can't perform search: %s\n",ldap_err2string(rc));
		ldap_unbind(ldap);
		return -1;
	};


	/* If search returned more than 2 results or 0 - something is wrong! */
	info("LDAP: (ldap_auth - VALIDATE SEARCH)");
	if ( ldap_mesg == NULL ){
		info("LDAP: No such user \"%s\"\n",user);
		ldap_unbind(ldap);
		return -1;
	}else {
		int entries = ldap_count_entries(ldap, ldap_mesg);
		info("LDAP: found %u entries\n", entries );
		if(entries>1){
			warn("LDAP: more than one user \"%s\" exists!\n",user);
			ldap_unbind(ldap);
			return -1;
		}
	}

	/* Check existance of dialupAccess attribute and it's value */
	LDAPMessage *ldap_entry;
	char **ldap_values;

	info("LDAP: (ldap_auth - AUTHENTICATE)");
	ldap_entry = ldap_first_entry(ldap, ldap_mesg);
	ldap_values = ldap_get_values(ldap, ldap_entry, LDAP_ATTR_DIALUPACCESS);
	if (ldap_values == NULL || strncasecmp(ldap_values[0],"YES",3) == 0 || strncasecmp(ldap_values[0],"FALSE",5) != 0 ) {
		info("LDAP: dialup access enabled for user");

		char userdn[MAX_BUF];
		/* Rebind with peers supplied credentials */
		if ( (rc = snprintf(userdn,MAX_BUF,"%s",ldap_get_dn(ldap,ldap_entry))) == -1){
			warn("LDAP: user DN stripped\n");
		}

		info("LDAP: rebind DN: %s\n",userdn);
		if ( (rc = ldap_simple_bind_s(ldap,userdn,password)) != LDAP_SUCCESS) {
			error("LDAP: username or password incorrect\n");
			ldap_unbind(ldap);
			ldap_msgfree(ldap_mesg);
			return 0;
		}
	} else {
		error("LDAP: dialup access disabled for user");
		ldap_unbind(ldap);
		ldap_msgfree(ldap_mesg);
		return 0;
	}

	info("LDAP: Auth success\n");
	ldap_data.access_ok = 1;
	return 1;
}
