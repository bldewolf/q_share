/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/* LINTLIBRARY */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * nfs security related library routines.
 *
 * Some of the routines in this file are adopted from
 * lib/libnsl/netselect/netselect.c and are modified to be
 * used for accessing /etc/nfssec.conf.
 */

/*
  * HEY HEY HEY *
  This is an abridged version of nfs_sec.c as found at
  https://github.com/illumos/illumos-gate/blob/97adda444bedd8afa322c1d2233957d40bc8e35c/usr/src/cmd/fs.d/nfs/lib/nfs_sec.c
  so that we can use nfs_getseconfig_byname.
*/


/* SVr4.0 1.18	*/

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <syslog.h>
#include <synch.h>
#include <rpc/rpc.h>
#include <nfs/nfs_sec.h>
#include <rpc/rpcsec_gss.h>
#ifdef WNFS_SEC_NEGO
#include "webnfs.h"
#endif

#define	GETBYNAME	1
#define	GETBYNUM	2

/*
 * mapping for /etc/nfssec.conf
 */
struct sc_data {
	char	*string;
	int	value;
};

static struct sc_data sc_service[] = {
	"default",	rpc_gss_svc_default,
	"-",		rpc_gss_svc_none,
	"none",		rpc_gss_svc_none,
	"integrity",	rpc_gss_svc_integrity,
	"privacy",	rpc_gss_svc_privacy,
	NULL,		SC_FAILURE
};

static mutex_t matching_lock = DEFAULTMUTEX;
static char *gettoken(char *, int);
extern	int atoi(const char *str);


extern	bool_t rpc_gss_mech_to_oid(char *, rpc_gss_OID *);
extern	bool_t rpc_gss_qop_to_num(char *, char *, uint_t *);

/*
 *  blank() returns true if the line is a blank line, 0 otherwise
 */
static int
blank(cp)
char *cp;
{
	while (*cp && isspace(*cp)) {
		cp++;
	}
	return (*cp == '\0');
}

/*
 *  comment() returns true if the line is a comment, 0 otherwise.
 */
static int
comment(cp)
char *cp;
{
	while (*cp && isspace(*cp)) {
		cp++;
	}
	return (*cp == '#');
}


/*
 *	getvalue() searches for the given string in the given array,
 *	and returns the integer value associated with the string.
 */
static unsigned long
getvalue(cp, sc_data)
char *cp;
struct sc_data sc_data[];
{
	int i;	/* used to index through the given struct sc_data array */

	for (i = 0; sc_data[i].string; i++) {
		if (strcmp(sc_data[i].string, cp) == 0) {
			break;
		}
	}
	return (sc_data[i].value);
}

/*
 *	shift1left() moves all characters in the string over 1 to
 *	the left.
 */
static void
shift1left(p)
char *p;
{
	for (; *p; p++)
		*p = *(p + 1);
}


/*
 *	gettoken() behaves much like strtok(), except that
 *	it knows about escaped space characters (i.e., space characters
 *	preceeded by a '\' are taken literally).
 *
 *	XXX We should make this MT-hot by making it more like strtok_r().
 */
static char *
gettoken(cp, skip)
char	*cp;
int skip;
{
	static char	*savep;	/* the place where we left off    */
	register char	*p;	/* the beginning of the new token */
	register char	*retp;	/* the token to be returned	  */


	/* Determine if first or subsequent call  */
	p = (cp == NULL)? savep: cp;

	/* Return if no tokens remain.  */
	if (p == 0) {
		return (NULL);
	}

	while (isspace(*p))
		p++;

	if (*p == '\0') {
		return (NULL);
	}

	/*
	 *	Save the location of the token and then skip past it
	 */

	retp = p;
	while (*p) {
		if (isspace(*p))
			if (skip == TRUE) {
				shift1left(p);
				continue;
			} else
				break;
		/*
		 *	Only process the escape of the space separator;
		 *	since the token may contain other separators,
		 *	let the other routines handle the escape of
		 *	specific characters in the token.
		 */

		if (*p == '\\' && *(p + 1) != '\n' && isspace(*(p + 1))) {
			shift1left(p);
		}
		p++;
	}
	if (*p == '\0') {
		savep = 0;	/* indicate this is last token */
	} else {
		*p = '\0';
		savep = ++p;
	}
	return (retp);
}

/*
 *  matchname() parses a line of the /etc/nfssec.conf file
 *  and match the sc_name with the given name.
 *  If there is a match, it fills the information into the given
 *  pointer of the seconfig_t structure.
 *
 *  Returns TRUE if a match is found.
 */
static bool_t
matchname(char *line, char *name, seconfig_t *secp)
{
	char	*tok1,	*tok2;	/* holds a token from the line */
	char	*secname, *gss_mech, *gss_qop; /* pointer to a secmode name */

	if ((secname = gettoken(line, FALSE)) == NULL) {
		/* bad line */
		return (FALSE);
	}

	if (strcmp(secname, name) != 0) {
		return (FALSE);
	}

	tok1 = tok2 = NULL;
	if (((tok1 = gettoken(NULL, FALSE)) == NULL) ||
	    ((gss_mech = gettoken(NULL, FALSE)) == NULL) ||
	    ((gss_qop = gettoken(NULL, FALSE)) == NULL) ||
	    ((tok2 = gettoken(NULL, FALSE)) == NULL) ||
	    ((secp->sc_service = getvalue(tok2, sc_service))
	    == SC_FAILURE)) {
		return (FALSE);
	}
	secp->sc_nfsnum = atoi(tok1);
	(void) strcpy(secp->sc_name, secname);
	(void) strcpy(secp->sc_gss_mech, gss_mech);
	secp->sc_gss_mech_type = NULL;
	if (secp->sc_gss_mech[0] != '-') {
		if (!rpc_gss_mech_to_oid(gss_mech, &secp->sc_gss_mech_type) ||
		    !rpc_gss_qop_to_num(gss_qop, gss_mech, &secp->sc_qop)) {
			return (FALSE);
		}
	}

	return (TRUE);
}

/*
 *  matchnum() parses a line of the /etc/nfssec.conf file
 *  and match the sc_nfsnum with the given number.
 *  If it is a match, it fills the information in the given pointer
 *  of the seconfig_t structure.
 *
 *  Returns TRUE if a match is found.
 */
static bool_t
matchnum(char *line, int num, seconfig_t *secp)
{
	char	*tok1,	*tok2;	/* holds a token from the line */
	char	*secname, *gss_mech, *gss_qop;	/* pointer to a secmode name */

	if ((secname = gettoken(line, FALSE)) == NULL) {
		/* bad line */
		return (FALSE);
	}

	tok1 = tok2 = NULL;
	if ((tok1 = gettoken(NULL, FALSE)) == NULL) {
		/* bad line */
		return (FALSE);
	}

	if ((secp->sc_nfsnum = atoi(tok1)) != num) {
		return (FALSE);
	}

	if (((gss_mech = gettoken(NULL, FALSE)) == NULL) ||
	    ((gss_qop = gettoken(NULL, FALSE)) == NULL) ||
	    ((tok2 = gettoken(NULL, FALSE)) == NULL) ||
	    ((secp->sc_service = getvalue(tok2, sc_service))
	    == SC_FAILURE)) {
		return (FALSE);
	}

	(void) strcpy(secp->sc_name, secname);
	(void) strcpy(secp->sc_gss_mech, gss_mech);
	if (secp->sc_gss_mech[0] != '-') {
		if (!rpc_gss_mech_to_oid(gss_mech, &secp->sc_gss_mech_type) ||
		    !rpc_gss_qop_to_num(gss_qop, gss_mech, &secp->sc_qop)) {
			return (FALSE);
		}
	}

	return (TRUE);
}

/*
 *  Fill in the RPC Protocol security flavor number
 *  into the sc_rpcnum of seconfig_t structure.
 *
 *  Mainly to map NFS secmod number to RPCSEC_GSS if
 *  a mechanism name is specified.
 */
static void
get_rpcnum(seconfig_t *secp)
{
	if (secp->sc_gss_mech[0] != '-') {
		secp->sc_rpcnum = RPCSEC_GSS;
	} else {
		secp->sc_rpcnum = secp->sc_nfsnum;
	}
}


/*
 *  Get seconfig from /etc/nfssec.conf by name or by number or
 *  by descriptior.
 */
/* ARGSUSED */
static int
get_seconfig(int whichway, char *name, int num,
		rpc_gss_service_t service, seconfig_t *entryp)
{
	char	line[BUFSIZ];	/* holds each line of NFSSEC_CONF */
	FILE	*fp;		/* file stream for NFSSEC_CONF */

	if ((whichway == GETBYNAME) && (name == NULL))
		return (SC_NOTFOUND);

	(void) mutex_lock(&matching_lock);
	if ((fp = fopen(NFSSEC_CONF, "r")) == NULL) {
		(void) mutex_unlock(&matching_lock);
		return (SC_OPENFAIL);
	}

	while (fgets(line, BUFSIZ, fp)) {
		if (!(blank(line) || comment(line))) {
			switch (whichway) {
				case GETBYNAME:
					if (matchname(line, name, entryp)) {
						goto found;
					}
					break;

				case GETBYNUM:
					if (matchnum(line, num, entryp)) {
						goto found;
					}
					break;

				default:
					break;
			}
		}
	}
	(void) fclose(fp);
	(void) mutex_unlock(&matching_lock);
	return (SC_NOTFOUND);

found:
	(void) fclose(fp);
	(void) mutex_unlock(&matching_lock);
	(void) get_rpcnum(entryp);
	return (SC_NOERROR);
}


/*
 *  NFS project private API.
 *  Get a seconfig entry from /etc/nfssec.conf by nfs specific sec name,
 *  e.g. des, krb5p, etc.
 */
int
nfs_getseconfig_byname(char *secmode_name, seconfig_t *entryp)
{
	if (!entryp)
		return (SC_NOMEM);

	return (get_seconfig(GETBYNAME, secmode_name, 0, rpc_gss_svc_none,
	    entryp));
}

