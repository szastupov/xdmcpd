/*
 * Copyright (C) 2008-2009 Stepan Zastupov AltEll Ltd.
 * Copyright (C) GDM Authors and contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#define _GNU_SOURCE
#include <glib.h>
#include <gio/gio.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <pwd.h>

#include <sys/socket.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netdb.h>

#include <X11/Xdmcp.h>

#include "cookie.h"
#include "xdmcpd.h"

gint sess_compare(XSession *a, XSession *b)
{
	return a->ssid - b->ssid;
}

XSession* session_new(XDMCPD *xdm)
{
	XSession *xs = g_malloc(sizeof(XSession));
	xs->ssid = g_random_int();
	xs->stat = XDMCP_PENDING;
	xs->time_stamp = time(NULL);
	gdm_cookie_generate(&xs->cookie, &xs->bcookie);

	xdm->sessions = g_list_insert_sorted(xdm->sessions, xs, (GCompareFunc)sess_compare);
	return xs;
}

XSession* session_lookup(XDMCPD *xdm, int ssid)
{
	GList *cur;
	for (cur = xdm->sessions; cur != NULL; cur = g_list_next(cur)) {
		XSession *res = (XSession*)cur->data;
		if (res->ssid == ssid)
			return res;
	}
	return NULL;
}


XSession* session_lookup_pid(XDMCPD *xdm, pid_t pid)
{
	GList *cur;
	for (cur = xdm->sessions; cur != NULL; cur = g_list_next(cur)) {
		XSession *res = (XSession*)cur->data;
		if (res->pid == pid)
			return res;
	}
	return NULL;
}

static void xdmcp_flush(XDMCPD *xdm)
{
	XdmcpFlush(xdm->fd,
			   &xdm->buf,
			   (XdmcpNetaddr)xdm->clnt_sa,
			   (int)sizeof(struct sockaddr_in));

}

static void xdmcp_send_willing(XDMCPD *xdm)
{
	ARRAY8        status;
	XdmcpHeader   header;
	static char  *last_status = NULL;
	static time_t last_willing = 0;

	g_message ("XDMCP: Sending WILLING to %s", xdm->clnt_host);

	if (last_willing == 0 || time (NULL) - 3 > last_willing) {
		g_free (last_status);
		last_status = g_strdup(xdm->sysid);
	}

	/*
	 * TODO check for lemits per display here
	 */
	status.data = (CARD8 *) g_strdup (last_status);

	status.length = strlen ((char *) status.data);

	header.opcode   = (CARD16) WILLING;
	header.length   = 6 + serv_authlist.authentication.length;
	header.length  += xdm->servhost.length + status.length;
	header.version  = XDM_PROTOCOL_VERSION;
	XdmcpWriteHeader (&xdm->buf, &header);

	/* Hardcoded authentication */
	XdmcpWriteARRAY8 (&xdm->buf, &serv_authlist.authentication);
	XdmcpWriteARRAY8 (&xdm->buf, &xdm->servhost);
	XdmcpWriteARRAY8 (&xdm->buf, &status);

	xdmcp_flush(xdm);

	g_free (status.data);
}

static void xdmcp_handle_direct_query(XDMCPD *xdm)
{
	ARRAYofARRAY8 clnt_authlist;
	int           expected_len;
	int           i;
	int           res;

	res = XdmcpReadARRAYofARRAY8 (&xdm->buf, &clnt_authlist);
	if G_UNLIKELY (! res) {
			g_message ("Could not extract authlist from packet");
			return;
		}

	expected_len = 1;

	for (i = 0 ; i < clnt_authlist.length ; i++)
		expected_len += 2 + clnt_authlist.data[i].length;

	if (xdm->hdr_len == expected_len)
		xdmcp_send_willing(xdm);
	else
		g_message ("Error in checksum");

	XdmcpDisposeARRAYofARRAY8 (&clnt_authlist);
}

static void
xdmcp_send_decline(XDMCPD *xdm,	const char *reason)
{
	XdmcpHeader      header;
	ARRAY8           authentype;
	ARRAY8           authendata;
	ARRAY8           status;

	g_message ("XDMCP: Sending DECLINE to %s", xdm->clnt_host);

	authentype.data   = (CARD8 *) 0;
	authentype.length = (CARD16)  0;

	authendata.data   = (CARD8 *) 0;
	authendata.length = (CARD16)  0;

	status.data       = (CARD8 *) reason;
	status.length     = strlen ((char *) status.data);

	header.version    = XDM_PROTOCOL_VERSION;
	header.opcode     = (CARD16) DECLINE;
	header.length     = 2 + status.length;
	header.length    += 2 + authentype.length;
	header.length    += 2 + authendata.length;

	XdmcpWriteHeader (&xdm->buf, &header);
	XdmcpWriteARRAY8 (&xdm->buf, &status);
	XdmcpWriteARRAY8 (&xdm->buf, &authentype);
	XdmcpWriteARRAY8 (&xdm->buf, &authendata);

	xdmcp_flush(xdm);
}

static void
xdmcp_send_accept (XDMCPD *xdm,
				   CARD32                   session_id,
				   ARRAY8Ptr                authentication_name,
				   ARRAY8Ptr                authentication_data,
				   ARRAY8Ptr                authorization_name,
				   ARRAY8Ptr                authorization_data)
{
	XdmcpHeader header;

	header.version    = XDM_PROTOCOL_VERSION;
	header.opcode     = (CARD16) ACCEPT;
	header.length     = 4;
	header.length    += 2 + authentication_name->length;
	header.length    += 2 + authentication_data->length;
	header.length    += 2 + authorization_name->length;
	header.length    += 2 + authorization_data->length;

	XdmcpWriteHeader (&xdm->buf, &header);
	XdmcpWriteCARD32 (&xdm->buf, session_id);
	XdmcpWriteARRAY8 (&xdm->buf, authentication_name);
	XdmcpWriteARRAY8 (&xdm->buf, authentication_data);
	XdmcpWriteARRAY8 (&xdm->buf, authorization_name);
	XdmcpWriteARRAY8 (&xdm->buf, authorization_data);

	xdmcp_flush(xdm);

	g_message ("XDMCP: Sending ACCEPT to %s with SessionID=%ld",
			   xdm->clnt_host,
			   (long)session_id);
}

static void
xdmcp_send_refuse (XDMCPD *xdm, CARD32 sessid)
{
	XdmcpHeader      header;
	g_message("XDMCP: Sending REFUSE to %ld",
			  (long)sessid);

	header.version = XDM_PROTOCOL_VERSION;
	header.opcode  = (CARD16) REFUSE;
	header.length  = 4;

	XdmcpWriteHeader (&xdm->buf, &header);
	XdmcpWriteCARD32 (&xdm->buf, sessid);

	xdmcp_flush(xdm);
}

static void xdmcp_start_app(XDMCPD *xdm, XSession *xs)
{
	char *denv = NULL;
	struct passwd *pw;
	pid_t pid;
	switch ((pid = fork())) {
	case 0:
		setpgid(0, 0);
		setsid();
		chdir("/");

		pw = getpwnam(xdm->runas);
		if (!pw)
			g_error("user %s does not exists", xdm->runas);
		setgid(pw->pw_gid);
		setuid(pw->pw_uid);

		close(xdm->fd);
		freopen("/dev/null", "r", stdin);
		freopen("/dev/null", "r", stdout);
		freopen("/dev/null", "r", stderr);

		denv = g_strdup_printf("%s:%d", xdm->clnt_host, xs->displ_num);
		setenv("DISPLAY", denv, 1);
		setenv("REMOTE_HOST", xdm->clnt_host, 1);
		g_free(denv);
		execvp(*xdm->exec_v, xdm->exec_v);
	case -1:
		g_error("fork error");
	default:
		xs->pid = pid;
	}
}

static void xdmcp_handle_manage(XDMCPD *xdm)
{
	CARD32              clnt_sessid;
	CARD16              clnt_dspnum;
	ARRAY8              clnt_dspclass;
	XSession			*xs;

	g_message ("gdm_xdmcp_handle_manage: Got MANAGE from %s", xdm->clnt_host);

	/* SessionID */
	if G_UNLIKELY (! XdmcpReadCARD32 (&xdm->buf, &clnt_sessid)) {
			g_message ("%s: Could not read Session ID",
					   "gdm_xdmcp_handle_manage");
			return;
		}

	/* Remote display number */
	if G_UNLIKELY (! XdmcpReadCARD16 (&xdm->buf, &clnt_dspnum)) {
			g_message ("%s: Could not read Display Number",
					   "gdm_xdmcp_handle_manage");
			return;
		}

	/* Display Class */
	if G_UNLIKELY (! XdmcpReadARRAY8 (&xdm->buf, &clnt_dspclass)) {
			g_message ("%s: Could not read Display Class",
					   "gdm_xdmcp_handle_manage");
			return;
		}

	xs = session_lookup(xdm, clnt_sessid);
	if (xs != NULL && xs->stat == XDMCP_PENDING) {
		xs->stat = XDMCP_MANAGED;

		/* Lauch selected application */
		xdmcp_start_app(xdm, xs);

	} else if G_UNLIKELY (xs != NULL && xs->stat == XDMCP_MANAGED)
							 g_message ("gdm_xdmcp_handle_manage: Session id %ld already managed",
										(long)clnt_sessid);
	else {
		g_message ("gdm_xdmcp_handle_manage: Failed to look up session id %ld",
				   (long)clnt_sessid);
		xdmcp_send_refuse(xdm, clnt_sessid);
	}

	XdmcpDisposeARRAY8 (&clnt_dspclass);
}


static void xdmcp_handle_keepalive(XDMCPD *xdm)
{
	CARD16 clnt_dspnum;
	CARD32 clnt_sessid;
	XdmcpHeader header;
	XSession *xs;
	int send_running = 0;
	CARD32 send_sessid = 0;

	g_message ("XDMCP: Got KEEPALIVE from %s", xdm->clnt_host);

	/* Remote display number */
	if G_UNLIKELY (! XdmcpReadCARD16 (&xdm->buf, &clnt_dspnum)) {
			g_message("%s: Could not read Display Number",
					  "gdm_xdmcp_handle_keepalive");
			return;
		}

	/* SessionID */
	if G_UNLIKELY (! XdmcpReadCARD32 (&xdm->buf, &clnt_sessid)) {
			g_message("%s: Could not read Session ID",
					  "gdm_xdmcp_handle_keepalive");
			return;
		}

	xs = session_lookup(xdm, clnt_sessid);
	if (xs) {
		xs->time_stamp = time(NULL);
		send_sessid = xs->ssid;
		if (xs->stat == XDMCP_MANAGED)
			send_running = 1;
	}

	g_message ("XDMCP: Sending ALIVE to %ld (running %d, sessid %ld)",
			   (long)clnt_sessid,
			   send_running,
			   (long)clnt_sessid);

	header.version = XDM_PROTOCOL_VERSION;
	header.opcode = (CARD16) ALIVE;
	header.length = 5;

	XdmcpWriteHeader(&xdm->buf, &header);
	XdmcpWriteCARD8(&xdm->buf, send_running);
	XdmcpWriteCARD32(&xdm->buf, send_sessid);

	xdmcp_flush(xdm);
}

static void xdmcp_handle_request(XDMCPD *xdm)
{
	CARD16        clnt_dspnum;
	ARRAY16       clnt_conntyp;
	ARRAYofARRAY8 clnt_addr;
	ARRAY8        clnt_authname;
	ARRAY8        clnt_authdata;
	ARRAYofARRAY8 clnt_authorization;
	ARRAY8        clnt_manufacturer;
	int           explen;
	int           i;
	gboolean      mitauth;
	gboolean      entered;

	mitauth = FALSE;
	entered = FALSE;

	g_message ("gdm_xdmcp_handle_request: Got REQUEST from %s", xdm->clnt_host);

	/* Remote display number */
	if G_UNLIKELY (! XdmcpReadCARD16 (&xdm->buf, &clnt_dspnum)) {
			g_message ("%s: Could not read Display Number",
					   "gdm_xdmcp_handle_request");
			return;
		}

	/* We don't care about connection type. Address says it all */
	if G_UNLIKELY (! XdmcpReadARRAY16 (&xdm->buf, &clnt_conntyp)) {
			g_message ("%s: Could not read Connection Type",
					   "gdm_xdmcp_handle_request");
			return;
		}

	/* This is TCP/IP - we don't care */
	if G_UNLIKELY (! XdmcpReadARRAYofARRAY8 (&xdm->buf, &clnt_addr)) {
			g_message ("%s: Could not read Client Address",
					   "gdm_xdmcp_handle_request");
			goto out_conntyp;
		}

	/* Read authentication type */
	if G_UNLIKELY (! XdmcpReadARRAY8 (&xdm->buf, &clnt_authname)) {
			g_message ("%s: Could not read Authentication Names",
					   "gdm_xdmcp_handle_request");
			goto out_addr;
		}

	/* Read authentication data */
	if G_UNLIKELY (! XdmcpReadARRAY8 (&xdm->buf, &clnt_authdata)) {
			g_message ("%s: Could not read Authentication Data",
					   "gdm_xdmcp_handle_request");
			goto out_authname;
		}

	/* Read and select from supported authorization list */
	if G_UNLIKELY (! XdmcpReadARRAYofARRAY8 (&xdm->buf, &clnt_authorization)) {
			g_message ("%s: Could not read Authorization List",
					   "gdm_xdmcp_handle_request");
			goto out_authdata;
		}

	/* libXdmcp doesn't terminate strings properly so we cheat and use strncmp () */
	for (i = 0 ; i < clnt_authorization.length ; i++)
		if (clnt_authorization.data[i].length == 18 &&
			strncmp ((char *) clnt_authorization.data[i].data,
					 "MIT-MAGIC-COOKIE-1", 18) == 0)
			mitauth = TRUE;

	/* Manufacturer ID */
	if G_UNLIKELY (! XdmcpReadARRAY8 (&xdm->buf, &clnt_manufacturer)) {
			g_message ("%s: Could not read Manufacturer ID",
					   "gdm_xdmcp_handle_request");
			goto out_authorization;
		}

	/* Crude checksumming */
	explen = 2;		    /* Display Number */
	explen += 1 + 2 * clnt_conntyp.length; /* Connection Type */
	explen += 1;		    /* Connection Address */
	for (i = 0 ; i < clnt_addr.length ; i++)
		explen += 2 + clnt_addr.data[i].length;
	explen += 2 + clnt_authname.length; /* Authentication Name */
	explen += 2 + clnt_authdata.length; /* Authentication Data */
	explen += 1;		    /* Authorization Names */
	for (i = 0 ; i < clnt_authorization.length ; i++)
		explen += 2 + clnt_authorization.data[i].length;
	explen += 2 + clnt_manufacturer.length;

	if G_UNLIKELY (explen != xdm->hdr_len) {
			g_message ("%s: Failed checksum from %s",
					   "gdm_xdmcp_handle_request",
					   xdm->clnt_host);
		}

	if (!mitauth)
		xdmcp_send_decline(xdm, "Only MIT-MAGIC-COOKIE-1 supported");
	else {
		XSession *xs = session_new(xdm);
		xs->displ_num = clnt_dspnum;

		ARRAY8 authentication_name;
		ARRAY8 authentication_data;
		ARRAY8 authorization_name;
		ARRAY8 authorization_data;

		authentication_name.data   = NULL;
		authentication_name.length = 0;
		authentication_data.data   = NULL;
		authentication_data.length = 0;

		authorization_name.data     = (CARD8 *) "MIT-MAGIC-COOKIE-1";
		authorization_name.length   = strlen ((char *) authorization_name.data);

		authorization_data.data     = (CARD8 *) xs->bcookie;
		authorization_data.length   = 16;

		/* the addrs are NOT copied */
		xdmcp_send_accept (xdm,
						   xs->ssid,
						   &authentication_name,
						   &authentication_data,
						   &authorization_name,
						   &authorization_data);

	}


	XdmcpDisposeARRAY8 (&clnt_manufacturer);
out_authorization:
	XdmcpDisposeARRAYofARRAY8 (&clnt_authorization);
out_authdata:
	XdmcpDisposeARRAY8 (&clnt_authdata);
out_authname:
	XdmcpDisposeARRAY8 (&clnt_authname);
out_addr:
	XdmcpDisposeARRAYofARRAY8 (&clnt_addr);
out_conntyp:
	XdmcpDisposeARRAY16 (&clnt_conntyp);
}


static const char *
opcode_string (int opcode)
{
	static const char * const opcode_names[] = {
		NULL,
		"BROADCAST_QUERY",
		"QUERY",
		"INDIRECT_QUERY",
		"FORWARD_QUERY",
		"WILLING",
		"UNWILLING",
		"REQUEST",
		"ACCEPT",
		"DECLINE",
		"MANAGE",
		"REFUSE",
		"FAILED",
		"KEEPALIVE",
		"ALIVE"
	};

	if (opcode < G_N_ELEMENTS (opcode_names)) {
		return opcode_names [opcode];
	} else {
		return "UNKNOWN";
	}
}

static gboolean xdmcp_check_access(XDMCPD *xdm)
{
	gboolean allow = FALSE;
	GList *cur;
	for (cur = xdm->acclist; cur != NULL; cur = g_list_next(cur))
		if (strcmp(xdm->clnt_host, (char*)cur->data) == 0)
			allow = TRUE;
	return allow;
}


static gboolean decode_packet(GIOChannel *channel,
							  GIOCondition cond, XDMCPD *xdm)
{
	if (cond & G_IO_IN) {
		int res;
		struct sockaddr_storage clnt_sa;
		gint sa_len = sizeof(clnt_sa);
		XdmcpHeader header;

		res = XdmcpFill(xdm->fd, &xdm->buf, (XdmcpNetaddr)&clnt_sa, &sa_len);
		if G_UNLIKELY (!res) {
				g_warning("XDMCP: Could not create XDMCP buffer!");
				return TRUE;
			}

		xdm->clnt_sa = &clnt_sa;

		res = XdmcpReadHeader(&xdm->buf, &header);
		if G_UNLIKELY (!res) {
				g_warning("XDMCP: Could not read XDMCP header!");
				return TRUE;
			}

		if G_UNLIKELY (header.version != XDM_PROTOCOL_VERSION &&
					   header.version != GDM_XDMCP_PROTOCOL_VERSION) {
				g_warning("XDMCP: Incorrect XDMCP version!");
				return TRUE;
			}


		memset(&xdm->clnt_host, 0, sizeof(xdm->clnt_host));
		memset(&xdm->clnt_port, 0, sizeof(xdm->clnt_port));
		xdm->clnt_port[0] = '\0';
		getnameinfo ((const struct sockaddr *)&clnt_sa,
					 sizeof(struct sockaddr_in),
					 xdm->clnt_host, sizeof(xdm->clnt_host),
					 xdm->clnt_port, sizeof(xdm->clnt_port),
					 NI_NUMERICHOST | NI_NUMERICSERV | NI_DGRAM);

		if (!xdmcp_check_access(xdm)) {
			g_message("XDMCP: Aceess from host %s denied, skipping", xdm->clnt_host);
			return TRUE;
		}

		g_message("XDMCP: Received opcode %s from client %s : %s",
				  opcode_string (header.opcode),
				  xdm->clnt_host,
				  xdm->clnt_port);

		xdm->hdr_len = header.length;
		switch (header.opcode) {
		case QUERY:
			xdmcp_handle_direct_query(xdm);
			break;
		case REQUEST:
			xdmcp_handle_request(xdm);
			break;
		case MANAGE:
			xdmcp_handle_manage(xdm);
			break;
		case KEEPALIVE:
			xdmcp_handle_keepalive(xdm);
			break;
		default:
			g_message("XDMCP: Unknown opcode from client %s : %s", xdm->clnt_host, xdm->clnt_port);
		}

	}

	if (cond & G_IO_ERR || cond & G_IO_HUP)
		g_message("bad things");

	return TRUE;
}

static int open_sock()
{
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s == -1)
		g_error("Unable to create socket");

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(DEFAULT_PORT);
	addr.sin_addr.s_addr = INADDR_ANY;

	if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) == -1)
		g_error("bind failed");

	return s;
}

static void xdmcp_load_acclist(XDMCPD* xdm)
{
	char *line = NULL;
	size_t len = 0;
	FILE *fp = fopen(xdm->acclist_path, "r");
	if (!fp) {
		g_warning("Failed to load acclist, all requests will be denied");
		return;
	}

	while (getline(&line, &len, fp) != -1) {
		char *space = strchr(line, '\n');
		if (space)
			*space = '\0';
		if (!strlen(line))
			continue;
		g_message("adding %s to acclist", line);
		xdm->acclist = g_list_prepend(xdm->acclist, g_strdup(line));
	}

	if (line)
		free(line);
	fclose(fp);
}

static void xdmcp_clear_acclist(XDMCPD* xdm)
{
	if (!xdm->acclist)
		return;
	g_message("Clearing acclist");

	g_list_foreach(xdm->acclist, (GFunc)g_free, NULL);
	g_list_free(xdm->acclist);
	xdm->acclist = NULL;
}

static void acclist_changed(GFileMonitor *mon, GFile *file, GFile *other,
							GFileMonitorEvent event_type, XDMCPD *xdm)
{
	/*
	 * Clear list on delete (i.e. vim delete file)
	 * and on change (standart file append).
	 * All other events would be ignored
	 */
	switch (event_type) {
	case G_FILE_MONITOR_EVENT_DELETED:
		xdmcp_clear_acclist(xdm);
		return;
	case G_FILE_MONITOR_EVENT_CHANGED:
		xdmcp_clear_acclist(xdm);
		return;
	case G_FILE_MONITOR_EVENT_CHANGES_DONE_HINT:
		xdmcp_load_acclist(xdm);
	case G_FILE_MONITOR_EVENT_UNMOUNTED:
	case G_FILE_MONITOR_EVENT_PRE_UNMOUNT:
	case G_FILE_MONITOR_EVENT_CREATED:
	case G_FILE_MONITOR_EVENT_ATTRIBUTE_CHANGED:
		return;
	}
}

static gboolean xdmcp_cleanup_sessions(XDMCPD *xdm)
{
	g_message("Cleanup begin");
	GList *cur = xdm->sessions;
	time_t tl = time(NULL)-CLEANUP_TIMEOUT;

	while (cur != NULL) {
		XSession *xs =(XSession*)cur->data;
		if (xs->time_stamp < tl) {
			g_message("Removing session %d", xs->ssid);
			GList *tmp = cur->next;
			if (xs->cookie)
				g_free(xs->cookie);
			if (xs->bcookie)
				g_free(xs->bcookie);
			g_free(xs);
			xdm->sessions = g_list_delete_link(xdm->sessions, cur);
			cur = tmp;
		} else
			cur = g_list_next(cur);
	}
	g_message("Cleanup end");
	return TRUE;
}

static gchar* config_get(GKeyFile* kf, const char *group, 
						 const char *key, const char *dflt)
{
	char *res = g_key_file_get_value(kf, group, key, NULL);
	if (res)
		return res;
	return g_strdup(dflt);
}

static void xdmcp_configure(XDMCPD *xdm)
{
	static const char *group = "XDMCP";
	GKeyFile *kf = g_key_file_new();
	if (!g_key_file_load_from_file(kf, xdm->config_path, 0, NULL))
		g_error("Unable to open config file %s", xdm->config_path);

	if (!g_key_file_has_group(kf, group))
		g_error("%s group not found in config file", group);

	xdm->runas = config_get(kf, group, "runas", "root");
	xdm->acclist_path = config_get(kf, group, "acclist", "xdmcpd.access");

	gchar *execute = config_get(kf, group, "execute", "xterm");
	xdm->exec_v = g_strsplit_set(execute, " \t", 20);
	g_free(execute);

	g_key_file_free(kf);
}

static XDMCPD* xdmcp_new(char *config_path)
{
	XDMCPD *xdm = g_malloc(sizeof(XDMCPD));

	if (config_path)
		xdm->config_path = config_path;
	else
		xdm->config_path = g_strdup("xdmcpd.conf");
	xdmcp_configure(xdm);

	int s = open_sock();
	xdm->fd = s;
	bzero(&xdm->buf, sizeof(xdm->buf));
	xdm->sessions = NULL;
	xdm->acclist = NULL;

	char hostbuf[1024];
	gethostname(hostbuf, sizeof(hostbuf));
	struct utsname name;
	uname(&name);
	xdm->sysid = g_strconcat(name.sysname, " ", name.release, NULL);
	xdm->servhost.data = (CARD8 *)g_strdup(hostbuf);
	xdm->servhost.length = strlen((char *)xdm->servhost.data);

	xdm->ioc = g_io_channel_unix_new(s);
	g_io_channel_set_encoding(xdm->ioc, NULL, NULL);
	g_io_channel_set_buffered(xdm->ioc, FALSE);

	g_io_add_watch_full(xdm->ioc, G_PRIORITY_DEFAULT,
						G_IO_IN | G_IO_ERR | G_IO_HUP,
						(GIOFunc)decode_packet, xdm, NULL);
	g_io_channel_unref(xdm->ioc);

	g_timeout_add_seconds(CLEANUP_TIMEOUT, (GSourceFunc)xdmcp_cleanup_sessions, xdm);

	xdmcp_load_acclist(xdm);

	GFile *afile = g_file_new_for_path(xdm->acclist_path);
	GFileMonitor *mon = g_file_monitor_file(afile, G_FILE_MONITOR_NONE, NULL, NULL);
	g_warn_if_fail(mon != NULL);
	g_signal_connect(mon, "changed", G_CALLBACK(acclist_changed), xdm);
	xdm->amon = mon;
	g_object_unref(afile);	// File will be destroyed with monitor

	return xdm;
}

static void xdmcp_destory(XDMCPD *xdm)
{
	g_io_channel_unref(xdm->ioc);
	close(xdm->fd);

	g_free(xdm->config_path);
	g_free(xdm->sysid);
	g_free(xdm->servhost.data);
	g_free(xdm->runas);
	g_free(xdm->acclist_path);
	g_strfreev(xdm->exec_v);

	g_list_foreach(xdm->sessions, (GFunc)g_free, NULL);
	g_list_free(xdm->sessions);

	xdmcp_clear_acclist(xdm);

	g_object_unref(xdm->amon);
}

static struct {
	GMainLoop *loop;
	XDMCPD *xdm;
} app_context = {0, 0};

static void sighandler(int s, siginfo_t *info, void *ctxt)
{
	if (s == SIGCHLD) {
		int status;
		waitpid(info->si_pid, &status, WNOHANG|WUNTRACED);
		g_message("child %d is dead", info->si_pid);

		if (app_context.xdm) {
			XDMCPD *xdm = app_context.xdm;
			XSession *xs = session_lookup_pid(xdm, info->si_pid);
			if (xs) {
				g_message("Deleting session %d", xs->ssid);
				xdm->sessions = g_list_remove(xdm->sessions, xs);
				g_free(xs);
			}
		}
		return;
	}

	g_message("exiting");
	if (app_context.loop)
		g_main_loop_quit(app_context.loop);
}

int main(int argc, char *argv[])
{
	struct sigaction sigs = {
		.sa_sigaction = sighandler,
		.sa_flags = SA_SIGINFO
	};
	sigaction(SIGINT, &sigs, NULL);
	sigaction(SIGTERM, &sigs, NULL);
	sigaction(SIGCHLD, &sigs, NULL);

	g_type_init();
	app_context.loop = g_main_loop_new(NULL, FALSE);

	int c;
	char *cp = NULL;
	while ((c = getopt(argc, argv, "c:")) != -1) {
		switch (c) {
		case 'c':
			cp = g_strdup(optarg);
			break;
		default:
			break;
		}
	}

	app_context.xdm = xdmcp_new(cp);

	g_main_loop_run(app_context.loop);

	xdmcp_destory(app_context.xdm);

	return 0;
}
