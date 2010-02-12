#ifndef XDMPCD_H
#define XDMPCD_H 

#define DEFAULT_PORT	177
#define GDM_XDMCP_PROTOCOL_VERSION 1001
#define CLEANUP_TIMEOUT		15*60

enum {
	XDMCP_PENDING /* Pending XDMCP display */,
	XDMCP_MANAGED /* Managed XDMCP display */,
	DISPLAY_DEAD /* Left for dead */,
	DISPLAY_CONFIG /* in process of being configured */
};

typedef struct _XdmAuth {
	ARRAY8 authentication;
	ARRAY8 authorization;
} XdmAuthRec, *XdmAuthPtr;

static XdmAuthRec serv_authlist = {
	{ (CARD16) 0, (CARD8 *) 0 },
	{ (CARD16) 0, (CARD8 *) 0 }
};

typedef struct {
	int fd;
	GIOChannel *ioc;
	gchar *sysid;
	ARRAY8 servhost;
	GList *sessions;

	/* Config variables */
	gchar *config_path;
	gchar *runas;
	gchar *acclist_path;
	gchar **exec_v;

	GList *acclist;
	GFileMonitor *amon;

	/*
	 * The next fields overwrites on each packet decode
	 */
	XdmcpBuffer buf;
	struct sockaddr_storage *clnt_sa;
	char clnt_host[NI_MAXHOST];
	char clnt_port[NI_MAXSERV];
	int hdr_len;
} XDMCPD;

typedef struct {
	int ssid;
	int displ_num ;
	char *bcookie;
	char *cookie;
	short stat;
	time_t time_stamp;
	pid_t pid;
} XSession;

#endif /* XDMPCD_H */
