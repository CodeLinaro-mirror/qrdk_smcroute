/* Linux netlink listener for interface arrival/removal events.
 *
 * Subscribes to RTNLGRP_LINK plus the IPv4/IPv6 address groups, refreshes
 * the iface list on any event, and drains the pending list so routes/
 * groups whose inbound interface just arrived install automatically.
 * Bridge port state changes are passed on to the proxy querier.
 *
 * Copyright (C) 2026  Joachim Wiberg <troglobit@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include "config.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if_bridge.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "ifevent.h"
#include "iface.h"
#include "log.h"
#include "pending.h"
#include "proxy.h"
#include "socket.h"

static int nl_sd = -1;

/* Bridge port state from IFLA_PROTINFO, RFC 4541 §2.1.1 */
static void bridge_msg(struct nlmsghdr *nlh)
{
	struct ifinfomsg *ifi = NLMSG_DATA(nlh);
	struct rtattr *rta = IFLA_RTA(ifi);
	int len = IFLA_PAYLOAD(nlh);
	int master = 0, state = -1;
	struct iface *iface;

	if (nlh->nlmsg_type != RTM_NEWLINK)
		return;

	for (; RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
		struct rtattr *sub;
		int sublen;

		switch (rta->rta_type & NLA_TYPE_MASK) {
		case IFLA_MASTER:
			master = *(int *)RTA_DATA(rta);
			break;

		case IFLA_PROTINFO:
			sub    = RTA_DATA(rta);
			sublen = RTA_PAYLOAD(rta);
			for (; RTA_OK(sub, sublen); sub = RTA_NEXT(sub, sublen)) {
				if ((sub->rta_type & NLA_TYPE_MASK) == IFLA_BRPORT_STATE)
					state = *(uint8_t *)RTA_DATA(sub);
			}
			break;
		}
	}

	if (!master || state < 0)
		return;

	/* a port not seen before is new, unknown state */
	iface = iface_find(ifi->ifi_index);
	if (iface) {
		if (iface->brstate == state)
			return;
		iface->brstate = state;
	}

	if (state == BR_STATE_FORWARDING)
		proxy_topology(master, ifi->ifi_index);
}

static void nl_cb(int sd, void *arg)
{
	char buf[8192];
	ssize_t n;
	int got = 0;

	(void)arg;

	for (;;) {
		struct nlmsghdr *nlh = (struct nlmsghdr *)buf;

		n = recv(sd, buf, sizeof(buf), MSG_DONTWAIT);
		if (n <= 0)
			break;

		for (; NLMSG_OK(nlh, n); nlh = NLMSG_NEXT(nlh, n)) {
			struct ifinfomsg *ifi = NLMSG_DATA(nlh);

			/* port state changes do not touch addresses or links */
			if (nlh->nlmsg_type == RTM_NEWLINK && ifi->ifi_family == AF_BRIDGE)
				bridge_msg(nlh);
			else
				got = 1;
		}
	}

	if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
		smclog(LOG_WARNING, "netlink recv: %s", strerror(errno));

	if (!got)
		return;

	iface_update();
	pending_drain();
}

void ifevent_init(void)
{
	struct sockaddr_nl addr = { 0 };
	int type = SOCK_RAW;

#ifdef HAVE_SOCK_CLOEXEC
	type |= SOCK_CLOEXEC;
#endif
	nl_sd = socket(AF_NETLINK, type, NETLINK_ROUTE);
	if (nl_sd < 0) {
		smclog(LOG_ERR, "Failed opening netlink socket: %s", strerror(errno));
		return;
	}

	addr.nl_family = AF_NETLINK;
	addr.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR;
	if (bind(nl_sd, (struct sockaddr *)&addr, sizeof(addr))) {
		smclog(LOG_ERR, "Failed binding netlink socket: %s", strerror(errno));
		close(nl_sd);
		nl_sd = -1;
		return;
	}

	socket_register(nl_sd, nl_cb, NULL);
}

void ifevent_exit(void)
{
	if (nl_sd < 0)
		return;
	socket_close(nl_sd);
	nl_sd = -1;
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
