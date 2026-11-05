/* MLD wire format, RFC 2710 and RFC 3810
 *
 * Copyright (C) 2026  Joachim Wiberg <troglobit@gmail.com>
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
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
 */

#include "config.h"

#ifdef HAVE_IPV6_MULTICAST_HOST
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>

#include "iface.h"
#include "igmp.h"
#include "log.h"
#include "mld.h"
#include "proxy.h"

struct mldv2_query {
	uint8_t  type;
	uint8_t  code;
	uint16_t csum;
	uint16_t mrc;		/* Maximum Response Code */
	uint16_t resv;
	struct in6_addr group;
	uint8_t  qrv;		/* Resv:4 S:1 QRV:3 */
	uint8_t  qqic;
	uint16_t nsrcs;
	struct in6_addr srcs[0];
};

/*
 * A General Query, or a Group-Specific one when @group is set, as
 * MLDv1 (gen 2) or MLDv2 (gen 3).  The kernel fills in the checksum.
 */
size_t mld_build_query(uint8_t *buf, int gen, int mrt, inet_addr_t *group, int qqi, int qrv)
{
	struct mldv2_query *query = (struct mldv2_query *)buf;
	size_t len = gen == 3 ? sizeof(*query) : sizeof(struct mld_hdr);

	memset(query, 0, len);
	query->type = MLD_LISTENER_QUERY;
	if (group)
		query->group = inet_addr6_get(group)->sin6_addr;

	if (gen == 3) {
		query->mrc  = htons(igmp_time_float(mrt * 1000, 12));
		query->qrv  = qrv & 7;
		query->qqic = igmp_time_float(qqi, 4);
	} else
		query->mrc = htons(mrt * 1000);

	return len;
}

/*
 * Process an MLD message from the mrouted socket, ICMPv6 header first;
 * the kernel has verified the checksum and stripped the IPv6 header.
 */
void mld_recv(int ifindex, inet_addr_t *src, int hlim, uint8_t *buf, size_t len)
{
	char s1[INET_ADDRSTR_LEN];
	struct sockaddr_in6 *sin6;
	struct mld_hdr *mld;
	struct iface *iface;
	inet_addr_t group = { 0 };
	struct in6_addr maddr;
	int mrt, gen;

	if (len < sizeof(*mld))
		return;

	iface = iface_find(ifindex);
	if (!iface || !proxy_role(iface))
		return;

	inet_addr2str(src, s1, sizeof(s1));

	/* RFC 3810 §5.1.14 and §5.2.13 */
	sin6 = inet_addr6_get(src);
	if (!IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr) && !IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr)) {
		smclog(LOG_DEBUG, "MLD from non link-local %s on %s, ignoring", s1, iface->ifname);
		return;
	}
	if (hlim != -1 && hlim != 1) {
		smclog(LOG_DEBUG, "MLD from %s on %s with hop limit %d, ignoring", s1, iface->ifname, hlim);
		return;
	}

	mld = (struct mld_hdr *)buf;
	smclog(LOG_DEBUG, "MLD type %d from %s on %s", mld->mld_type, s1, iface->ifname);

	if (mld->mld_type == MLDV2_LISTENER_REPORT) {
		igmp_v3_records(iface, src, buf, len, sizeof(struct in6_addr));
		return;
	}

	maddr = mld->mld_addr;
	inet_addr6_set(&group, &maddr);

	switch (mld->mld_type) {
	case MLD_LISTENER_QUERY:
		if (len == sizeof(*mld)) {
			gen = 2;
			mrt = ntohs(mld->mld_maxdelay) / 1000;
		} else if (len >= sizeof(struct mldv2_query)) {
			struct mldv2_query *query = (struct mldv2_query *)mld;

			gen = 3;
			mrt = igmp_float_time(ntohs(query->mrc), 12) / 1000;
		} else {
			smclog(LOG_INFO, "Invalid MLD query from %s, length %zu", s1, len);
			return;
		}
		proxy_query(iface, src, &group, mrt, gen);
		break;

	case MLD_LISTENER_REPORT:
		proxy_report(iface, src, &group, 2);
		break;

	case MLD_LISTENER_REDUCTION:
		proxy_leave(iface, src, &group, 2);
		break;

	default:
		break;
	}
}
#endif /* HAVE_IPV6_MULTICAST_HOST */

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
