/* IGMP wire format, RFC 2236 and RFC 3376
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

#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/igmp.h>

#include "iface.h"
#include "igmp.h"
#include "log.h"
#include "proxy.h"
#include "util.h"

#define IGMP_TIMER_SCALE 10	/* Max Resp Time is in 1/10 s */

/* An IPv4 or IPv6 address, @alen bytes, straight off the wire */
static void addr_from_wire(inet_addr_t *addr, const uint8_t *ptr, size_t alen)
{
	memset(addr, 0, sizeof(*addr));
#ifdef HAVE_IPV6_MULTICAST_HOST
	if (alen == sizeof(struct in6_addr)) {
		struct in6_addr in6;

		memcpy(&in6, ptr, sizeof(in6));
		inet_addr6_set(addr, &in6);
		return;
	}
#endif
	{
		struct in_addr in;

		memcpy(&in, ptr, sizeof(in));
		inet_addr_set(addr, &in);
	}
}

/* Hand the sources of a record to the proxy, a few at a time */
static void sources(struct iface *iface, inet_addr_t *src, inet_addr_t *group,
		    const uint8_t *ptr, int nsrcs, size_t alen,
		    void (*cb)(struct iface *, inet_addr_t *, inet_addr_t *, inet_addr_t *, int))
{
	inet_addr_t srcs[16];
	int i, num = 0;

	for (i = 0; i < nsrcs; i++, ptr += alen) {
		addr_from_wire(&srcs[num++], ptr, alen);
		if (num == (int)NELEMS(srcs) || i == nsrcs - 1) {
			cb(iface, src, group, srcs, num);
			num = 0;
		}
	}
}


/*
 * Group records of an IGMPv3 or MLDv2 report, RFC 3376 §4.2 and RFC 3810
 * §5.2, @alen is the address width.  EXCLUDE source lists are ignored,
 * RFC 5790.
 */
void igmp_v3_records(struct iface *iface, inet_addr_t *src, const uint8_t *buf, size_t len, size_t alen)
{
	const uint8_t *ptr = buf + 8, *end = buf + len;
	char s[INET_ADDRSTR_LEN];
	uint16_t num;
	int i;

	if (len < 8)
		return;

	memcpy(&num, buf + 6, sizeof(num));
	num = ntohs(num);

	for (i = 0; i < num; i++) {
		inet_addr_t group;
		uint16_t nsrcs;
		size_t size;

		if (ptr + 4 + alen > end) {
			smclog(LOG_INFO, "Invalid membership report from %s, record %d truncated",
			       inet_addr2str(src, s, sizeof(s)), i);
			return;
		}

		memcpy(&nsrcs, ptr + 2, sizeof(nsrcs));
		nsrcs = ntohs(nsrcs);
		size  = 4 + alen + nsrcs * alen + ptr[1] * 4;
		if (ptr + size > end) {
			smclog(LOG_INFO, "Invalid membership report from %s, record %d overflows",
			       inet_addr2str(src, s, sizeof(s)), i);
			return;
		}

		addr_from_wire(&group, ptr + 4, alen);

		switch (ptr[0]) {
		case IGMP_MODE_IS_EXCLUDE:
		case IGMP_CHANGE_TO_EXCLUDE_MODE:
			proxy_report(iface, src, &group, 3);
			break;

		case IGMP_MODE_IS_INCLUDE:
		case IGMP_CHANGE_TO_INCLUDE_MODE:
		case IGMP_ALLOW_NEW_SOURCES:
			if (nsrcs)
				sources(iface, src, &group, ptr + 4 + alen, nsrcs, alen, proxy_include);
			else
				proxy_leave(iface, src, &group, 3);
			break;

		case IGMP_BLOCK_OLD_SOURCES:
			sources(iface, src, &group, ptr + 4 + alen, nsrcs, alen, proxy_block);
			break;

		default:
			/* RFC 3376 §4.2.12, unknown record types are ignored */
			break;
		}

		ptr += size;
	}
}

/*
 * A General Query, or a Group-Specific one when @group is set, in the
 * format of generation @gen.  Routers in IGMPv2 mode send queries
 * truncated after the group field, in IGMPv1 mode with Max Response
 * Time zero, RFC 2236 §2 and RFC 3376 §7.
 */
size_t igmp_build_query(uint8_t *buf, int gen, int mrt, inet_addr_t *group, int qqi, int qrv)
{
	struct igmpv3_query *query = (struct igmpv3_query *)buf;
	size_t len = gen == 3 ? sizeof(*query) : IGMP_MINLEN;
	int code = mrt * IGMP_TIMER_SCALE;

	memset(query, 0, len);
	query->type = IGMP_MEMBERSHIP_QUERY;
	if (group)
		query->group = inet_addr_get(group)->s_addr;

	if (gen == 3) {
		query->code = igmp_time_float(code, 4);
		query->qrv  = qrv & 7;
		query->qqic = igmp_time_float(qqi, 4);
	} else if (gen == 2)
		query->code = code;

	query->csum = inet_cksum(query, len);

	return len;
}

/*
 * Process an IGMP packet from the mrouted socket, IP header included.
 */
void igmp_recv(int ifindex, uint8_t *buf, size_t len)
{
	char s1[INET_ADDRSTR_LEN], s2[INET_ADDRSTR_LEN], s3[INET_ADDRSTR_LEN];
	inet_addr_t src = { 0 }, group = { 0 };
	struct iface *iface;
	struct igmp *igmp;
	struct in_addr saddr;
	struct ip *ip;
	size_t hlen, dlen;
	int mrt, gen;

	iface = iface_find(ifindex);
	if (!iface || !proxy_role(iface))
		return;

	ip = (struct ip *)buf;
	hlen = ip->ip_hl << 2;
	if (hlen < sizeof(*ip) || hlen > len)
		return;

	dlen = ntohs(ip->ip_len) - hlen;
	if (dlen < IGMP_MINLEN || hlen + dlen > len)
		return;

	/* our own, looped back */
	if (iface->inaddr.s_addr && ip->ip_src.s_addr == iface->inaddr.s_addr)
		return;

	igmp = (struct igmp *)(buf + hlen);
	saddr = ip->ip_src;
	inet_addr_set(&src, &saddr);
	inet_addr2str(&src, s1, sizeof(s1));

	if (inet_cksum(igmp, dlen)) {
		smclog(LOG_INFO, "Bad IGMP checksum from %s, ignoring", s1);
		return;
	}

	inet_addr_set(&group, &igmp->igmp_group);
	smclog(LOG_DEBUG, "IGMP type 0x%02x from %s to %s on %s, group %s", igmp->igmp_type, s1,
	       inet_ntop(AF_INET, &ip->ip_dst, s2, sizeof(s2)), iface->ifname,
	       inet_addr2str(&group, s3, sizeof(s3)));

	switch (igmp->igmp_type) {
	case IGMP_MEMBERSHIP_QUERY:
		/* RFC 3376 §7.1 */
		if (dlen == IGMP_MINLEN) {
			gen = igmp->igmp_code ? 2 : 1;
			mrt = igmp->igmp_code / IGMP_TIMER_SCALE;
		} else if (dlen >= sizeof(struct igmpv3_query)) {
			struct igmpv3_query *query = (struct igmpv3_query *)igmp;

			gen = 3;
			mrt = igmp_float_time(query->code, 4) / IGMP_TIMER_SCALE;
		} else {
			smclog(LOG_INFO, "Invalid IGMP query from %s, length %zu", s1, dlen);
			return;
		}
		proxy_query(iface, &src, &group, mrt, gen);
		break;

	case IGMP_V1_MEMBERSHIP_REPORT:
		proxy_report(iface, &src, &group, 1);
		break;

	case IGMP_V2_MEMBERSHIP_REPORT:
		proxy_report(iface, &src, &group, 2);
		break;

	case IGMP_V2_LEAVE_GROUP:
		proxy_leave(iface, &src, &group, 2);
		break;

	case IGMP_V3_MEMBERSHIP_REPORT:
		igmp_v3_records(iface, &src, (uint8_t *)igmp, dlen, sizeof(struct in_addr));
		break;

	default:
		break;
	}
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
