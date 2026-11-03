/* Kernel API for join/leave multicast groups and add/del routes
 *
 * Copyright (C) 2011-2026  Joachim Wiberg <troglobit@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "config.h"

#include <errno.h>
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#ifdef IP_RECVIF
#include <net/if_dl.h>
#endif
#include <netinet/ip.h>
#ifdef HAVE_IPV6_MULTICAST_HOST
#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#endif
#ifdef __linux__
#include <net/ethernet.h>
#include <netpacket/packet.h>
#endif

#include "iface.h"
#include "kern.h"
#include "log.h"
#include "mld.h"
#include "mrdisc.h"
#include "socket.h"
#include "util.h"

/*
 * Raw IGMP socket used as interface for the IPv4 mrouted API.
 * Receives IGMP packets and upcall messages from the kernel.
 */
static int sd4 = -1;
/*
 * Raw ICMPv6 socket used as interface for the IPv6 mrouted API.
 * Receives MLD packets and upcall messages from the kenrel.
 */
static int sd6 = -1;

/* Router Alert for queries, RFC 3376 §4.1.3 and RFC 3810 §5 */
static const uint8_t ra4[4] = { IPOPT_RA, 4, 0, 0 };
#ifdef HAVE_IPV6_MULTICAST_HOST
/* Hop-by-hop header with the Router Alert option, RFC 2711 */
struct hbh_ra {
	struct ip6_hbh        hdr;
	struct ip6_opt_router ra;
	uint8_t               pad[2];
};
static const struct hbh_ra ra6 = {
	.hdr = { .ip6h_nxt = IPPROTO_ICMPV6 },
	.ra  = { .ip6or_type = IP6OPT_ROUTER_ALERT, .ip6or_len = 2 },
	.pad = { IP6OPT_PADN, 0 },
};
#endif

/* IPv4 internal virtual interfaces (VIF) descriptor vector */
static struct {
	struct iface *iface;
} vif_list[MAX_MC_VIFS];

/* IPv6 internal virtual interfaces (VIF) descriptor vector */
static struct mif {
	struct iface *iface;
} mif_list[MAX_MC_VIFS];


/*
 * This function handles both ASM and SSM join/leave for IPv4 and IPv6
 * using the RFC 3678 API available on Linux, FreeBSD, and a few other
 * operating systems.
 *
 * On Linux this makes it possible to join a group on an interface that
 * is down and/or has no IP address assigned to it yet.  The latter is
 * one of the most common causes of malfunction on Linux and IPv4 with
 * the old struct ip_mreq API.
 */
#ifdef HAVE_STRUCT_GROUP_REQ	/* Prefer RFC 3678 */
static int group_req(int sd, int cmd, struct mcgroup *mcg)
{
	char source[INET_ADDRSTR_LEN], group[INET_ADDRSTR_LEN];
	struct group_source_req gsr = { 0 };
	struct group_req gr = { 0 };
	size_t len;
	void *arg;
	int op, proto;

#ifdef HAVE_IPV6_MULTICAST_HOST
	if (mcg->group.ss_family == AF_INET6)
		proto = IPPROTO_IPV6;
	else
#endif
		proto = IPPROTO_IP;

	if (is_anyaddr(&mcg->source)) {
		if (cmd)	op = MCAST_JOIN_GROUP;
		else		op = MCAST_LEAVE_GROUP;

		arg                = &gr;
		len                = sizeof(gr);
		gr.gr_interface    = mcg->iface->ifindex;
		gr.gr_group        = mcg->group;

		strncpy(source, "*", sizeof(source));
		inet_addr2str(&gr.gr_group, group, sizeof(group));
	} else {
		if (cmd)	op = MCAST_JOIN_SOURCE_GROUP;
		else		op = MCAST_LEAVE_SOURCE_GROUP;

		arg                = &gsr;
		len                = sizeof(gsr);
		gsr.gsr_interface  = mcg->iface->ifindex;
		gsr.gsr_source     = mcg->source;
		gsr.gsr_group      = mcg->group;

		inet_addr2str(&gsr.gsr_source, source, sizeof(source));
		inet_addr2str(&gsr.gsr_group, group, sizeof(group));
	}

	smclog(LOG_DEBUG, "%s group (%s,%s) on ifindex %d and socket %d ...",
	       cmd ? "Join" : "Leave", source, group, mcg->iface->ifindex, sd);

	return setsockopt(sd, proto, op, arg, len);
}

#else  /* Assume we have old style struct ip_mreq */

static int group_req(int sd, int cmd, struct mcgroup *mcg)
{
	char group[INET_ADDRSTR_LEN];
#ifdef HAVE_IPV6_MULTICAST_HOST
	struct ipv6_mreq ipv6mr = { 0 };
#endif
#ifdef HAVE_STRUCT_IP_MREQN
	struct ip_mreqn imr = { 0 };
#else
	struct ip_mreq imr = { 0 };
#endif
	int op, proto;
	size_t len;
	void *arg;

#ifdef HAVE_IPV6_MULTICAST_HOST
	if (mcg->group.ss_family == AF_INET6) {
		struct sockaddr_in6 *sin6;

		sin6 = inet_addr6_get(&mcg->group);
		ipv6mr.ipv6mr_multiaddr = sin6->sin6_addr;
		ipv6mr.ipv6mr_interface = mcg->iface->ifindex;

		proto = IPPROTO_IPV6;
		op    = cmd ? IPV6_JOIN_GROUP : IPV6_LEAVE_GROUP;
		arg   = &ipv6mr;
		len   = sizeof(ipv6mr);
	} else
#endif
	{
		imr.imr_multiaddr = *inet_addr_get(&mcg->group);
#ifdef HAVE_STRUCT_IP_MREQN
		imr.imr_ifindex   = mcg->iface->ifindex;
#else
		imr.imr_interface = mcg->iface->inaddr;
#endif

		proto = IPPROTO_IP;
		op    = cmd ? IP_ADD_MEMBERSHIP : IP_DROP_MEMBERSHIP;
		arg   = &imr;
		len   = sizeof(imr);
	}

	smclog(LOG_DEBUG, "%s group (*,%s) on ifindex %d ...", cmd ? "Join" : "Leave",
	       inet_addr2str(&mcg->group, group, sizeof(group)), mcg->iface->ifindex);

	return setsockopt(sd, proto, op, arg, len);
}
#endif

int kern_join_leave(int sd, int cmd, struct mcgroup *mcg)
{
	if (group_req(sd, cmd, mcg)) {
		char source[INET_ADDRSTR_LEN] = "*";
		char group[INET_ADDRSTR_LEN];
		int len;

		if (!is_anyaddr(&mcg->source))
			inet_addr2str(&mcg->source, source, sizeof(source));
		inet_addr2str(&mcg->group, group, sizeof(group));
		len = mcg->len == 0 ? 32 : mcg->len;

		smclog(LOG_ERR, "Failed %s group (%s,%s/%d) on sd %d ... %d: %s",
		       cmd ? "joining" : "leaving",
		       source, group, len, sd,
		       errno, strerror(errno));
		return 1;
	}

	return 0;
}

/* Replace the source filter of @sd's membership of @group on @iface, RFC 3678 */
int kern_set_filter(int sd, struct iface *iface, inet_addr_t *group, int exclude, inet_addr_t *srcs, int num)
{
#ifdef HAVE_STRUCT_GROUP_REQ
	socklen_t len = sizeof(struct sockaddr_in);

#ifdef HAVE_IPV6_MULTICAST_HOST
	if (group->ss_family == AF_INET6)
		len = sizeof(struct sockaddr_in6);
#endif
	return setsourcefilter(sd, iface->ifindex, (struct sockaddr *)group, len,
			       exclude ? MCAST_EXCLUDE : MCAST_INCLUDE, num, srcs);
#else
	(void)sd; (void)iface; (void)group; (void)exclude; (void)srcs; (void)num;
	return errno = ENOTSUP;
#endif
}

/*
 * Read a packet from one of the mrouted sockets along with its ancillary
 * data.  The IPv4 header is part of the data, the IPv6 one is not.
 */
ssize_t kern_recv(int sd, void *buf, size_t len, struct kern_rx *rx)
{
	struct sockaddr_storage from;
	struct cmsghdr *cmsg;
	struct msghdr msgh;
	struct iovec iov;
	char cmbuf[256];
	ssize_t num;

	memset(rx, 0, sizeof(*rx));
	rx->hlim = -1;

	iov.iov_base = buf;
	iov.iov_len  = len;

	memset(&msgh, 0, sizeof(msgh));
	msgh.msg_name       = &from;
	msgh.msg_namelen    = sizeof(from);
	msgh.msg_iov        = &iov;
	msgh.msg_iovlen     = 1;
	msgh.msg_control    = cmbuf;
	msgh.msg_controllen = sizeof(cmbuf);

	num = recvmsg(sd, &msgh, 0);
	if (num < 0)
		return -1;

	for (cmsg = CMSG_FIRSTHDR(&msgh); cmsg; cmsg = CMSG_NXTHDR(&msgh, cmsg)) {
#ifdef IP_PKTINFO
		if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO) {
			struct in_pktinfo ipi;

			memcpy(&ipi, CMSG_DATA(cmsg), sizeof(ipi));
			rx->ifindex = ipi.ipi_ifindex;
		}
#elif defined(IP_RECVIF)
		if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_RECVIF)
			rx->ifindex = ((struct sockaddr_dl *)CMSG_DATA(cmsg))->sdl_index;
#endif
#ifdef HAVE_IPV6_MULTICAST_HOST
		if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO) {
			struct in6_pktinfo ipi6;

			memcpy(&ipi6, CMSG_DATA(cmsg), sizeof(ipi6));
			rx->ifindex = ipi6.ipi6_ifindex;
		}
		if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_HOPLIMIT)
			memcpy(&rx->hlim, CMSG_DATA(cmsg), sizeof(rx->hlim));
#endif
	}

#ifdef HAVE_IPV6_MULTICAST_HOST
	if (msgh.msg_namelen >= sizeof(struct sockaddr_in6) && from.ss_family == AF_INET6)
		inet_addr6_set(&rx->src, &((struct sockaddr_in6 *)&from)->sin6_addr);
#endif

	return num;
}

/*
 * Send a query or report on @iface from the mrouted socket of @dst's family.
 * The sockets carry the Router Alert option and hop limit 1.
 */
#if defined(__linux__) && defined(ENABLE_PROXY)
/* Packet socket for queries from 0.0.0.0 and ::, send only */
static int sdp = -1;

int kern_proxy_queries(void)
{
	return sdp != -1;
}

/* ICMPv6 checksum with the pseudo-header, RFC 8200 §8.1 */
static uint16_t icmp6_cksum(const struct ip6_hdr *ip6, const void *buf, size_t len)
{
	struct {
		struct in6_addr src, dst;
		uint32_t        len;
		uint8_t         zero[3], nxt;
	} ph = { ip6->ip6_src, ip6->ip6_dst, htonl(len), { 0 }, IPPROTO_ICMPV6 };
	uint32_t sum;

	sum  = (uint16_t)~inet_cksum(&ph, sizeof(ph));
	sum += (uint16_t)~inet_cksum(buf, len);
	sum  = (sum >> 16) + (sum & 0xffff);

	return ~sum;
}

/* Queries from 0.0.0.0 and ::, Linux fills in the address on raw IP sockets */
static int send_raw(struct iface *iface, inet_addr_t *dst, const void *buf, size_t len)
{
	struct sockaddr_ll sll = {
		.sll_family  = AF_PACKET,
		.sll_ifindex = iface->ifindex,
		.sll_halen   = ETH_ALEN,
	};
	uint8_t pkt[256];
	size_t hlen;

	if (sdp == -1)
		return errno = EAGAIN;

#ifdef HAVE_IPV6_MULTICAST_HOST
	if (dst->ss_family == AF_INET6) {
		struct ip6_hdr *ip6 = (struct ip6_hdr *)pkt;
		struct icmp6_hdr *icmp6;
		const uint8_t *d;

		hlen = sizeof(*ip6) + sizeof(ra6);
		if (hlen + len > sizeof(pkt))
			return errno = EMSGSIZE;

		memset(ip6, 0, sizeof(*ip6));
		ip6->ip6_flow = htonl(6 << 28);
		ip6->ip6_plen = htons(sizeof(ra6) + len);
		ip6->ip6_nxt  = IPPROTO_HOPOPTS;
		ip6->ip6_hlim = 1;
		ip6->ip6_dst  = inet_addr6_get(dst)->sin6_addr;
		memcpy(ip6 + 1, &ra6, sizeof(ra6));

		icmp6 = memcpy(pkt + hlen, buf, len);
		icmp6->icmp6_cksum = 0;
		icmp6->icmp6_cksum = icmp6_cksum(ip6, icmp6, len);

		/* RFC 2464 §7 */
		d = ip6->ip6_dst.s6_addr;
		sll.sll_protocol = htons(ETH_P_IPV6);
		memcpy(sll.sll_addr, (uint8_t []){ 0x33, 0x33, d[12], d[13], d[14], d[15] }, ETH_ALEN);
	} else
#endif
	{
		struct ip *ip = (struct ip *)pkt;
		uint32_t d;

		hlen = sizeof(*ip) + sizeof(ra4);
		if (hlen + len > sizeof(pkt))
			return errno = EMSGSIZE;

		memset(ip, 0, sizeof(*ip));
		ip->ip_v   = 4;
		ip->ip_hl  = hlen / 4;
		ip->ip_tos = IPTOS_PREC_INTERNETCONTROL;
		ip->ip_len = htons(hlen + len);
		ip->ip_ttl = 1;
		ip->ip_p   = IPPROTO_IGMP;
		ip->ip_dst = *inet_addr_get(dst);
		memcpy(ip + 1, ra4, sizeof(ra4));
		ip->ip_sum = inet_cksum(ip, hlen);
		memcpy(pkt + hlen, buf, len);

		/* RFC 1112 §6.4 */
		d = ntohl(ip->ip_dst.s_addr);
		sll.sll_protocol = htons(ETH_P_IP);
		memcpy(sll.sll_addr, (uint8_t []){ 0x01, 0x00, 0x5e, (d >> 16) & 0x7f, d >> 8, d }, ETH_ALEN);
	}

	if (sendto(sdp, pkt, hlen + len, 0, (struct sockaddr *)&sll, sizeof(sll)) < 0)
		return -1;

	return 0;
}
#else
int kern_proxy_queries(void)
{
	return 0;
}

static int send_raw(struct iface *iface, inet_addr_t *dst, const void *buf, size_t len)
{
	(void)iface;
	(void)dst;
	(void)buf;
	(void)len;

	return errno = EOPNOTSUPP;
}
#endif

/*
 * Send an IGMP or MLD message on @iface from @src to @dst.  The raw
 * sockets carry the Router Alert option and hop limit 1 and use the
 * interface address, an unspecified @src goes out as a proxy query.
 */
int kern_send(struct iface *iface, inet_addr_t *src, inet_addr_t *dst, const void *buf, size_t len)
{
	inet_addr_t to = *dst;
	socklen_t slen;
	int sd;

	if (is_anyaddr(src))
		return send_raw(iface, dst, buf, len);

#ifdef HAVE_IPV6_MULTICAST_HOST
	if (dst->ss_family == AF_INET6) {
		int ifindex = iface->ifindex;

		if (sd6 == -1)
			return errno = EAGAIN;
		if (setsockopt(sd6, IPPROTO_IPV6, IPV6_MULTICAST_IF, &ifindex, sizeof(ifindex)))
			return -1;

		inet_addr6_get(&to)->sin6_scope_id = ifindex;
		slen = sizeof(struct sockaddr_in6);
		sd = sd6;
	} else
#endif
	{
#ifdef HAVE_STRUCT_IP_MREQN
		struct ip_mreqn imr = { .imr_ifindex = iface->ifindex };
#else
		struct in_addr imr = iface->inaddr;
#endif
		if (sd4 == -1)
			return errno = EAGAIN;
		if (setsockopt(sd4, IPPROTO_IP, IP_MULTICAST_IF, &imr, sizeof(imr)))
			return -1;

		slen = sizeof(struct sockaddr_in);
		sd = sd4;
	}

	if (sendto(sd, buf, len, 0, (struct sockaddr *)&to, slen) < 0)
		return -1;

	return 0;
}

int kern_mroute_init(int table_id, void (*cb)(int, void *), void *arg)
{
	int val = 1;

	if (sd4 < 0) {
		sd4 = socket_create(AF_INET, SOCK_RAW, IPPROTO_IGMP, cb, arg);
		if (sd4 < 0)
			return -1;
	}

#if defined(__linux__) && defined(ENABLE_PROXY)
	/* send only, protocol 0 receives nothing, needs CAP_NET_RAW before dropping root */
	if (sdp < 0) {
		sdp = socket(AF_PACKET, SOCK_DGRAM, 0);
		if (sdp < 0)
			smclog(LOG_WARNING, "Failed creating packet socket, no proxy queries: %s", strerror(errno));
	}
#endif

#ifdef MRT_TABLE /* Currently only available on Linux  */
	if (table_id != 0) {
		smclog(LOG_INFO, "Setting IPv4 multicast routing table id %d", table_id);
		if (setsockopt(sd4, IPPROTO_IP, MRT_TABLE, &table_id, sizeof(table_id)) < 0) {
			errno = EPROTONOSUPPORT;
			goto error;
		}
	}
#else
	(void)table_id;
#endif

	if (setsockopt(sd4, IPPROTO_IP, MRT_INIT, &val, sizeof(val)))
		goto error;

	/* Enable "PIM" to get WRONGVIF messages */
	if (setsockopt(sd4, IPPROTO_IP, MRT_PIM, &val, sizeof(val)))
		smclog(LOG_ERR, "Failed enabling PIM IGMPMSG_WRONGVIF, ignoring: %s", strerror(errno));

	/* For queries, RFC 3376 §4.1.3 */
	if (setsockopt(sd4, IPPROTO_IP, IP_OPTIONS, ra4, sizeof(ra4)))
		smclog(LOG_WARNING, "Failed setting Router Alert option: %s", strerror(errno));
	if (setsockopt(sd4, IPPROTO_IP, IP_MULTICAST_TTL, &val, sizeof(val)))
		smclog(LOG_WARNING, "Failed setting multicast TTL: %s", strerror(errno));

	/* Reports to 224.0.0.22 are delivered locally, not via the router alert chain */
#ifdef IP_MULTICAST_ALL
	if (setsockopt(sd4, IPPROTO_IP, IP_MULTICAST_ALL, &val, sizeof(val)))
		smclog(LOG_WARNING, "Failed enabling IP_MULTICAST_ALL: %s", strerror(errno));
#endif

	/* Ingress interface of IGMP packets, proxy reports may come from 0.0.0.0 */
#ifdef IP_PKTINFO
	if (setsockopt(sd4, IPPROTO_IP, IP_PKTINFO, &val, sizeof(val)))
		smclog(LOG_WARNING, "Failed enabling IP_PKTINFO: %s", strerror(errno));
#elif defined(IP_RECVIF)
	if (setsockopt(sd4, IPPROTO_IP, IP_RECVIF, &val, sizeof(val)))
		smclog(LOG_WARNING, "Failed enabling IP_RECVIF: %s", strerror(errno));
#endif

	/* Initialize virtual interface table */
	memset(&vif_list, 0, sizeof(vif_list));

	return 0;
error:
	socket_close(sd4);
	sd4 = -1;

	return -1;
}

int kern_mroute_exit(void)
{
	if (sd4 == -1)
		return errno = EAGAIN;

	/* Drop all kernel routes set by smcroute */
	if (setsockopt(sd4, IPPROTO_IP, MRT_DONE, NULL, 0))
		smclog(LOG_WARNING, "Failed shutting down IPv4 multicast routing socket: %s",
		       strerror(errno));

	socket_close(sd4);
	sd4 = -1;
#if defined(__linux__) && defined(ENABLE_PROXY)
	if (sdp != -1)
		close(sdp);
	sdp = -1;
#endif

	return 0;
}

int kern_vif_add(struct iface *iface)
{
	struct vifctl vifc = { 0 };
	size_t i;
	int vif;

	if (!iface)
		return errno = EINVAL;
	if ((iface->flags & IFF_MULTICAST) != IFF_MULTICAST)
		return errno = ENOPROTOOPT;
	if (sd4 == -1)
		return errno = EAGAIN;
	if (iface->vif != NO_VIF)
		return errno = EEXIST;

	/* find a free vif */
	for (i = 0, vif = -1; i < NELEMS(vif_list); i++) {
		if (!vif_list[i].iface) {
			vif = i;
			break;
		}
	}

	if (vif == -1)
		return errno = ENOMEM;

	memset(&vifc, 0, sizeof(vifc));
	vifc.vifc_vifi = vif;
	vifc.vifc_flags = 0;      /* no tunnel, no source routing, register ? */
	vifc.vifc_threshold = iface->threshold;
	vifc.vifc_rate_limit = 0;	/* hopefully no limit */
#ifdef VIFF_USE_IFINDEX		/* Register VIF using ifindex, not lcl_addr, since Linux 2.6.33 */
	vifc.vifc_flags |= VIFF_USE_IFINDEX;
	vifc.vifc_lcl_ifindex = iface->ifindex;
#else
	vifc.vifc_lcl_addr.s_addr = iface->inaddr.s_addr;
#endif
	vifc.vifc_rmt_addr.s_addr = htonl(INADDR_ANY);

	smclog(LOG_DEBUG, "Map iface %-16s => VIF %-2d ifindex %2d flags 0x%04x TTL threshold %u",
	       iface->ifname, vifc.vifc_vifi, iface->ifindex, vifc.vifc_flags, iface->threshold);

	if (setsockopt(sd4, IPPROTO_IP, MRT_ADD_VIF, &vifc, sizeof(vifc)))
		return 1;

	iface->vif = vif;
	vif_list[vif].iface = iface;

	return 0;
}

int kern_vif_del(struct iface *iface)
{
	struct vifctl vifc = { 0 };
	int rc;

	if (sd4 == -1)
		return errno = EAGAIN;
	if (!iface)
		return errno = EINVAL;
	if (iface->vif == NO_VIF)
		return errno = ENOENT;

	smclog(LOG_DEBUG, "Removing  %-16s => VIF %-2d", iface->ifname, iface->vif);

	vifc.vifc_vifi = iface->vif;
#ifdef __linux__
	rc = setsockopt(sd4, IPPROTO_IP, MRT_DEL_VIF, &vifc, sizeof(vifc));
#else
	rc = setsockopt(sd4, IPPROTO_IP, MRT_DEL_VIF, &vifc.vifc_vifi, sizeof(vifc.vifc_vifi));
#endif
	if (!rc) {
		vif_list[iface->vif].iface = NULL;
		iface->vif = -1;
	}

	return rc;
}

static int kern_mroute4(int cmd, struct mroute *route)
{
	char origin[INET_ADDRSTRLEN], group[INET_ADDRSTRLEN];
	int op = cmd ? MRT_ADD_MFC : MRT_DEL_MFC;
	struct mfcctl mfcc = { 0 };
	size_t i;

	if (sd4 == -1) {
		smclog(LOG_DEBUG, "No IPv4 multicast socket");
		return -1;
	}

	memset(&mfcc, 0, sizeof(mfcc));
	mfcc.mfcc_origin   = *inet_addr_get(&route->source);
	mfcc.mfcc_mcastgrp = *inet_addr_get(&route->group);
	mfcc.mfcc_parent   = route->inbound;

	inet_addr2str(&route->source, origin, sizeof(origin));
	inet_addr2str(&route->group, group, sizeof(group));

	/* copy the TTL vector, as many as the kernel supports */
	for (i = 0; i < NELEMS(mfcc.mfcc_ttls); i++)
		mfcc.mfcc_ttls[i] = route->ttl[i];

	if (setsockopt(sd4, IPPROTO_IP, op, &mfcc, sizeof(mfcc))) {
		if (ENOENT == errno)
			smclog(LOG_DEBUG, "failed removing multicast route (%s,%s), does not exist.",
				origin, group);
		else
			smclog(LOG_WARNING, "failed %s IPv4 multicast route (%s,%s): %s",
			       cmd ? "adding" : "removing", origin, group, strerror(errno));
		return 1;
	}

	smclog(LOG_DEBUG, "%s %s -> %s from VIF %d", cmd ? "Add" : "Del",
	       origin, group, route->inbound);

	return 0;
}

static int kern_stats4(struct mroute *route, struct mroute_stats *ms)
{
	struct sioc_sg_req sg_req = { 0 };

	if (sd4 == -1)
		return errno = EAGAIN;

	memset(&sg_req, 0, sizeof(sg_req));
	sg_req.src = *inet_addr_get(&route->source);
	sg_req.grp = *inet_addr_get(&route->group);

	if (ioctl(sd4, SIOCGETSGCNT, &sg_req) < 0) {
		if (ms->ms_wrong_if)
			smclog(LOG_WARNING, "Failed getting MFC stats: %s", strerror(errno));
		return errno;
	}

	ms->ms_pktcnt   = sg_req.pktcnt;
	ms->ms_bytecnt  = sg_req.bytecnt;
	ms->ms_wrong_if = sg_req.wrong_if;

	return 0;
}

#ifdef  HAVE_IPV6_MULTICAST_HOST
#ifdef __linux__
#define IPV6_ALL_MC_FORWARD "/proc/sys/net/ipv6/conf/all/mc_forwarding"

static int proc_set_val(char *file, int val)
{
	int fd, rc = 0;

	fd = open(file, O_WRONLY);
	if (fd < 0)
		return 1;

	if (-1 == write(fd, "1", val))
		rc = 1;

	close(fd);

	return rc;
}
#endif /* Linux only */

int kern_mroute6_init(int table_id, void (*cb)(int, void *), void *arg)
{
	struct icmp6_filter filt;
	int val = 1;

	if (sd6 < 0) {
		sd6 = socket_create(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6, cb, arg);
		if (sd6 < 0)
			return -1;
	}

#ifdef MRT6_TABLE /* Currently only available on Linux  */
	if (table_id != 0) {
		smclog(LOG_INFO, "Setting IPv6 multicast routing table id %d", table_id);
		if (setsockopt(sd6, IPPROTO_IPV6, MRT6_TABLE, &table_id, sizeof(table_id)) < 0) {
			errno = EPROTONOSUPPORT;
			goto error;
		}
	}
#else
	(void)table_id;
#endif

	if (setsockopt(sd6, IPPROTO_IPV6, MRT6_INIT, &val, sizeof(val)))
		goto error;

	/* For queries, RFC 3810 §5, the kernel sets the next header */
	if (setsockopt(sd6, IPPROTO_IPV6, IPV6_HOPOPTS, &ra6, sizeof(ra6)))
		smclog(LOG_WARNING, "Failed setting Router Alert option: %s", strerror(errno));
	if (setsockopt(sd6, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &val, sizeof(val)))
		smclog(LOG_WARNING, "Failed setting multicast hop limit: %s", strerror(errno));

#ifdef IPV6_MULTICAST_ALL
	if (setsockopt(sd6, IPPROTO_IPV6, IPV6_MULTICAST_ALL, &val, sizeof(val)))
		smclog(LOG_WARNING, "Failed enabling IPV6_MULTICAST_ALL: %s", strerror(errno));
#endif
	if (setsockopt(sd6, IPPROTO_IPV6, IPV6_RECVPKTINFO, &val, sizeof(val)))
		smclog(LOG_WARNING, "Failed enabling IPV6_RECVPKTINFO: %s", strerror(errno));
	if (setsockopt(sd6, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &val, sizeof(val)))
		smclog(LOG_WARNING, "Failed enabling IPV6_RECVHOPLIMIT: %s", strerror(errno));

	/* Only MLD, kernel upcalls are queued directly and bypass the filter */
	ICMP6_FILTER_SETBLOCKALL(&filt);
	ICMP6_FILTER_SETPASS(MLD_LISTENER_QUERY, &filt);
	ICMP6_FILTER_SETPASS(MLD_LISTENER_REPORT, &filt);
	ICMP6_FILTER_SETPASS(MLD_LISTENER_REDUCTION, &filt);
	ICMP6_FILTER_SETPASS(MLDV2_LISTENER_REPORT, &filt);
	if (setsockopt(sd6, IPPROTO_ICMPV6, ICMP6_FILTER, &filt, sizeof(filt)))
		smclog(LOG_WARNING, "Failed setting ICMPv6 filter: %s", strerror(errno));

	/* Initialize virtual interface table */
	memset(&mif_list, 0, sizeof(mif_list));

#ifdef __linux__
	/*
	 * On Linux pre 2.6.29 kernels net.ipv6.conf.all.mc_forwarding
	 * is not set on MRT6_INIT so we have to do this manually
	 */
	if (proc_set_val(IPV6_ALL_MC_FORWARD, 1)) {
		if (errno != EACCES) {
			smclog(LOG_ERR, "Failed enabling IPv6 multicast forwarding: %s",
			       strerror(errno));
			goto error;
		}
	}
#endif

	return 0;
error:
	socket_close(sd6);
	sd6 = -1;

	return -1;
}

int kern_mroute6_exit(void)
{
	if (sd6 == -1)
		return errno = EAGAIN;

	if (setsockopt(sd6, IPPROTO_IPV6, MRT6_DONE, NULL, 0))
		smclog(LOG_WARNING, "Failed shutting down IPv6 multicast routing socket: %s",
		       strerror(errno));

	socket_close(sd6);
	sd6 = -1;

	return 0;
}

/* Create a virtual interface from @iface so it can be used for IPv6 multicast routing. */
int kern_mif_add(struct iface *iface)
{
	struct mif6ctl mif6c = { 0 };
	int mif = -1;
	size_t i;

	if (sd6 == -1)
		return errno = EAGAIN;
	if (!iface)
		return errno = EINVAL;
	if ((iface->flags & IFF_MULTICAST) != IFF_MULTICAST)
		return errno = ENOPROTOOPT;
	if (iface->mif != NO_VIF)
		return errno = EEXIST;

	/* find a free mif */
	for (i = 0; i < NELEMS(mif_list); i++) {
		if (!mif_list[i].iface) {
			mif = i;
			break;
		}
	}

	if (mif == -1)
		return errno = ENOMEM;

	memset(&mif6c, 0, sizeof(mif6c));
	mif6c.mif6c_mifi = mif;
	mif6c.mif6c_flags = 0;             /* no register */
#ifdef HAVE_MIF6CTL_VIFC_THRESHOLD
	mif6c.vifc_threshold = iface->threshold;
#endif
	mif6c.mif6c_pifi = iface->ifindex; /* physical interface index */
#ifdef HAVE_MIF6CTL_VIFC_RATE_LIMIT
	mif6c.vifc_rate_limit = 0;         /* hopefully no limit */
#endif

	smclog(LOG_DEBUG, "Map iface %-16s => MIF %-2d ifindex %2d flags 0x%04x TTL threshold %u",
	       iface->ifname, mif6c.mif6c_mifi, mif6c.mif6c_pifi, mif6c.mif6c_flags, iface->threshold);

	if (setsockopt(sd6, IPPROTO_IPV6, MRT6_ADD_MIF, &mif6c, sizeof(mif6c)))
		return -1;

	iface->mif = mif;
	mif_list[mif].iface = iface;

	return 0;
}

int kern_mif_del(struct iface *iface)
{
	int rc;

	if (sd6 == -1)
		return errno = EAGAIN;
	if (!iface)
		return errno = EINVAL;
	if (iface->mif == NO_VIF)
		return errno = ENOENT;

	smclog(LOG_DEBUG, "Removing  %-16s => MIF %-2d", iface->ifname, iface->mif);

	rc = setsockopt(sd6, IPPROTO_IPV6, MRT6_DEL_MIF, &iface->mif, sizeof(iface->mif));
	if (!rc) {
		mif_list[iface->mif].iface = NULL;
		iface->mif = -1;
	}

	return rc;
}

static int kern_mroute6(int cmd, struct mroute *route)
{
	char origin[INET_ADDRSTR_LEN], group[INET_ADDRSTR_LEN];
	int op = cmd ? MRT6_ADD_MFC : MRT6_DEL_MFC;
	struct mf6cctl mf6cc = { 0 };
	size_t i;

	if (sd6 == -1)
		return errno = EAGAIN;
	if (!route)
		return errno = EINVAL;

	memset(&mf6cc, 0, sizeof(mf6cc));
	mf6cc.mf6cc_origin   = *inet_addr6_get(&route->source);
	mf6cc.mf6cc_mcastgrp = *inet_addr6_get(&route->group);
	mf6cc.mf6cc_parent   = route->inbound;

	inet_addr2str(&route->source, origin, INET_ADDRSTR_LEN);
	inet_addr2str(&route->group, group, INET_ADDRSTR_LEN);

	IF_ZERO(&mf6cc.mf6cc_ifset);
	for (i = 0; i < NELEMS(route->ttl); i++) {
		if (route->ttl[i]) {
			IF_SET(i, &mf6cc.mf6cc_ifset);
		}
	}

	if (setsockopt(sd6, IPPROTO_IPV6, op, &mf6cc, sizeof(mf6cc))) {
		if (ENOENT == errno)
			smclog(LOG_DEBUG, "failed removing IPv6 multicast route (%s,%s), "
			       "does not exist.", origin, group);
		else
			smclog(LOG_WARNING, "failed %s IPv6 multicast route (%s,%s): %s",
			       cmd ? "adding" : "removing", origin, group, strerror(errno));
		return 1;
	}

	smclog(LOG_DEBUG, "%s %s -> %s from VIF %d", cmd ? "Add" : "Del",
	       origin, group, route->inbound);

	return 0;
}

static int kern_stats6(struct mroute *route, struct mroute_stats *ms)
{
	struct sioc_sg_req6 sg_req = { 0 };

	if (sd6 == -1)
		return errno = EAGAIN;

	sg_req.src = *inet_addr6_get(&route->source);
	sg_req.grp = *inet_addr6_get(&route->group);

	if (ioctl(sd6, SIOCGETSGCNT_IN6, &sg_req) < 0) {
		if (ms->ms_wrong_if)
			smclog(LOG_WARNING, "Failed getting MFC stats: %s", strerror(errno));
		return errno;
	}

	ms->ms_pktcnt   = sg_req.pktcnt;
	ms->ms_bytecnt  = sg_req.bytecnt;
	ms->ms_wrong_if = sg_req.wrong_if;

	return 0;
}
#endif /* HAVE_IPV6_MULTICAST_HOST */

/*
 * Query kernel for route usage statistics
 */
int kern_stats(struct mroute *route, struct mroute_stats *ms)
{
	if (!route || !ms)
		return errno = EINVAL;

#ifdef  HAVE_IPV6_MULTICAST_HOST
	if (route->group.ss_family == AF_INET6)
		return kern_stats6(route, ms);
#endif

	return kern_stats4(route, ms);
}

int kern_mroute_add(struct mroute *route)
{
	if (!route)
		return errno = EINVAL;

#ifdef  HAVE_IPV6_MULTICAST_HOST
	if (route->group.ss_family == AF_INET6)
		return kern_mroute6(1, route);
#endif

	return kern_mroute4(1, route);
}

int kern_mroute_del(struct mroute *route)
{
	if (!route)
		return errno = EINVAL;

#ifdef  HAVE_IPV6_MULTICAST_HOST
	if (route->group.ss_family == AF_INET6)
		return kern_mroute6(0, route);
#endif

	return kern_mroute4(0, route);
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
