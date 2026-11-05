/* Generic kernel multicast routing API for Linux and *BSD
 *
 * Copyright (C) 2001-2005  Carsten Schill <carsten@cschill.de>
 * Copyright (C) 2006-2009  Julien BLACHE <jb@jblache.org>
 * Copyright (C) 2009       Todd Hayton <todd.hayton@gmail.com>
 * Copyright (C) 2009-2011  Micha Lenk <micha@debian.org>
 * Copyright (C) 2011-2026  Joachim Wiberg <troglobit@gmail.com>
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
#include "queue.h"

#include <errno.h>
#include <string.h>
#include <stdio.h>		/* snprintf() */
#include <sysexits.h>
#include <unistd.h>
#include <time.h>

#include "log.h"
#include "iface.h"
#include "ipc.h"
#include "script.h"
#include "mrdisc.h"
#include "mroute.h"
#include "kern.h"
#include "igmp.h"
#include "mld.h"
#include "proxy.h"
#include "timer.h"
#include "util.h"

/*
 * Cache flush timeout, used for learned S in (*,G) that stop xmit
 */
static int cache_timeout = 0;

/*
 * User added/configured routes, both ASM and SSM
 */
static TAILQ_HEAD(cl, mroute) conf_list = TAILQ_HEAD_INITIALIZER(conf_list);

/*
 * Kernel MFC
 */
static TAILQ_HEAD(kl, mroute) kern_list = TAILQ_HEAD_INITIALIZER(kern_list);

static int  mroute4_add_vif    (struct iface *iface);
static int  mroute_dyn_add     (struct mroute *route);
static int  mroute_resolve     (struct mroute *route);
static int  is_match           (struct mroute *rule, struct mroute *cand);
static int  is_exact_match     (struct mroute *rule, struct mroute *cand);
static void mfc_prune_vif      (int family, int vif);

/* Check for kernel IGMPMSG_NOCACHE for (*,G) hits. I.e., source-less routes. */
static void handle_nocache4(int sd, void *arg)
{
	char origin[INET_ADDRSTRLEN], group[INET_ADDRSTRLEN];
	struct mroute mroute = { 0 };
	struct igmpmsg *im;
	struct iface *iface;
	struct kern_rx rx;
	struct ip *ip;
	char tmp[2048];
	int result;

	(void)arg;
	result = kern_recv(sd, tmp, sizeof(tmp), &rx);
	if (result < 0) {
		smclog(LOG_WARNING, "Failed reading IGMP message from kernel: %s", strerror(errno));
		return;
	}

	if ((size_t)result < sizeof(*ip))
		return;

	ip = (struct ip *)tmp;
	if (ip->ip_p == IPPROTO_IGMP) {
		igmp_recv(rx.ifindex, (uint8_t *)tmp, result);
		return;
	}

	/* packets sent up from kernel to daemon have ip->ip_p = 0 */
	if (ip->ip_p != 0)
		return;

	im = (struct igmpmsg *)tmp;
	if (im->im_msgtype == 0)
		return;

	inet_addr_set(&mroute.source, &im->im_src);
	inet_addr_set(&mroute.group, &im->im_dst);
	mroute.inbound = im->im_vif;
	mroute.len     = 32;
	mroute.src_len = 32;

	inet_addr2str(&mroute.source, origin, sizeof(origin));
	inet_addr2str(&mroute.group, group, sizeof(group));

	iface = iface_find_by_inbound(&mroute);
	if (!iface) {
		smclog(LOG_WARNING, "No matching interface for VIF %u, cannot handle IGMP message %d.",
		       mroute.inbound, im->im_msgtype);
		return;
	}

	/* check for IGMPMSG_NOCACHE to do (*,G) based routing. */
	switch (im->im_msgtype) {
	case IGMPMSG_NOCACHE:
		/* Find any matching route for this group on that iif. */
		smclog(LOG_DEBUG, "New multicast data from %s to group %s on %s",
		       origin, group, iface->ifname);

		result = mroute_dyn_add(&mroute);
		if (result) {
			/*
			 * This is a common error, the router receives streams it is not
			 * set up to route -- we ignore these by default, but if the user
			 * sets a more permissive log level we help out by showing what
			 * is going on.
			 */
			if (ENOENT == errno)
				smclog(LOG_INFO, "Multicast from %s, group %s, on %s does not match any (*,G) rule",
				       origin, group, iface->ifname);
			return;
		}

		script_exec(&mroute);
		break;

	case IGMPMSG_WRONGVIF:
		if (mroute_resolve(&mroute) == 0) {
			smclog(LOG_NOTICE, "Moved (%s,%s) inbound to %s after WRONGVIF",
			       origin, group, iface->ifname);
			script_exec(&mroute);
		} else {
			smclog(LOG_INFO, "Multicast from %s, group %s on wrong VIF %u, iface %s",
			       origin, group, mroute.inbound, iface->ifname);
		}
		break;

	case IGMPMSG_WHOLEPKT:
#ifdef IGMPMSG_WRVIFWHOLE
	case IGMPMSG_WRVIFWHOLE:
#endif
		smclog(LOG_WARNING, "Receiving PIM register data from %s, group %s", origin, group);
		break;

	default:
		smclog(LOG_DEBUG, "Unknown IGMP message %d from kernel", im->im_msgtype);
		break;
	}
}

static void cache_flush(void *arg)
{
	(void)arg;

	smclog(LOG_INFO, "Cache timeout, flushing unused (*,G) routes!");
	mroute_expire(cache_timeout);
}

/**
 * mroute4_enable - Initialise IPv4 multicast routing
 *
 * Setup the kernel IPv4 multicast routing API and lock the multicast
 * routing socket to this program (only!).
 *
 * Returns:
 * POSIX OK(0) on success, non-zero on error with @errno set.
 */
static int mroute4_enable(int table_id)
{
	if (kern_mroute_init(table_id, handle_nocache4, NULL)) {
		switch (errno) {
		case ENOPROTOOPT:
			smclog(LOG_WARNING, "Kernel does not even support IGMP, skipping ...");
			break;

		case EPROTONOSUPPORT:
			smclog(LOG_ERR, "Cannot set IPv4 multicast routing table id: %s", strerror(errno));
			smclog(LOG_ERR, "Make sure your kernel has CONFIG_IP_MROUTE_MULTIPLE_TABLES=y");
			break;

		case EADDRINUSE:
			smclog(LOG_ERR, "IPv4 multicast routing API already in use: %s",
			       strerror(errno));
			smclog(LOG_ERR, "Is another multicast routing daemon (igmpproxy, mcpd, pimd) running?");
			break;

		case EOPNOTSUPP:
			smclog(LOG_ERR, "Kernel does not support IPv4 multicast routing, skipping ...");
			break;

		default:
			smclog(LOG_ERR, "Failed initializing IPv4 multicast routing API: %s",
			       strerror(errno));
			break;
		}

		return 1;
	}

	return 0;
}

/**
 * mroute4_disable - Disable IPv4 multicast routing
 *
 * Disable IPv4 multicast routing and release kernel routing socket.
 */
static void mroute4_disable(void)
{
	struct mroute *entry, *tmp;

	if (kern_mroute_exit())
		return;

	TAILQ_FOREACH_SAFE(entry, &conf_list, link, tmp) {
		TAILQ_REMOVE(&conf_list, entry, link);
		free(entry);
	}
	TAILQ_FOREACH_SAFE(entry, &kern_list, link, tmp) {
		TAILQ_REMOVE(&kern_list, entry, link);
		free(entry);
	}
}

/* Create a virtual interface from @iface so it can be used for IPv4 multicast routing. */
static int mroute4_add_vif(struct iface *iface)
{
	if (kern_vif_add(iface)) {
		switch (errno) {
		case ENOPROTOOPT:
			smclog(LOG_WARNING, "Interface %s is not multicast capable, skipping VIF.",
			       iface->ifname);
			return -1;

		case EAGAIN:
			smclog(LOG_DEBUG, "No IPv4 multicast socket");
			return -1;

		case ENOMEM:
			smclog(LOG_WARNING, "Not enough available VIFs to create %s", iface->ifname);
			return 1;

		case EEXIST:
			smclog(LOG_DEBUG, "Interface %s already has VIF %d.", iface->ifname, iface->vif);
			return 0;

		default:
			break;
		}

		smclog(LOG_DEBUG, "Failed creating VIF for %s: %s", iface->ifname, strerror(errno));
		return -1;
	}

	if (iface->mrdisc)
		return mrdisc_register(iface->ifname, iface->vif);

	return mrdisc_deregister(iface->vif);
}

static int mroute4_del_vif(struct iface *iface)
{
	int rc = 0;

	if (iface->mrdisc)
		rc = mrdisc_deregister(iface->vif);

	if (iface->vif == ALL_VIFS)
		return 0;

	if (kern_vif_del(iface)) {
		switch (errno) {
		case ENOENT:
		case EADDRNOTAVAIL:
			break;
		default:
			smclog(LOG_ERR, "Failed deleting VIF for iface %s: %s", iface->ifname, strerror(errno));
			break;
		}
		rc = -1;
	}

	if (iface->vif != ALL_VIFS)
		mfc_prune_vif(AF_INET, iface->vif);
	iface->vif = ALL_VIFS;

	return rc;
}

static int is_exact_match(struct mroute *rule, struct mroute *cand)
{
	if (rule->group.ss_family != cand->group.ss_family)
		return 0;
	if (rule->inbound != cand->inbound)
		return 0;

	if (!inet_addr_cmp(&rule->source, &cand->source) &&
	    !inet_addr_cmp(&rule->group,  &cand->group)  &&
	    rule->len     == cand->len                   &&
	    rule->src_len == cand->src_len)
		return 1;

	return 0;
}

/*
 * Used for (*,G) matches
 *
 * The incoming candidate is compared to the configured rule, e.g.
 * does 225.1.2.3 fall inside 225.0.0.0/8?  => Yes
 * does 225.1.2.3 fall inside 225.0.0.0/15? => Yes
 * does 225.1.2.3 fall inside 225.0.0.0/16? => No
 *
 * does ff05:bad1::1 fall inside ff05:bad0::/16? => Yes
 * does ff05:bad1::1 fall inside ff05:bad0::/31? => Yes
 * does ff05:bad1::1 fall inside ff05:bad0::/32? => No
 */
int is_match(struct mroute *rule, struct mroute *cand)
{
	inet_addr_t a, b;
	int rc = 0;

	if (rule->group.ss_family != cand->group.ss_family)
		return 0;
	if (rule->inbound != cand->inbound)
		return rc;

	a = inet_netaddr(&rule->group, rule->len);
	b = inet_netaddr(&cand->group, rule->len);

	rc = !inet_addr_cmp(&a, &b);
	if (is_anyaddr(&rule->source))
		return rc;

	a = inet_netaddr(&rule->source, rule->src_len);
	b = inet_netaddr(&cand->source, rule->src_len);
	rc &= !inet_addr_cmp(&a, &b);

	return rc;
}

static int is_ssm(struct mroute *route)
{
	int max_len = inet_max_len(&route->group);

	return !is_anyaddr(&route->source) && route->src_len == max_len && route->len == max_len;
}

/* find any existing route, with matching inbound interface */
static struct mroute *conf_find(struct mroute *route)
{
	struct mroute *entry;

	TAILQ_FOREACH(entry, &conf_list, link) {
		if (is_exact_match(route, entry))
			return entry;
	}

	return NULL;
}

/*
 * The kernel keys its MFC on (S,G) only, the inbound VIF is a property
 * of the entry.  Mirror that: at most one entry per (S,G).
 */
static struct mroute *mfc_find(struct mroute *route)
{
	struct mroute *entry;

	TAILQ_FOREACH(entry, &kern_list, link) {
		if (inet_addr_cmp(&entry->source, &route->source))
			continue;
		if (!inet_addr_cmp(&entry->group, &route->group))
			return entry;
	}

	return NULL;
}

static int is_active(struct mroute *route)
{
	size_t i;

	for (i = 0; i < NELEMS(route->ttl); i++) {
		if (route->ttl[i])
			return 1;
	}

	return 0;
}

/*
 * Get valid packet usage statistics (i.e. number of actually forwarded
 * packets) from the kernel for an installed MFC entry
 */
static unsigned long get_valid_pkt(struct mroute *route)
{
	struct mroute_stats ms = { 0 };

	if (kern_stats(route, &ms))
		return 0;

	return ms.ms_pktcnt - ms.ms_wrong_if;
}

static int mfc_drop(struct mroute *kern)
{
	int rc;

	rc = kern_mroute_del(kern);
	TAILQ_REMOVE(&kern_list, kern, link);
	free(kern);

	return rc;
}

/**
 * mroute_expire - Expire dynamically added (*,G) routes
 * @max_idle: Timeout for routes in seconds, 0 to expire all dynamic routes
 *
 * This function flushes all (*,G) routes which haven't been used (i.e. no
 * packets matching them have been forwarded) in the last max_idle seconds.
 * It is called periodically on cache-timeout or on request of smcroutectl.
 * The latter is useful in case of topology changes (e.g. VRRP fail-over)
 * or similar.
 */
void mroute_expire(int max_idle)
{
	struct mroute *entry, *tmp;
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);

	TAILQ_FOREACH_SAFE(entry, &kern_list, link, tmp) {
		char origin[INET_ADDRSTR_LEN], group[INET_ADDRSTR_LEN];
		struct iface *iface;

		/* an (S,G) rule pins its entry, learned entries expire */
		if (conf_find(entry))
			continue;

		inet_addr2str(&entry->group, group, sizeof(group));
		inet_addr2str(&entry->source, origin, sizeof(origin));
		iface = iface_find_by_inbound(entry);

		if (!entry->last_use) {
			/* New entry */
			entry->last_use = now.tv_sec;
			entry->valid_pkt = get_valid_pkt(entry);
			continue;
		}

		smclog(LOG_DEBUG, "Checking (%s,%s) on %s, time to expire: last %ld max %d now: %ld",
		       origin, group, iface ? iface->ifname : "UNKNOWN",
		       entry->last_use, max_idle, now.tv_sec);

		if (entry->last_use + max_idle <= now.tv_sec) {
			unsigned long valid_pkt;

			valid_pkt = get_valid_pkt(entry);
			if (valid_pkt != entry->valid_pkt) {
				/* Used since last check, update */
				smclog(LOG_DEBUG, "  -> Nope, still active, valid %lu vs last valid %lu.",
				       valid_pkt, entry->valid_pkt);
				entry->last_use  = now.tv_sec;
				entry->valid_pkt = valid_pkt;
				continue;
			}

			/* Not used, expire */
			smclog(LOG_DEBUG, "  -> Yup, stale route.");
			mfc_drop(entry);
		}
	}
}

/* Rebuild the oif set of kernel entry @kern from every rule covering it */
static void mfc_compute(struct mroute *kern)
{
	struct mroute *conf;

	memset(kern->ttl, 0, sizeof(kern->ttl));
	TAILQ_FOREACH(conf, &conf_list, link) {
		if (!is_match(conf, kern))
			continue;

		for (size_t i = 0; i < NELEMS(kern->ttl); i++) {
			if (conf->ttl[i])
				kern->ttl[i] = conf->ttl[i];
		}
	}

	proxy_oifs(kern);
}

/*
 * Recompute and push @kern to the kernel.  An entry no exact (S,G)
 * rule pins, and no rule gives any oif, is dropped instead.
 */
static int mfc_update(struct mroute *kern)
{
	mfc_compute(kern);
	if (!is_active(kern) && !conf_find(kern))
		return mfc_drop(kern);

	return kern_mroute_add(kern);
}

/* Update every kernel entry covered by @rule, e.g. after it changed */
static int mfc_update_matching(struct mroute *rule)
{
	struct mroute *kern, *tmp;
	int rc = 0;

	TAILQ_FOREACH_SAFE(kern, &kern_list, link, tmp) {
		if (!is_match(rule, kern))
			continue;
		if (mfc_update(kern))
			rc = -1;
	}

	return rc;
}

/*
 * Look up, or create, the kernel entry for the exact (S,G) in @route
 * and claim it for @route's inbound, like MRT_ADD_MFC does.
 */
static struct mroute *mfc_ensure(struct mroute *route)
{
	struct mroute *kern;

	kern = mfc_find(route);
	if (!kern) {
		kern = malloc(sizeof(struct mroute));
		if (!kern) {
			smclog(LOG_WARNING, "Cannot add kernel route: %s", strerror(errno));
			return NULL;
		}

		memcpy(kern, route, sizeof(struct mroute));
		TAILQ_INSERT_TAIL(&kern_list, kern, link);
	}
	kern->inbound = route->inbound;

	return kern;
}

/*
 * Bring the kernel up to date with rule @conf.  Only an (S,G) rule
 * gets an entry of its own, a (*,G) rule covers entries that exist.
 */
static int mfc_install(struct mroute *conf)
{
	if (is_ssm(conf) && !mfc_ensure(conf))
		return 1;

	return mfc_update_matching(conf);
}

/*
 * A VIF went away: drop every entry it fed, and take it out of the
 * oifs of every rule and entry it was listed in.
 */
static void mfc_prune_vif(int family, int vif)
{
	struct mroute *entry, *tmp;

	TAILQ_FOREACH_SAFE(entry, &conf_list, link, tmp) {
		if (entry->group.ss_family != family)
			continue;

		if (entry->inbound == vif) {
			TAILQ_REMOVE(&conf_list, entry, link);
			free(entry);
		} else
			entry->ttl[vif] = 0;
	}

	TAILQ_FOREACH_SAFE(entry, &kern_list, link, tmp) {
		if (entry->group.ss_family != family)
			continue;

		if (entry->inbound == vif)
			mfc_drop(entry);
		else if (entry->ttl[vif])
			mfc_update(entry);
	}
}

/**
 * mroute_add_route - Add route to kernel, or save a wildcard route for later use
 * @route: Pointer to multicast route to add
 *
 * Adds the given multicast @route to the kernel multicast routing table
 * unless it is ASM, i.e., a (*,G) route.  Those we save for and check
 * against at runtime when the kernel signals us.
 *
 * Returns:
 * POSIX OK(0) on success, non-zero on error with @errno set.
 */
int mroute_add_route(struct mroute *route)
{
	struct mroute *conf;

	conf = conf_find(route);
	if (conf) {
		size_t i;

		/* .conf: replace found entry with new outbounds */
		if (conf->unused) {
			for (i = 0; i < NELEMS(conf->ttl); i++)
				conf->ttl[i] = 0;
		}

		/* ipc: add any new outbound interafces */
		for (i = 0; i < NELEMS(conf->ttl); i++) {
			if (route->ttl[i])
				conf->ttl[i] = route->ttl[i];
		}
	} else {
		conf = malloc(sizeof(struct mroute));
		if (!conf) {
			smclog(LOG_WARNING, "Cannot add multicast route: %s", strerror(errno));
			return 1;
		}

		memcpy(conf, route, sizeof(struct mroute));
		TAILQ_INSERT_TAIL(&conf_list, conf, link);
	}

	conf->unused = 0;
	return mfc_install(conf);
}

/**
 * mroute_del_route - Remove route from kernel, or all matching routes if wildcard
 * @route: Pointer to multicast route to remove
 *
 * Removes the given multicast @route from the kernel multicast routing
 * table, or if the @route is a wildcard, then all matching kernel
 * routes are removed, as well as the wildcard.
 *
 * Returns:
 * POSIX OK(0) on success, non-zero on error with @errno set.
 */
int mroute_del_route(struct mroute *route)
{
	struct mroute *conf;
	int rc;

	if (route->unused) {
		conf = route;
	} else {
		conf = conf_find(route);
		if (!conf) {
			errno = ENOENT;
			return -1;
		}

		if (is_active(route)) {
			/* remove only the listed oifs from config */
			for (size_t i = 0; i < NELEMS(conf->ttl); i++) {
				if (route->ttl[i] > 0)
					conf->ttl[i] = 0;
			}

			return mfc_update_matching(conf);
		}
	}

	TAILQ_REMOVE(&conf_list, conf, link);
	rc = mfc_update_matching(conf);
	free(conf);

	return rc;
}

#ifdef HAVE_IPV6_MULTICAST_ROUTING
static int mroute6_add_mif(struct iface *iface);

/*
 * Receive and drop ICMPv6 stuff. This is either MLD packets or upcall
 * messages sent up from the kernel.
 */
static void handle_nocache6(int sd, void *arg)
{
	char origin[INET_ADDRSTR_LEN], group[INET_ADDRSTR_LEN];
	struct mroute mroute = { 0 };
	struct mrt6msg *im6;
	struct iface *iface;
	struct kern_rx rx;
	char tmp[2048];
	int result;

	(void)arg;
	result = kern_recv(sd, tmp, sizeof(tmp), &rx);
	if (result < 0) {
		smclog(LOG_INFO, "Failed reading MLD message from kernel: %s", strerror(errno));
		return;
	}

	/*
	 * The mrt6msg struct is overlayed on the ICMPv6 header, so the
	 * im6_mbz field (must-be-zero) is the ICMPv6 type, e.g. 143 for
	 * an MLDv2 report, and im6_msgtype its code.
	 */
	im6 = (struct mrt6msg *)tmp;
	if (result > 0 && im6->im6_mbz != 0) {
		mld_recv(rx.ifindex, &rx.src, rx.hlim, (uint8_t *)tmp, result);
		return;
	}

	if ((size_t)result < sizeof(*im6))
		return;

	if (im6->im6_msgtype == 0)
		return;

	inet_addr6_set(&mroute.source, &im6->im6_src);
	inet_addr6_set(&mroute.group, &im6->im6_dst);
	mroute.inbound = im6->im6_mif;
	mroute.len     = 128;
	mroute.src_len = 128;

	inet_addr2str(&mroute.source, origin, sizeof(origin));
	inet_addr2str(&mroute.group, group, sizeof(group));

	iface = iface_find_by_inbound(&mroute);
	if (!iface) {
		smclog(LOG_WARNING, "No matching interface for VIF %u, cannot handle MRT6MSG %u:%u. "
		       "Multicast source %s, dest %s", mroute.inbound, im6->im6_mbz, im6->im6_msgtype,
		       origin, group);
		return;
	}

	switch (im6->im6_msgtype) {
	case MRT6MSG_NOCACHE:
		smclog(LOG_DEBUG, "New multicast data from %s to group %s on VIF %u",
		       origin, group, mroute.inbound);

		/* Find any matching route for this group on that iif. */
		result = mroute_dyn_add(&mroute);
		if (result) {
			/*
			 * This is a common error, the router receives streams it is not
			 * set up to route -- we ignore these by default, but if the user
			 * sets a more permissive log level we help out by showing what
			 * is going on.
			 */
			if (ENOENT == errno)
				smclog(LOG_INFO, "Multicast from %s, group %s, on %s does not match any (*,G) rule",
				       origin, group, iface->ifname);
			return;
		}

		script_exec(&mroute);
		break;

	case MRT6MSG_WRONGMIF:
		if (mroute_resolve(&mroute) == 0) {
			smclog(LOG_NOTICE, "Moved (%s,%s) inbound to %s after WRONGMIF",
			       origin, group, iface->ifname);
			script_exec(&mroute);
		} else {
			smclog(LOG_INFO, "Multicast from %s, group %s on wrong MIF %u, iface %s",
			       origin, group, mroute.inbound, iface->ifname);
		}
		break;

	case MRT6MSG_WHOLEPKT:
		smclog(LOG_WARNING, "Receiving PIM6 register data from %s, group %s", origin, group);
		break;

	default:
		smclog(LOG_DEBUG, "Unknown MRT6MSG %u from kernel", im6->im6_msgtype);
		break;
	}
}
#endif /* HAVE_IPV6_MULTICAST_ROUTING */

/**
 * mroute6_enable - Initialise IPv6 multicast routing
 *
 * Setup the kernel IPv6 multicast routing API and lock the multicast
 * routing socket to this program (only!).
 *
 * Returns:
 * POSIX OK(0) on success, non-zero on error with @errno set.
 */
static int mroute6_enable(int table_id)
{
#ifndef HAVE_IPV6_MULTICAST_ROUTING
	(void)table_id;
#else
	if (kern_mroute6_init(table_id, handle_nocache6, NULL)) {
		switch (errno) {
		case ENOPROTOOPT:
			smclog(LOG_WARNING, "Kernel does not even support IPv6 ICMP, skipping ...");
			break;

		case EPROTONOSUPPORT:
			smclog(LOG_ERR, "Cannot set IPv6 multicast routing table id: %s",
			       strerror(errno));
			smclog(LOG_ERR, "Make sure your kernel has CONFIG_IPV6_MROUTE_MULTIPLE_TABLES=y");
			break;

		case EADDRINUSE:
			smclog(LOG_ERR, "IPv6 multicast routing API already in use: %s",
			       strerror(errno));
			smclog(LOG_ERR, "Is another multicast routing daemon (mldproxy, pim6d) running?");
			break;

		case EOPNOTSUPP:
			smclog(LOG_ERR, "Kernel does not support IPv6 multicast routing, skipping ...");
			break;

		default:
			smclog(LOG_ERR, "Failed initializing IPv6 multicast routing API: %s",
			       strerror(errno));
			break;
		}

		return 1;
	}

	return 0;
#endif /* HAVE_IPV6_MULTICAST_ROUTING */

	return -1;
}

/**
 * mroute6_disable - Disable IPv6 multicast routing
 *
 * Disable IPv6 multicast routing and release kernel routing socket.
 */
static void mroute6_disable(void)
{
#ifdef HAVE_IPV6_MULTICAST_ROUTING
	kern_mroute6_exit();
#endif
}

#ifdef HAVE_IPV6_MULTICAST_ROUTING
/* Create a virtual interface from @iface so it can be used for IPv6 multicast routing. */
static int mroute6_add_mif(struct iface *iface)
{
	if (kern_mif_add(iface)) {
		switch (errno) {
		case ENOPROTOOPT:
			smclog(LOG_WARNING, "Interface %s is not multicast capable, skipping MIF.",
			       iface->ifname);
			return -1;

		case EAGAIN:
			smclog(LOG_DEBUG, "No IPv6 multicast socket");
			return -1;

		case ENOMEM:
			smclog(LOG_WARNING, "Not enough available MIFs to create %s", iface->ifname);
			return 1;

		case EEXIST:
			smclog(LOG_DEBUG, "Interface %s already has MIF %d.", iface->ifname, iface->mif);
			return 0;

		default:
			break;
		}

		smclog(LOG_DEBUG, "Failed creating MIF for %s: %s", iface->ifname, strerror(errno));

		return -1;
	}

	return 0;
}

static int mroute6_del_mif(struct iface *iface)
{
	int rc = 0;

	if (iface->mif == ALL_VIFS)
		return 0;

	if (kern_mif_del(iface) && errno != ENOENT) {
		switch (errno) {
		case ENOENT:
		case EADDRNOTAVAIL:
			break;
		default:
			smclog(LOG_ERR, "Failed deleting MIF for iface %s: %s", iface->ifname, strerror(errno));
			break;
		}
		rc = -1;
	}

	if (iface->mif != ALL_VIFS)
		mfc_prune_vif(AF_INET6, iface->mif);
	iface->mif = ALL_VIFS;

	return rc;
}
#endif /* HAVE_IPV6_MULTICAST_ROUTING */

/*
 * Look up a configured (*,G) rule whose inbound matches @route's iif
 * and install/replace the kernel MFC entry for it.  Shared by both
 * NOCACHE (via mroute_dyn_add) and WRONGVIF/WRONGMIF.  Returns 0 on
 * hit, -1 with errno=ENOENT on miss (kernel entry, if any, left alone).
 */
static int mroute_resolve(struct mroute *route)
{
	struct mroute *entry, *kern;

	TAILQ_FOREACH(entry, &conf_list, link) {
		if (is_match(entry, route))
			break;
	}

	if (!entry && !proxy_oifs(route)) {
		errno = ENOENT;
		return -1;
	}

	kern = mfc_ensure(route);
	if (!kern)
		return -1;

	mfc_update(kern);
	return 0;
}

/*
 * NOCACHE upcall handler.  Resolve via mroute_resolve(); on miss
 * install a zero-ttl stop filter so the kernel stops upcalling NOCACHE
 * for this (S,G,IIF).
 */
static int mroute_dyn_add(struct mroute *route)
{
	struct mroute *kern;

	if (mroute_resolve(route) == 0)
		return 0;

	kern = mfc_ensure(route);
	if (kern) {
		memset(kern->ttl, 0, sizeof(kern->ttl));
		kern_mroute_add(kern);
	}

	errno = ENOENT;
	return -1;
}

int mroute_init(int table_id, int cache_tmo)
{
	static int running = 0;

	TAILQ_INIT(&conf_list);
	TAILQ_INIT(&kern_list);

	if (cache_tmo > 0 && !running) {
		running++;
		cache_timeout = cache_tmo;
		timer_add(cache_tmo, cache_flush, NULL);
	}

	return  mroute4_enable(table_id) ||
		mroute6_enable(table_id);
}

void mroute_exit(void)
{
	mroute4_disable();
	mroute6_disable();
}

/* Used by file parser to add VIFs/MIFs after setup */
int mroute_add_vif(char *ifname, const struct phyint *opt)
{
	struct ifmatch state;
	struct iface *iface;
	int rc = 0;

	iface_match_init(&state);
	while ((iface = iface_match_by_name(ifname, 1, &state))) {
		smclog(LOG_DEBUG, "Creating/updating multicast VIF for %s TTL %d", iface->ifname, opt->threshold);
		iface->mrdisc         = opt->mrdisc;
		iface->threshold      = opt->threshold;
		iface->proxy          = opt->proxy;
		iface->proxy_querier  = opt->proxy_querier;
		iface->query_interval = opt->query_interval;
		iface->unused         = 0;
		if (mroute4_add_vif(iface))
			rc = -1;
#ifdef HAVE_IPV6_MULTICAST_ROUTING
		if (mroute6_add_mif(iface))
			rc = -1;
#endif
		proxy_sync(iface);
	}

	if (!state.match_count) {
		smclog(LOG_DEBUG, "Failed adding phyint %s, no matching interfaces.", ifname);
		return 1;
	}

	return rc;
}

/* Like mroute_add_vif() but preserves any user-set mrdisc/ttl. */
int mroute_ensure_vif(const char *ifname)
{
	struct ifmatch state;
	struct iface *iface;
	int rc = 0;

	iface_match_init(&state);
	while ((iface = iface_match_by_name(ifname, 1, &state))) {
		iface->unused = 0;
		if (mroute4_add_vif(iface))
			rc = -1;
#ifdef HAVE_IPV6_MULTICAST_ROUTING
		if (mroute6_add_mif(iface))
			rc = -1;
#endif
	}

	return rc;
}

/* Used by file parser to remove VIFs/MIFs after setup */
int mroute_del_vif(char *ifname)
{
	struct ifmatch state;
	struct iface *iface;
	int rc = 0;

	iface_match_init(&state);
	while ((iface = iface_match_by_name(ifname, 1, &state))) {
		smclog(LOG_DEBUG, "Removing multicast VIFs for %s", iface->ifname);
		if (mroute4_del_vif(iface))
			rc = -1;
#ifdef HAVE_IPV6_MULTICAST_ROUTING
		if (mroute6_del_mif(iface))
			rc = -1;
#endif
		proxy_sync(iface);
	}

	if (!state.match_count) {
		smclog(LOG_DEBUG, "Failed removing phyint %s, no matching interfaces.", ifname);
		return 1;
	}

	return rc;
}

/* Resync kernel entries for @group, or all when NULL, after an oif source changed */
void mroute_update_group(inet_addr_t *group)
{
	struct mroute *entry, *tmp;

	TAILQ_FOREACH_SAFE(entry, &kern_list, link, tmp) {
		uint8_t ttl[MAX_MC_VIFS];

		if (group && inet_addr_cmp(&entry->group, group))
			continue;

		memcpy(ttl, entry->ttl, sizeof(ttl));
		mfc_compute(entry);
		if (memcmp(ttl, entry->ttl, sizeof(ttl)))
			mfc_update(entry);
	}
}

/*
 * Called on SIGHUP/reload.  Mark all known configured routes as
 * 'unused', let mroute*_add() unmark and mroute_reload_end() take
 * care to remove routes that still have the 'unused' flag.
 */
void mroute_reload_beg(void)
{
	struct mroute *entry;
	struct iface *iface;
	int first = 1;

	TAILQ_FOREACH(entry, &conf_list, link)
		entry->unused = 1;

	while ((iface = iface_iterator(first))) {
		first = 0;
		iface->unused = 1;
	}
}

void mroute_reload_end(void)
{
	struct mroute *entry, *tmp;
	struct iface *iface;
	int first = 1;

	while ((iface = iface_iterator(first))) {
		char  dummy[IFNAMSIZ];

		first = 0;
		if (iface->unused || !if_indextoname(iface->ifindex, dummy))
			mroute_del_vif(iface->ifname);
	}

	TAILQ_FOREACH_SAFE(entry, &conf_list, link, tmp) {
		if (entry->unused)
			mroute_del_route(entry);
	}
}

static int show_mroute_json(int sd, struct mroute *r, int first)
{
	char src[INET_ADDRSTR_LEN] = "", grp[INET_ADDRSTR_LEN];
	char src_field[INET_ADDRSTR_LEN + 16];
	char grp_field[INET_ADDRSTR_LEN + 16];
	char line[512];
	struct iface *iface;
	int max_len, sent_oif = 0;

	max_len = inet_max_len(&r->group);

	if (is_anyaddr(&r->source)) {
		snprintf(src_field, sizeof(src_field), "null");
	} else {
		inet_addr2str(&r->source, src, sizeof(src));
		if (r->src_len != max_len)
			snprintf(src_field, sizeof(src_field), "\"%s/%u\"", src, r->src_len);
		else
			snprintf(src_field, sizeof(src_field), "\"%s\"", src);
	}

	inet_addr2str(&r->group, grp, sizeof(grp));
	if (r->len != max_len)
		snprintf(grp_field, sizeof(grp_field), "\"%s/%u\"", grp, r->len);
	else
		snprintf(grp_field, sizeof(grp_field), "\"%s\"", grp);

	iface = iface_find_by_inbound(r);
	snprintf(line, sizeof(line),
		 "%s{\"source\":%s,\"group\":%s,\"iif\":\"%s\",\"oifs\":[",
		 first ? "" : ",", src_field, grp_field,
		 iface ? iface->ifname : "");
	if (ipc_send(sd, line, strlen(line)) < 0)
		return -1;

	iface = iface_outbound_iterator(r, 1);
	while (iface) {
		snprintf(line, sizeof(line), "%s\"%s\"",
			 sent_oif ? "," : "", iface->ifname);
		if (ipc_send(sd, line, strlen(line)) < 0)
			return -1;
		sent_oif = 1;
		iface = iface_outbound_iterator(r, 0);
	}
	ipc_send(sd, "]}", 2);
	return 0;
}

static int show_mroute(int sd, struct mroute *r, int inw, int detail)
{
	char src[INET_ADDRSTR_LEN] = "*";
	char src_len[5] = "";
	char grp[INET_ADDRSTR_LEN];
	char grp_len[5] = "";
	char sg[(INET_ADDRSTR_LEN + 3) * 2 + 5];
	char buf[MAX_MC_VIFS * 17 + 80];
	struct iface *iface;
	int max_len;

	max_len = inet_max_len(&r->group);

	if (!is_anyaddr(&r->source)) {
		inet_addr2str(&r->source, src, sizeof(src));
		if (r->src_len != max_len)
			snprintf(src_len, sizeof(src_len), "/%u", r->src_len);
	}
	inet_addr2str(&r->group, grp, sizeof(grp));
	if (r->len != max_len)
		snprintf(grp_len, sizeof(grp_len), "/%u", r->len);

	iface = iface_find_by_inbound(r);
	snprintf(sg, sizeof(sg), "(%s%s, %s%s)", src, src_len, grp, grp_len);
	if (!iface) {
		smclog(LOG_ERR, "Failed reading iif for %s, aborting.", sg);
		exit(EX_SOFTWARE);
	}
	snprintf(buf, sizeof(buf), "%-42s %-*s ", sg, inw, iface->ifname);

	if (detail) {
		struct mroute_stats ms = { 0 };
		char stats[30];

		kern_stats(r, &ms);
		snprintf(stats, sizeof(stats), "%10lu %10lu ", ms.ms_pktcnt, ms.ms_bytecnt);
		strlcat(buf, stats, sizeof(buf));
	}

	iface = iface_outbound_iterator(r, 1);
	while (iface) {
		char tmp[22];

		snprintf(tmp, sizeof(tmp), " %s", iface->ifname);
		strlcat(buf, tmp, sizeof(buf));

		iface = iface_outbound_iterator(r, 0);
	}
	strlcat(buf, "\n", sizeof(buf));

	if (ipc_send(sd, buf, strlen(buf)) < 0) {
		smclog(LOG_ERR, "Failed sending reply to client: %s", strerror(errno));
		return -1;
	}

	return 0;
}

static int has_any_ssm(void)
{
	struct mroute *e;

	TAILQ_FOREACH(e, &conf_list, link) {
		if (is_ssm(e))
			return 1;
	}

	return 0;
}

static int has_any_asm(void)
{
	struct mroute *e;

	TAILQ_FOREACH(e, &conf_list, link) {
		if (!is_ssm(e))
			return 1;
	}

	return 0;
}

/* Write all (*,G) routes to client socket */
int mroute_show(int sd, enum show_mode mode)
{
	const char *r = "ROUTE (S,G)", *o = "OIFS", *i = "IIF";
	int detail = mode == SHOW_DETAIL;
	struct mroute *entry;
	char line[256];
	int inw;

	if (mode == SHOW_JSON) {
		int first;

		ipc_send(sd, "{\"routes\":{\"asm\":[", 18);
		first = 1;
		TAILQ_FOREACH(entry, &conf_list, link) {
			if (is_ssm(entry))
				continue;
			if (show_mroute_json(sd, entry, first) < 0)
				return 1;
			first = 0;
		}
		ipc_send(sd, "],\"ssm\":[", 9);
		first = 1;
		TAILQ_FOREACH(entry, &conf_list, link) {
			if (!is_ssm(entry))
				continue;
			if (show_mroute_json(sd, entry, first) < 0)
				return 1;
			first = 0;
		}
		ipc_send(sd, "],\"kernel\":[", 12);
		first = 1;
		TAILQ_FOREACH(entry, &kern_list, link) {
			if (show_mroute_json(sd, entry, first) < 0)
				return 1;
			first = 0;
		}
		ipc_send(sd, "]}}\n", 4);
		return 0;
	}

	inw = iface_ifname_maxlen();
	if (inw < (int)strlen(i))
		inw = (int)strlen(i);

	if (detail) {
		const char *p = "PACKETS", *b = "BYTES";
		snprintf(line, sizeof(line), "%-42s %-*s %10s %10s  %s=\n", r, inw, i, p, b, o);
	} else
		snprintf(line, sizeof(line), "%-42s %-*s  %s=\n", r, inw, i, o);

	if (has_any_asm()) {
		char *asm_conf = "(*,G) Template Rules_\n";

		ipc_send(sd, asm_conf, strlen(asm_conf));
		ipc_send(sd, line, strlen(line));
		TAILQ_FOREACH(entry, &conf_list, link) {
			if (is_ssm(entry))
				continue;
			if (show_mroute(sd, entry, inw, detail) < 0)
				return 1;
		}
	}

	if (has_any_ssm()) {
		char *ssm_list = "(S,G) Rules_\n";

		ipc_send(sd, ssm_list, strlen(ssm_list));
		ipc_send(sd, line, strlen(line));
		TAILQ_FOREACH(entry, &conf_list, link) {
			if (!is_ssm(entry))
				continue;
			if (show_mroute(sd, entry, inw, detail) < 0)
				return 1;
		}
	}

	if (!TAILQ_EMPTY(&kern_list)) {
		char *asm_kern = "Kernel MFC Table_\n";

		ipc_send(sd, asm_kern, strlen(asm_kern));
		ipc_send(sd, line, strlen(line));
		TAILQ_FOREACH(entry, &kern_list, link) {
			if (!is_active(entry))
				continue;
			if (show_mroute(sd, entry, inw, detail) < 0)
				return 1;
		}
		TAILQ_FOREACH(entry, &kern_list, link) {
			if (is_active(entry))
				continue;
			if (show_mroute(sd, entry, inw, detail) < 0)
				return 1;
		}
	}

	return 0;
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
