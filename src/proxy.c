/* IGMP/MLD proxying, RFC 4605
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
#include "queue.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "iface.h"
#include "igmp.h"
#include "kern.h"
#include "log.h"
#include "mcgroup.h"
#include "mld.h"
#include "mroute.h"
#include "proxy.h"
#include "timer.h"
#include "util.h"

/* smcroute.conf querier settings, timers in seconds, RFC 3376 §8 */
enum { QUERY_INTERVAL, RESPONSE_INTERVAL, LAST_MEMBER_INTERVAL, ROBUSTNESS, ROUTER_TIMEOUT, TOPOLOGY_QUERY, ROUTER_ALERT };

static struct {
	const char *keyword;
	int val, def, min, max;
} settings[] = {
	[QUERY_INTERVAL]       = { "global-query-interval",       125, 125, 1, 1024 },
	[RESPONSE_INTERVAL]    = { "global-response-interval",     10,  10, 1, 1024 },
	[LAST_MEMBER_INTERVAL] = { "global-last-member-interval",   1,   1, 1, 1024 },
	[ROBUSTNESS]           = { "robustness",                    2,   2, 2,   10 },
	[ROUTER_TIMEOUT]       = { "router-timeout",                0,   0, 1, 1024 }, /* 0: derived */
	[TOPOLOGY_QUERY]       = { "topology-query",                1,   1, 0,    1 },
	[ROUTER_ALERT]         = { "router-alert",                  1,   1, 0,    1 },
};

/* Joined on downstream interfaces to receive what hosts send to routers */
static const char *control_groups[] = {
	"224.0.0.22", "224.0.0.2",	/* IGMPv3 reports, leaves and MRD */
	"ff02::16",   "ff02::2",	/* MLDv2 reports, done and MRD */
};

/* An older protocol version in use, and for how long to assume so */
struct gen {
	int    cur;
	time_t expires;
};

/* A burst of @left sends, some interval apart */
struct burst {
	int    left;
	time_t next;
};

struct source {
	TAILQ_ENTRY(source) link;
	inet_addr_t addr;
	time_t      expires;
};

/*
 * Membership of one group on one downstream interface, RFC 5790
 * lightweight semantics: EXCLUDE{} means any source, INCLUDE lists
 * the wanted sources, each with its own timer.
 */
struct member {
	TAILQ_ENTRY(member) link;
	inet_addr_t  group;
	int          exclude;
	time_t       expires;		/* group timer, EXCLUDE mode */
	struct gen   gen;		/* lowest host version present */
	struct burst query;		/* group-specific queries */
	TAILQ_HEAD(, source) sources;
};

/* Querier state, one per address family on an interface */
struct querier {
	struct gen  gen;		/* query version in use on the link */
	int         me;			/* we send the queries */
	inet_addr_t other;		/* elected querier when not us */
	time_t      expires;		/* other querier present timeout */
	int         startup;		/* startup queries left to send */
	time_t      next;		/* next general query */
};

/* A subscription on the upstream, on behalf of the downstreams */
struct upjoin {
	TAILQ_ENTRY(upjoin) link;
	struct iface *iface;
	inet_addr_t   group;
	int           sd;
	int           exclude;		/* any source, else the sources below */
	int           num;
	inet_addr_t  *srcs;
	int           keep;		/* still wanted, during a sync */
};

struct proxy_iface {
	TAILQ_ENTRY(proxy_iface) link;
	struct iface *iface;
	int           role;
	int           sd[NELEMS(control_groups)];	/* -1 if not joined */
	struct querier querier[2];			/* IPv4, IPv6 */
	int           parent;				/* ifindex below a VLAN interface */
	TAILQ_HEAD(, member) members;
};

static TAILQ_HEAD(, proxy_iface) pif_list = TAILQ_HEAD_INITIALIZER(pif_list);
static TAILQ_HEAD(, upjoin) upjoin_list = TAILQ_HEAD_INITIALIZER(upjoin_list);
static struct proxy_iface *upstream;


void proxy_conf_reset(void)
{
	size_t i;

	for (i = 0; i < NELEMS(settings); i++)
		settings[i].val = settings[i].def;
	kern_router_alert(settings[ROUTER_ALERT].val);
}

/* Returns 0 if @keyword is not a setting, 1 when set, -1 when @arg is out of range */
int proxy_conf(const char *keyword, const char *arg)
{
	size_t i;
	int val;

	for (i = 0; i < NELEMS(settings); i++) {
		if (strcmp(settings[i].keyword, keyword))
			continue;

		if (!arg)
			val = -1;
		else if (settings[i].max == 1 && !strcmp(arg, "on"))
			val = 1;
		else if (settings[i].max == 1 && !strcmp(arg, "off"))
			val = 0;
		else
			val = atoi(arg);
		if (val < settings[i].min || val > settings[i].max)
			return -1;

		settings[i].val = val;
		if (i == ROUTER_ALERT)
			kern_router_alert(val);
		return 1;
	}

	return 0;
}

static int query_interval(struct proxy_iface *pif)
{
	if (pif->iface->query_interval)
		return pif->iface->query_interval;

	return settings[QUERY_INTERVAL].val;
}

/* Must not exceed the query interval, RFC 3376 §8.3 */
static int response_interval(struct proxy_iface *pif)
{
	return MIN(settings[RESPONSE_INTERVAL].val, query_interval(pif));
}

/* Group membership interval, RFC 3376 §8.4 */
static int group_interval(struct proxy_iface *pif)
{
	return settings[ROBUSTNESS].val * query_interval(pif) + response_interval(pif);
}

/* Other querier present interval, RFC 3376 §8.5 */
static int other_querier_interval(struct proxy_iface *pif)
{
	if (settings[ROUTER_TIMEOUT].val)
		return settings[ROUTER_TIMEOUT].val;

	return settings[ROBUSTNESS].val * query_interval(pif) + response_interval(pif) / 2;
}

/* Startup query interval, RFC 3376 §8.6 */
static int startup_interval(struct proxy_iface *pif)
{
	return MAX(query_interval(pif) / 4, 1);
}

/* Last member query time, RFC 3376 §8.8 and §8.9 */
static int last_member_time(void)
{
	return settings[ROBUSTNESS].val * settings[LAST_MEMBER_INTERVAL].val;
}

static time_t now(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec;
}

static const char *family_name(int family)
{
	return family == AF_INET6 ? "MLD" : "IGMP";
}

static struct querier *querier_of(struct proxy_iface *pif, int family)
{
	return &pif->querier[family == AF_INET6];
}

/* Lower a timer, never extend it */
static void lower(time_t *expires, time_t to)
{
	if (*expires > to)
		*expires = to;
}

/* Older version seen, RFC 3376 §7.2.1 and §7.3.2 */
static void gen_seen(struct gen *g, int gen, time_t expires)
{
	if (gen == 3 || gen > g->cur)
		return;

	g->cur     = gen;
	g->expires = expires;
}

static void gen_tick(struct gen *g, time_t t)
{
	if (g->cur < 3 && g->expires <= t)
		g->cur = 3;
}

/* Returns 1 when the next send of the burst is due, and schedules the one after */
static int burst_due(struct burst *b, time_t t, int interval)
{
	if (!b->left || b->next > t)
		return 0;

	b->left--;
	b->next = t + interval;

	return 1;
}

/* Our address of @family on @iface, 0 if none */
static int local_addr(struct iface *iface, int family, inet_addr_t *addr)
{
	memset(addr, 0, sizeof(*addr));
#ifdef HAVE_IPV6_MULTICAST_HOST
	if (family == AF_INET6) {
		if (IN6_IS_ADDR_UNSPECIFIED(&iface->in6addr))
			return 0;

		inet_addr6_set(addr, &iface->in6addr);
		return 1;
	}
#endif
	if (!iface->inaddr.s_addr)
		return 0;

	inet_addr_set(addr, &iface->inaddr);
	return 1;
}

/*
 * The address we query from: our own, or the unspecified one when we
 * have none or are told to send proxy queries, RFC 4541 §2.1.1.1.
 * Returns 1 for our own, 0 for a proxy query, -1 when neither works.
 */
static int querier_addr(struct proxy_iface *pif, int family, inet_addr_t *addr)
{
	if (!pif->iface->proxy_querier && local_addr(pif->iface, family, addr))
		return 1;

	inet_anyaddr(family, addr);

	return kern_proxy_queries() ? 0 : -1;
}

static struct proxy_iface *pif_find(struct iface *iface)
{
	struct proxy_iface *pif;

	TAILQ_FOREACH(pif, &pif_list, link) {
		if (pif->iface == iface)
			return pif;
	}

	return NULL;
}

int proxy_role(struct iface *iface)
{
	struct proxy_iface *pif;

	pif = pif_find(iface);
	return pif ? pif->role : PROXY_NONE;
}

static struct member *member_find(struct proxy_iface *pif, inet_addr_t *group)
{
	struct member *m;

	TAILQ_FOREACH(m, &pif->members, link) {
		if (!inet_addr_cmp(&m->group, group))
			return m;
	}

	return NULL;
}

/* Find or create the membership, flagging a change that affects forwarding */
static struct member *member_get(struct proxy_iface *pif, inet_addr_t *group, int exclude, int *changed)
{
	struct member *m;

	m = member_find(pif, group);
	if (m) {
		if (exclude && !m->exclude) {
			m->exclude = 1;
			*changed = 1;
		}

		return m;
	}

	m = calloc(1, sizeof(*m));
	if (!m) {
		smclog(LOG_ERR, "Out of memory in %s()", __func__);
		return NULL;
	}

	m->group   = *group;
	m->exclude = exclude;
	m->gen.cur = 3;
	TAILQ_INIT(&m->sources);
	TAILQ_INSERT_TAIL(&pif->members, m, link);
	*changed = 1;

	return m;
}

static void member_del(struct proxy_iface *pif, struct member *m)
{
	struct source *s, *tmp;

	TAILQ_FOREACH_SAFE(s, &m->sources, link, tmp) {
		TAILQ_REMOVE(&m->sources, s, link);
		free(s);
	}
	TAILQ_REMOVE(&pif->members, m, link);
	free(m);
}

static struct source *source_find(struct member *m, inet_addr_t *addr)
{
	struct source *s;

	TAILQ_FOREACH(s, &m->sources, link) {
		if (!inet_addr_cmp(&s->addr, addr))
			return s;
	}

	return NULL;
}

/* Returns 1 if the source is new to the member */
static int source_refresh(struct member *m, inet_addr_t *addr, time_t expires)
{
	struct source *s;
	int new = 0;

	s = source_find(m, addr);
	if (!s) {
		s = calloc(1, sizeof(*s));
		if (!s) {
			smclog(LOG_ERR, "Out of memory in %s()", __func__);
			return 0;
		}

		s->addr = *addr;
		TAILQ_INSERT_TAIL(&m->sources, s, link);
		new = 1;
	}
	s->expires = expires;

	return new;
}

/* Does downstream @pif want the (S,G) of kernel entry @kern? */
static int wants(struct proxy_iface *pif, struct mroute *kern)
{
	struct member *m;

	m = member_find(pif, &kern->group);
	if (!m)
		return 0;
	if (m->exclude)
		return 1;

	return source_find(m, &kern->source) != NULL;
}

static struct upjoin *upjoin_find(inet_addr_t *group)
{
	struct upjoin *uj;

	TAILQ_FOREACH(uj, &upjoin_list, link) {
		if (!inet_addr_cmp(&uj->group, group))
			return uj;
	}

	return NULL;
}

static void upjoin_del(struct upjoin *uj)
{
	char g[INET_ADDRSTR_LEN];

	smclog(LOG_INFO, "Leaving %s on upstream %s", inet_addr2str(&uj->group, g, sizeof(g)),
	       uj->iface->ifname);

	mcgroup_leave(uj->iface, NULL, &uj->group, uj->sd);
	TAILQ_REMOVE(&upjoin_list, uj, link);
	free(uj->srcs);
	free(uj);
}

/* Any downstream with an EXCLUDE membership for @group? */
static int any_exclude(inet_addr_t *group)
{
	struct proxy_iface *pif;
	struct member *m;

	TAILQ_FOREACH(pif, &pif_list, link) {
		m = member_find(pif, group);
		if (m && m->exclude)
			return 1;
	}

	return 0;
}

/* The sources wanted for @group on any downstream, without duplicates */
static int upjoin_sources(inet_addr_t *group, inet_addr_t **srcs)
{
	struct proxy_iface *pif;
	struct member *m;
	struct source *s;
	int i, num = 0, max = 0;

	*srcs = NULL;
	TAILQ_FOREACH(pif, &pif_list, link) {
		m = member_find(pif, group);
		if (!m)
			continue;

		TAILQ_FOREACH(s, &m->sources, link)
			max++;
	}
	if (!max)
		return 0;

	*srcs = calloc(max, sizeof(**srcs));
	if (!*srcs) {
		smclog(LOG_ERR, "Out of memory in %s()", __func__);
		return 0;
	}

	TAILQ_FOREACH(pif, &pif_list, link) {
		m = member_find(pif, group);
		if (!m)
			continue;

		TAILQ_FOREACH(s, &m->sources, link) {
			for (i = 0; i < num; i++) {
				if (!inet_addr_cmp(&(*srcs)[i], &s->addr))
					break;
			}
			if (i == num)
				(*srcs)[num++] = s->addr;
		}
	}

	return num;
}

/*
 * Subscribe the upstream to @group: any source when a downstream has an
 * EXCLUDE member, else the union of their sources, RFC 3376 §3.2.
 */
static void upjoin_sync(inet_addr_t *group)
{
	char g[INET_ADDRSTR_LEN];
	inet_addr_t *srcs = NULL;
	struct upjoin *uj;
	int exclude, num = 0;

	exclude = any_exclude(group);
	if (!exclude)
		num = upjoin_sources(group, &srcs);
	if (!exclude && !num)
		return;

	inet_addr2str(group, g, sizeof(g));
	uj = upjoin_find(group);
	if (!uj) {
		int sd;

		sd = mcgroup_join(upstream->iface, NULL, group);
		if (sd == -1) {
			smclog(LOG_WARNING, "Failed joining %s on upstream %s", g, upstream->iface->ifname);
			free(srcs);
			return;
		}

		uj = calloc(1, sizeof(*uj));
		if (!uj) {
			smclog(LOG_ERR, "Out of memory in %s()", __func__);
			mcgroup_leave(upstream->iface, NULL, group, sd);
			free(srcs);
			return;
		}

		uj->iface   = upstream->iface;
		uj->group   = *group;
		uj->sd      = sd;
		uj->exclude = 1;
		TAILQ_INSERT_TAIL(&upjoin_list, uj, link);

		smclog(LOG_INFO, "Joined %s on upstream %s", g, uj->iface->ifname);
	}
	uj->keep = 1;

	if (exclude == uj->exclude && num == uj->num &&
	    (!num || !memcmp(srcs, uj->srcs, num * sizeof(*srcs)))) {
		free(srcs);
		return;
	}

	if (kern_set_filter(uj->sd, uj->iface, group, exclude, srcs, num)) {
		smclog(LOG_WARNING, "Failed setting %d source filter for %s on upstream %s: %s", num, g,
		       uj->iface->ifname, errno == ENOBUFS ? "too many sources, see igmp_max_msf" : strerror(errno));
		free(srcs);
		return;
	}

	free(uj->srcs);
	uj->srcs    = srcs;
	uj->num     = num;
	uj->exclude = exclude;

	if (exclude)
		smclog(LOG_INFO, "Subscribed to %s on upstream %s, any source", g, uj->iface->ifname);
	else
		smclog(LOG_INFO, "Subscribed to %s on upstream %s, %d sources", g, uj->iface->ifname, num);
}

/*
 * Host side, RFC 4605 §4.1: the upstream subscribes to the union of
 * the downstream memberships of @group, or of all groups when NULL.
 */
static void upstream_sync(inet_addr_t *group)
{
	struct proxy_iface *pif;
	struct upjoin *uj, *tmp;
	struct member *m;

	TAILQ_FOREACH(uj, &upjoin_list, link) {
		if (!group || !inet_addr_cmp(&uj->group, group))
			uj->keep = 0;
	}

	if (upstream && group)
		upjoin_sync(group);

	TAILQ_FOREACH(pif, &pif_list, link) {
		if (!upstream || group)
			break;
		if (pif->role != PROXY_DOWNSTREAM)
			continue;

		TAILQ_FOREACH(m, &pif->members, link)
			upjoin_sync(&m->group);
	}

	TAILQ_FOREACH_SAFE(uj, &upjoin_list, link, tmp) {
		if (!uj->keep)
			upjoin_del(uj);
	}
}

/* The memberships of @group changed, NULL for all */
static void membership_changed(inet_addr_t *group)
{
	upstream_sync(group);
	mroute_update_group(group);
}

/*
 * Forwarding rules, RFC 4605 §4.2: traffic from the upstream goes to
 * every downstream with a member for it, traffic from a downstream
 * goes to the upstream and to every other downstream with a member.
 * Returns the number of oifs set.
 */
int proxy_oifs(struct mroute *kern)
{
	struct proxy_iface *in, *pif;
	int num = 0;

	in = pif_find(iface_find_by_inbound(kern));
	if (!in)
		return 0;

	TAILQ_FOREACH(pif, &pif_list, link) {
		vifi_t vif;

		if (pif == in)
			continue;

		vif = iface_get_vif(kern->group.ss_family, pif->iface);
		if (vif == NO_VIF)
			continue;

		if (pif->role == PROXY_UPSTREAM || wants(pif, kern)) {
			kern->ttl[vif] = pif->iface->threshold;
			num++;
		}
	}

	return num;
}

/* A General Query, or a Group-Specific one when @group is set */
static int send_query(struct proxy_iface *pif, int family, inet_addr_t *group)
{
	struct querier *q = querier_of(pif, family);
	int mrt = group ? settings[LAST_MEMBER_INTERVAL].val : response_interval(pif);
	char g[INET_ADDRSTR_LEN] = "all";
	inet_addr_t dst = { 0 }, me;
	uint8_t buf[64];
	size_t len;

	if (group) {
		dst = *group;
		inet_addr2str(group, g, sizeof(g));
	} else
		inet_str2addr(family == AF_INET6 ? "ff02::1" : "224.0.0.1", &dst);

	if (family == AF_INET6)
		len = mld_build_query(buf, q->gen.cur, mrt, group, query_interval(pif), settings[ROBUSTNESS].val);
	else
		len = igmp_build_query(buf, q->gen.cur, mrt, group, query_interval(pif), settings[ROBUSTNESS].val);

	querier_addr(pif, family, &me);
	if (kern_send(pif->iface, &me, &dst, buf, len)) {
		smclog(LOG_WARNING, "Failed sending %s query on %s: %s", family_name(family),
		       pif->iface->ifname, strerror(errno));
		return -1;
	}

	smclog(LOG_DEBUG, "Sent %s query for %s on %s", family_name(family), g, pif->iface->ifname);

	return 0;
}

/* Query now and start the startup burst, RFC 3376 §8.6 */
static void querier_restart(struct querier *q, time_t t)
{
	q->startup = settings[ROBUSTNESS].val;
	q->next    = t;
}

/*
 * Querier timers of one family on a downstream interface.  Taking over
 * starts with a query burst, then one per interval.
 */
static void querier_tick(struct proxy_iface *pif, int family, time_t t)
{
	struct querier *q = querier_of(pif, family);
	inet_addr_t me;

	if (iface_get_vif(family, pif->iface) == NO_VIF)
		return;

	if (querier_addr(pif, family, &me) < 0) {
		if (q->me) {
			smclog(LOG_INFO, "No address on %s, giving up %s querier duties",
			       pif->iface->ifname, family_name(family));
			q->me = 0;
		}
		return;
	}

	if (!q->me) {
		if (!is_anyaddr(&q->other) && q->expires > t)
			return;

		smclog(LOG_INFO, "Assuming %s %squerier duties on %s", family_name(family),
		       is_anyaddr(&me) ? "proxy " : "", pif->iface->ifname);
		q->me = 1;
		querier_restart(q, t);
	}

	if (q->next > t)
		return;

	/* e.g. a link-local address still tentative, try again shortly */
	if (send_query(pif, family, NULL)) {
		q->next = t + 1;
		return;
	}

	if (q->startup)
		q->startup--;
	q->next = t + (q->startup ? startup_interval(pif) : query_interval(pif));
}

/* A port of @bridge started forwarding, RFC 4541 §2.1.1 */
void proxy_topology(int bridge, int port)
{
	struct proxy_iface *pif;
	time_t t = now();
	size_t i;

	if (!settings[TOPOLOGY_QUERY].val)
		return;

	TAILQ_FOREACH(pif, &pif_list, link) {
		char ifname[IFNAMSIZ];
		int me = 0;

		if (pif->role != PROXY_DOWNSTREAM)
			continue;
		if (pif->iface->ifindex != bridge && pif->parent != bridge)
			continue;

		for (i = 0; i < NELEMS(pif->querier); i++) {
			if (!pif->querier[i].me)
				continue;

			querier_restart(&pif->querier[i], t);
			me = 1;
		}

		if (me)
			smclog(LOG_INFO, "Port %s forwarding, querying %s",
			       if_indextoname(port, ifname) ? ifname : "?", pif->iface->ifname);
	}
}

/*
 * Age memberships once a second; entries fall back to INCLUDE mode
 * when the group timer runs out and go away when nothing is left.
 */
static void sweep(void *arg)
{
	struct proxy_iface *pif;
	time_t t = now();

	(void)arg;
	TAILQ_FOREACH(pif, &pif_list, link) {
		struct member *m, *mtmp;

		gen_tick(&pif->querier[0].gen, t);
		gen_tick(&pif->querier[1].gen, t);
		if (pif->role != PROXY_DOWNSTREAM)
			continue;

		querier_tick(pif, AF_INET, t);
#ifdef HAVE_IPV6_MULTICAST_HOST
		querier_tick(pif, AF_INET6, t);
#endif
		TAILQ_FOREACH_SAFE(m, &pif->members, link, mtmp) {
			inet_addr_t group = m->group;
			struct source *s, *stmp;
			int changed = 0;

			gen_tick(&m->gen, t);
			if (burst_due(&m->query, t, settings[LAST_MEMBER_INTERVAL].val))
				send_query(pif, group.ss_family, &group);

			TAILQ_FOREACH_SAFE(s, &m->sources, link, stmp) {
				if (s->expires > t)
					continue;

				TAILQ_REMOVE(&m->sources, s, link);
				free(s);
				changed = 1;
			}

			if (m->exclude && m->expires <= t) {
				m->exclude = 0;
				changed = 1;
			}

			if (!changed)
				continue;

			if (!m->exclude && TAILQ_EMPTY(&m->sources)) {
				char g[INET_ADDRSTR_LEN];

				smclog(LOG_INFO, "Membership for %s on %s timed out",
				       inet_addr2str(&group, g, sizeof(g)), pif->iface->ifname);
				member_del(pif, m);
			}

			membership_changed(&group);
		}
	}
}

static void pif_add(struct iface *iface, int role)
{
	struct proxy_iface *pif;
	size_t i;

	pif = calloc(1, sizeof(*pif));
	if (!pif) {
		smclog(LOG_ERR, "Out of memory in %s()", __func__);
		return;
	}

	pif->iface  = iface;
	pif->role   = role;
	pif->parent = iface_lower(iface);
	TAILQ_INIT(&pif->members);
	for (i = 0; i < NELEMS(pif->sd); i++)
		pif->sd[i] = -1;
	for (i = 0; i < NELEMS(pif->querier); i++)
		pif->querier[i].gen.cur = 3;

	if (TAILQ_EMPTY(&pif_list))
		timer_add(1, sweep, NULL);
	TAILQ_INSERT_TAIL(&pif_list, pif, link);

	if (role == PROXY_UPSTREAM) {
		upstream = pif;
	} else {
		for (i = 0; i < NELEMS(control_groups); i++) {
			inet_addr_t group = { 0 };

			inet_str2addr(control_groups[i], &group);
			if (iface_get_vif(group.ss_family, iface) == NO_VIF)
				continue;

			pif->sd[i] = mcgroup_join(iface, NULL, &group);
		}
	}

	smclog(LOG_INFO, "Interface %s is now proxy %s", iface->ifname,
	       role == PROXY_UPSTREAM ? "upstream" : "downstream");

	membership_changed(NULL);
}

static void pif_del(struct proxy_iface *pif)
{
	struct member *m, *tmp;
	size_t i;

	smclog(LOG_INFO, "Interface %s no longer proxy %s", pif->iface->ifname,
	       pif->role == PROXY_UPSTREAM ? "upstream" : "downstream");

	for (i = 0; i < NELEMS(pif->sd); i++) {
		inet_addr_t group = { 0 };

		if (pif->sd[i] == -1)
			continue;

		inet_str2addr(control_groups[i], &group);
		mcgroup_leave(pif->iface, NULL, &group, pif->sd[i]);
	}

	TAILQ_FOREACH_SAFE(m, &pif->members, link, tmp)
		member_del(pif, m);

	if (upstream == pif)
		upstream = NULL;
	TAILQ_REMOVE(&pif_list, pif, link);
	free(pif);

	if (TAILQ_EMPTY(&pif_list))
		timer_del(sweep, NULL);

	membership_changed(NULL);
}

/*
 * Bring the proxy state of @iface in line with its configured role,
 * called whenever its VIFs or its phyint line change.
 */
void proxy_sync(struct iface *iface)
{
	struct proxy_iface *pif;
	int role = iface->proxy;

	if (iface->vif == NO_VIF && iface->mif == NO_VIF)
		role = PROXY_NONE;

	if (role == PROXY_UPSTREAM && upstream && upstream->iface != iface) {
		smclog(LOG_WARNING, "Only one upstream interface is supported, %s is, ignoring %s",
		       upstream->iface->ifname, iface->ifname);
		role = PROXY_NONE;
	}

	pif = pif_find(iface);
	if (pif && pif->role == role) {
		time_t t = now();
		size_t i;

		/* a shorter query interval takes effect at once */
		for (i = 0; i < NELEMS(pif->querier); i++)
			lower(&pif->querier[i].next, t + query_interval(pif));
		return;
	}

	if (pif)
		pif_del(pif);
	if (role != PROXY_NONE)
		pif_add(iface, role);
}

/* A downstream interface this report may come from, or NULL */
static struct proxy_iface *downstream(struct iface *iface, inet_addr_t *group)
{
	struct proxy_iface *pif;

	pif = pif_find(iface);
	if (!pif || pif->role != PROXY_DOWNSTREAM)
		return NULL;
	if (is_linklocal_mcast(group))
		return NULL;

	return pif;
}

/*
 * Querier election, lowest address wins, RFC 3376 §6.6.2 and RFC 3810
 * §7.6.2.  A group-specific query lowers our group timer, §6.6.1.
 */
void proxy_query(struct iface *iface, inet_addr_t *src, inet_addr_t *group, int mrt, int gen)
{
	char s[INET_ADDRSTR_LEN];
	struct proxy_iface *pif;
	struct querier *q;
	struct member *m;
	inet_addr_t me;
	time_t t = now();
	int cmp;

	pif = pif_find(iface);
	if (!pif)
		return;

	/* proxy queries from 0.0.0.0 or :: never win */
	if (is_anyaddr(src))
		return;

	q = querier_of(pif, src->ss_family);
	gen_seen(&q->gen, gen, t + group_interval(pif));

	if (pif->role != PROXY_DOWNSTREAM)
		return;

	inet_addr2str(src, s, sizeof(s));
	if (q->me) {
		/* any real querier beats our proxy queries */
		if (querier_addr(pif, src->ss_family, &me) > 0 && inet_addr_cmp(src, &me) >= 0)
			return;

		smclog(LOG_INFO, "Querier %s on %s wins, standing down", s, iface->ifname);
		q->me = 0;
	} else {
		cmp = is_anyaddr(&q->other) ? -1 : inet_addr_cmp(src, &q->other);
		if (cmp > 0)
			return;
		if (cmp < 0)
			smclog(LOG_INFO, "New %s querier %s on %s", family_name(src->ss_family), s, iface->ifname);
	}

	q->other   = *src;
	q->expires = t + other_querier_interval(pif);

	if (is_anyaddr(group))
		return;

	m = member_find(pif, group);
	if (m && m->exclude)
		lower(&m->expires, t + settings[ROBUSTNESS].val * mrt);
}

/* IGMPv1/v2 and MLDv1 report, or a v3 EXCLUDE record: any source wanted */
void proxy_report(struct iface *iface, inet_addr_t *src, inet_addr_t *group, int gen)
{
	char g[INET_ADDRSTR_LEN], s[INET_ADDRSTR_LEN];
	struct proxy_iface *pif;
	struct member *m;
	time_t t = now();
	int changed = 0;

	pif = downstream(iface, group);
	if (!pif)
		return;

	m = member_get(pif, group, 1, &changed);
	if (!m)
		return;

	m->expires    = t + group_interval(pif);
	m->query.left = 0;
	gen_seen(&m->gen, gen, m->expires);

	smclog(LOG_INFO, "Member report for %s from %s on %s, v%d", inet_addr2str(group, g, sizeof(g)),
	       inet_addr2str(src, s, sizeof(s)), iface->ifname, gen);

	if (changed)
		membership_changed(group);
}

/* IGMPv3 or MLDv2 INCLUDE/ALLOW record: these sources wanted */
void proxy_include(struct iface *iface, inet_addr_t *src, inet_addr_t *group, inet_addr_t *srcs, int num)
{
	char g[INET_ADDRSTR_LEN], s[INET_ADDRSTR_LEN];
	struct proxy_iface *pif;
	struct member *m;
	time_t expires;
	int changed = 0;
	int i;

	pif = downstream(iface, group);
	if (!pif)
		return;

	m = member_get(pif, group, 0, &changed);
	if (!m)
		return;

	expires = now() + group_interval(pif);
	for (i = 0; i < num; i++) {
		if (source_refresh(m, &srcs[i], expires))
			changed = 1;
	}

	smclog(LOG_INFO, "Member report for %s from %s on %s, v3 with %d sources",
	       inet_addr2str(group, g, sizeof(g)), inet_addr2str(src, s, sizeof(s)),
	       iface->ifname, num);

	if (changed)
		membership_changed(group);
}

/*
 * Query the group before dropping it, RFC 3376 §6.4.2 and §7.3.2.
 * Returns the member to act on, or NULL to ignore the leave.
 */
static struct member *leaving(struct iface *iface, inet_addr_t *src, inet_addr_t *group, int gen, time_t t)
{
	char g[INET_ADDRSTR_LEN], s[INET_ADDRSTR_LEN];
	struct proxy_iface *pif;
	struct querier *q;
	struct member *m;
	const char *why;

	pif = downstream(iface, group);
	if (!pif)
		return NULL;

	q = querier_of(pif, group->ss_family);
	m = member_find(pif, group);
	if (!m)
		why = "not a member";
	else if (!q->me)
		why = "not querier";
	else if (m->gen.cur == 1 || (m->gen.cur == 2 && gen == 3))
		why = "older hosts present";
	else {
		if (!m->query.left) {
			smclog(LOG_INFO, "Leave for %s from %s on %s, querying the group",
			       inet_addr2str(group, g, sizeof(g)), inet_addr2str(src, s, sizeof(s)),
			       iface->ifname);
			m->query.left = settings[ROBUSTNESS].val;
			m->query.next = t;
		}

		return m;
	}

	smclog(LOG_DEBUG, "Leave for %s from %s on %s ignored, %s", inet_addr2str(group, g, sizeof(g)),
	       inet_addr2str(src, s, sizeof(s)), iface->ifname, why);

	return NULL;
}

/* IGMPv2 leave, MLDv1 done, or a v3 TO_IN({}) record */
void proxy_leave(struct iface *iface, inet_addr_t *src, inet_addr_t *group, int gen)
{
	struct member *m;
	time_t t = now();

	m = leaving(iface, src, group, gen, t);
	if (m && m->exclude)
		lower(&m->expires, t + last_member_time());
}

/* IGMPv3 or MLDv2 BLOCK record: these sources no longer wanted */
void proxy_block(struct iface *iface, inet_addr_t *src, inet_addr_t *group, inet_addr_t *srcs, int num)
{
	struct member *m;
	time_t t = now();
	int i;

	m = leaving(iface, src, group, 3, t);
	if (!m || m->exclude)
		return;

	for (i = 0; i < num; i++) {
		struct source *s;

		s = source_find(m, &srcs[i]);
		if (s)
			lower(&s->expires, t + last_member_time());
	}
}

void proxy_exit(void)
{
	struct proxy_iface *pif, *tmp;

	TAILQ_FOREACH_SAFE(pif, &pif_list, link, tmp)
		pif_del(pif);
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
