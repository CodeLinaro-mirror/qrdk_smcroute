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

#ifndef SMCROUTE_KERN_H_
#define SMCROUTE_KERN_H_

#include "mcgroup.h"
#include "mroute.h"

struct mroute_stats {
	unsigned long ms_pktcnt;
	unsigned long ms_bytecnt;
	unsigned long ms_wrong_if;
};

/* Ancillary data of a packet from one of the mrouted sockets */
struct kern_rx {
	int         ifindex;	/* ingress interface, 0 if unknown */
	int         hlim;	/* IPv6 hop limit, -1 if unknown */
	inet_addr_t src;	/* IPv6 source, from the socket address */
};

int kern_join_leave  (int sd, int cmd, struct mcgroup *mcg);
int kern_set_filter  (int sd, struct iface *iface, inet_addr_t *group, int exclude, inet_addr_t *srcs, int num);

ssize_t kern_recv    (int sd, void *buf, size_t len, struct kern_rx *rx);
int     kern_send    (struct iface *iface, inet_addr_t *dst, const void *buf, size_t len);

int kern_mroute_init (int table_id, void (*cb)(int, void *), void *arg);
int kern_mroute_exit (void);

int kern_mroute6_init(int table_id, void (*cb)(int, void *), void *arg);
int kern_mroute6_exit(void);

int kern_vif_add     (struct iface *iface);
int kern_vif_del     (struct iface *iface);

int kern_mif_add     (struct iface *iface);
int kern_mif_del     (struct iface *iface);

int kern_mroute_add  (struct mroute *route);
int kern_mroute_del  (struct mroute *route);

int kern_stats       (struct mroute *route, struct mroute_stats *ms);

#endif /* SMCROUTE_KERN_H_ */
