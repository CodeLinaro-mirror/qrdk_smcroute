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

#ifndef SMCROUTE_PROXY_H_
#define SMCROUTE_PROXY_H_

#include "config.h"

#include "inet.h"

struct iface;
struct mroute;

/*
 * Host protocol generation, shared by IGMP and MLD:
 * 1 = IGMPv1, 2 = IGMPv2 and MLDv1, 3 = IGMPv3 and MLDv2
 */

#ifdef ENABLE_PROXY
void proxy_exit      (void);

void proxy_sync      (struct iface *iface);
int  proxy_role      (struct iface *iface);
int  proxy_oifs      (struct mroute *kern);

void proxy_query     (struct iface *iface, inet_addr_t *src, inet_addr_t *group, int mrt, int gen);
void proxy_report    (struct iface *iface, inet_addr_t *src, inet_addr_t *group, int gen);
void proxy_include   (struct iface *iface, inet_addr_t *src, inet_addr_t *group, inet_addr_t *srcs, int num);
void proxy_block     (struct iface *iface, inet_addr_t *src, inet_addr_t *group, inet_addr_t *srcs, int num);
void proxy_leave     (struct iface *iface, inet_addr_t *src, inet_addr_t *group, int gen);
#else
#define proxy_exit()
#define proxy_sync(iface)
#define proxy_oifs(kern)        0
#endif

#endif /* SMCROUTE_PROXY_H_ */
