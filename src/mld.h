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

#ifndef SMCROUTE_MLD_H_
#define SMCROUTE_MLD_H_

#include "config.h"
#include <stddef.h>
#include <stdint.h>

#include "inet.h"

#ifndef MLDV2_LISTENER_REPORT
#define MLDV2_LISTENER_REPORT 143
#endif

#if defined(ENABLE_PROXY) && defined(HAVE_IPV6_MULTICAST_HOST)
void   mld_recv       (int ifindex, inet_addr_t *src, int hlim, uint8_t *buf, size_t len);
size_t mld_build_query(uint8_t *buf, int gen, int mrt, inet_addr_t *group, int qqi, int qrv);
#else
#define mld_recv(ifindex, src, hlim, buf, len)
#define mld_build_query(buf, gen, mrt, group, qqi, qrv) 0
#endif

#endif /* SMCROUTE_MLD_H_ */
