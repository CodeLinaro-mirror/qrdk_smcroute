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

#ifndef SMCROUTE_IGMP_H_
#define SMCROUTE_IGMP_H_

#include "config.h"
#include <stddef.h>
#include <stdint.h>

#include "inet.h"

#ifndef IGMP_V3_MEMBERSHIP_REPORT
#define IGMP_V3_MEMBERSHIP_REPORT	0x22
#endif

/* IGMPv3 and MLDv2 group record types, RFC 3376 §4.2.12 */
#ifndef IGMP_MODE_IS_INCLUDE
#define IGMP_MODE_IS_INCLUDE		1
#define IGMP_MODE_IS_EXCLUDE		2
#define IGMP_CHANGE_TO_INCLUDE_MODE	3
#define IGMP_CHANGE_TO_EXCLUDE_MODE	4
#define IGMP_ALLOW_NEW_SOURCES		5
#define IGMP_BLOCK_OLD_SOURCES		6
#endif

struct igmpv3_query {
	uint8_t  type;
	uint8_t  code;
	uint16_t csum;
	uint32_t group;
	uint8_t  qrv;		/* Resv:4 S:1 QRV:3 */
	uint8_t  qqic;
	uint16_t nsrcs;
	uint32_t srcs[0];
};

/*
 * Max Resp Code and QQIC, RFC 3376 §4.1.1, and the MLDv2 Max Resp
 * Code, RFC 3810 §5.1.3: plain below 2^(mant+3), else a 3-bit exponent
 * and a @mant bit mantissa.  IGMP has 4 mantissa bits, MLD 12.
 */
static inline unsigned int igmp_float_time(unsigned int code, int mant)
{
	if (code < (1U << (mant + 3)))
		return code;

	return ((code & ((1U << mant) - 1)) | (1U << mant)) << (((code >> mant) & 7) + 3);
}

static inline unsigned int igmp_time_float(unsigned int val, int mant)
{
	unsigned int exp = 0;

	if (val < (1U << (mant + 3)))
		return val;

	val >>= 3;
	while (val > (2U << mant) - 1) {
		val >>= 1;
		exp++;
	}
	if (exp > 7)
		return (2U << (mant + 3)) - 1;

	return (1U << (mant + 3)) | (exp << mant) | (val & ((1U << mant) - 1));
}

struct iface;

#ifdef ENABLE_PROXY
void   igmp_recv       (int ifindex, uint8_t *buf, size_t len);
void   igmp_v3_records (struct iface *iface, inet_addr_t *src, const uint8_t *buf, size_t len, size_t alen);
size_t igmp_build_query(uint8_t *buf, int gen, int mrt, inet_addr_t *group, int qqi, int qrv);
#else
#define igmp_recv(ifindex, buf, len)
#endif

#endif /* SMCROUTE_IGMP_H_ */
