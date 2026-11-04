
BSD route-socket equivalent of the Linux netlink listener
---------------------------------------------------------

`src/ifevent_nl.c` wakes `smcrouted` on `RTM_NEWLINK`/`RTM_DELLINK`
events so pending mroute/mgroup directives activate automatically when
their interface arrives.  BSD systems currently fall through to
`src/ifevent_stub.c` (no-op) and depend on `SIGHUP`/`smcroutectl reload`
to pick up new interfaces.

A `src/ifevent_route.c` using `PF_ROUTE` / `RTM_IFINFO` / `RTM_NEWADDR`
on BSD would slot into the existing automake conditional
(`HAVE_NETLINK` becomes the misnomer; rename to `HAVE_IFEVENT` and
gate it as `case $host_os in linux*|*bsd*) ...`).  The callback just
needs to invoke `iface_update()` and `pending_drain()` — same as the
Linux side.


Refactor MRDISC Support
-----------------------

The current MRDISC implementation is fragile (see issue #175 for an
example), and it also does not work on non-Linux systems.  So the
implementation really needs to be refactored, not just for this but also
for adding IPv6 support (below).


Add Support for IPv6 MRDISC
---------------------------

[RFC4286][1] details both IPv4 and IPv6, which should not be problem
to support in SMCRoute.  Anyone with Wireshark and a bit of patience
could add it.  Your patch is welcome! :)

[1]: https://datatracker.ietf.org/doc/html/rfc4286


Tests must have uniquely named netns (if any)
---------------------------------------------

I've had to rename the R1/R2 netns used in test/gre.sh, because it turns
out these names are shared when we run in the unshare and gre.sh's names
clashed with multi.sh's.  I.e., they were stomping hard on each other's
toes and often the gre.sh test completed before multi.sh, thus causing
the latter to lose both R1 and R2 and the test failed (of course).

We may be able to work around this by running each test in its own root
netns.  Something that could be set up by lib.sh.  I have not verified
this yet, hence this TODO.


Add support for WRONGVIF, somehow
---------------------------------

When an (S,G) for an already installed kernel MFC route suddenly appears
on another inbound interface, the kernel sends a WRONGVIF upcall message
to smcrouted.  Currently we don't act on it, mostly because there is no
clear idea how to deal with such cases from a small routing daemon that
knows nothing of the rest of the layer-3 topology (which may have been
reconfigured due to link loss by, e.g. OSPF).  It can be a valid change
of inbound interface, or looped back traffic that we don't want.

For now, users are recommended to install multiast snooping switches on
their outbound interfaces, and/or leverage to `phyint foo ttl-threshold`
setting to prevent already routed multicast from being looped back.

One idea is to delegate the behavior to our external script facility.


Investigate why MIF thresholds don't seem to work on Linux 5.11.0
------------------------------------------------------------------

Here smcrouted has managed to set the TTL thresholds of three OIFs to
values != 1, but the kernel still lists all of them as `:1`.  See test
`reload6.sh`

    Group                            Origin                           Iif      Pkts  Bytes     Wrong  Oifs
    ff2e:0000:0000:0000:0000:0000:0000:0042 fc00:0000:0000:0000:0000:0000:0000:0001 0          0        0        0  2:1    4:1    5:1


Possibly Exit with Error if Multicast Socket is Busy
----------------------------------------------------

Currently we only log this state and then continue.  Not sure what is
the best approach, but everything read from a .conf will fail so not
much point really continuing?

    smcroute[2359]: IPv4 multicast routing API already in use: Address in use

Proposal: exit with error if either mrouting socket is busy.
          We need to consider this a configuration error.


Support for (re-)enumerating VIFs at runtime
--------------------------------------------

Currently the `-t SEC` startup delay option has to be used if not all
interfaces are available when `smcrouted` starts.  Commonly a problem at
boot, but also if adding a pluggable interface (PCMCIA/USB) at runtime.

Hence, it would be a great addition to SMCRoute if new interface VIF/MIF
mappings could be at least added at runtime.


Support for filtering based on source ADDRESS/LEN
-------------------------------------------------

When setting up a (*,G/LEN) route it may be necessary to filter out some
senders of multicast.  The following is a suggestion for how that might
look, notice the omitted `source` argument:

    mroute from eth0 except 192.168.1.0/24 group 225.1.2.0/24 to eth1 eth2

Filtering multiple sources:

    mroute from eth0 except 192.168.1.0/24,192.168.2.3 group 225.1.2.0/24 to eth1 eth2

This is sometimes also referred to as Administrative Scoping (RFC2365).


IGMP/MLD proxy, remaining work
------------------------------

The proxy, `phyint IFNAME upstream|downstream`, covers what igmpproxy
and mcproxy do for most setups.  Left for later:

  - EXCLUDE mode source lists are ignored, RFC 5790 lightweight
    semantics.  Full RFC 3376 §6.4 state (EXCLUDE with sources, and
    group-and-source specific queries) would need a per-group filter
    on the upstream that the kernel can express with setsourcefilter()
    already, so the merge in `upstream_sync()` is the place to start
  - One upstream interface per daemon.  mcproxy allows several, each
    with a set of groups; a `proxy` directive mapping group ranges to
    upstreams would be the natural syntax, with `proxy_oifs()` picking
    the upstream per entry instead of the global `upstream`
  - Allow/deny lists per downstream interface, to keep e.g. SSDP from
    being forwarded upstream.  Filter at report ingress, before the
    membership is created, so forwarding and the upstream subscription
    agree
  - The IGMP/MLD version to start querying with is always the latest,
    with fallback per link and per group when older hosts appear.  A
    per-interface `phyint` option, `igmpv2`/`mldv1`, would let hosts
    that choke on v3 queries be served from the start
  - A non-querier keeps its own timers.  RFC 3376 §6.2.1 has it adopt
    the elected querier's QQI and QRV from the QQIC and QRV fields of
    its queries, `proxy_query()` gets the whole query so the fields are
    there to parse
  - mrdisc, RFC 4286, is IPv4 only; the MLD side of the proxy has the
    ff02::2 socket for it already
  - Only tested on Linux.  Proxy queries from 0.0.0.0/:: need the Linux
    packet socket, the topology query needs the netlink listener, both
    are left out on other systems.  The receive path uses IP_PKTINFO
    with an IP_RECVIF fallback written but untested, and the sticky
    IPV6_HOPOPTS Router Alert needs CAP_NET_RAW at init on Linux


[igmpproxy]: https://github.com/pali/igmpproxy
[mcproxy]:   https://github.com/mcproxy/mcproxy
[RFC4605]:   https://www.ietf.org/rfc/rfc4605.txt
