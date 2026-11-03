EXTRA_DIST         = adv.sh basic.sh batch.sh bridge.sh contin.sh dyn.sh expire.sh gre.sh ipv6.sh
EXTRA_DIST        += include.sh isolated.sh join.sh joinlen.sh json.sh lib.sh
EXTRA_DIST        += lost.sh multi.sh mem.sh mrcache.sh mrdisc.sh overlap.sh pending.sh
EXTRA_DIST        += poison.sh proxy.sh proxyq.sh querier.sh reload.sh reload6.sh timers.sh upstream.sh vlan.sh vrfy.sh wrongvif.sh
CLEANFILES         = *~ *.trs *.log
TEST_EXTENSIONS    = .sh
TESTS_ENVIRONMENT  = unshare -mrun --map-auto

TESTS              = expire.sh
TESTS             += adv.sh
TESTS             += basic.sh
TESTS             += batch.sh
TESTS             += bridge.sh
TESTS             += contin.sh
TESTS             += dyn.sh
TESTS             += gre.sh
TESTS             += include.sh
TESTS             += ipv6.sh
TESTS             += isolated.sh
TESTS             += join.sh
TESTS             += joinlen.sh
TESTS             += json.sh
TESTS             += lost.sh
TESTS             += mem.sh
TESTS             += mrcache.sh
if USE_MRDISC
TESTS             += mrdisc.sh
endif
TESTS             += multi.sh
TESTS             += overlap.sh
TESTS             += pending.sh
TESTS             += poison.sh
if USE_PROXY
TESTS             += proxy.sh
TESTS             += proxyq.sh
TESTS             += querier.sh
endif
TESTS             += reload.sh
TESTS             += reload6.sh
if USE_PROXY
TESTS             += timers.sh
TESTS             += upstream.sh
endif
TESTS             += vlan.sh
TESTS             += vrfy.sh
TESTS             += wrongvif.sh
