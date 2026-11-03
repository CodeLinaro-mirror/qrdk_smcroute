#!/bin/sh
# Verifies the configurable querier timers: a per-phyint query
# interval, with a global response interval and robustness, shows in
# the number of general queries sent and in their max response time.
#set -x

# shellcheck source=/dev/null
. "$(dirname "$0")/lib.sh"

DOWN=/tmp/$NM/lan
DIF=$(basename "$DOWN")

print "Creating world ..."
topo isolated "$DOWN"

ip addr add 20.0.0.1/24 dev "$DIF"
nsenter --net="$DOWN" -- ip addr add 20.0.0.10/24 dev eth0

ip -br a

print "Creating config ..."
cat <<EOF > "/tmp/$NM/conf"
global-response-interval 2
robustness 3
phyint $DIF enable downstream query-interval 4
EOF
cat "/tmp/$NM/conf"

print "Starting control traffic collector on downstream host ..."
nsenter --net="$DOWN" -- tshark -lni eth0 -w "/tmp/$NM/ctrl.pcap" 'igmp or ip6' 2>/dev/null &
CTRL=$!
echo $CTRL >> "/tmp/$NM/PIDs"
sleep 1

print "Starting smcrouted ..."
../src/smcrouted -f "/tmp/$NM/conf" -n -N -P "/tmp/$NM/pid" -l debug -u "/tmp/$NM/sock" &
sleep 1

print "Collecting queries for 14 sec: 3 at startup 1 sec apart, then every 4 sec ..."
sleep 14
kill $CTRL
sleep 1

print "Analyzing ..."
tshark -r "/tmp/$NM/ctrl.pcap" 2>/dev/null | tee "/tmp/$NM/ctrl"
general=$(grep -c "Membership Query, general" "/tmp/$NM/ctrl")
mld=$(grep -c "Multicast Listener Query" "/tmp/$NM/ctrl")
resp=$(tshark -r "/tmp/$NM/ctrl.pcap" -Y 'igmp.type == 0x11' -T fields -e igmp.max_resp 2>/dev/null | sort -u | tr '\n' ' ')
echo " => $general IGMP general queries, expected >= 5"
echo " => $mld MLD general queries, expected >= 5"
echo " => IGMP max response time(s), in 1/10 sec: $resp, expected 20"

# shellcheck disable=SC2166 disable=SC2086
[ $general -ge 5 -a $mld -ge 5 -a "$resp" = "20 " ] && OK
FAIL
