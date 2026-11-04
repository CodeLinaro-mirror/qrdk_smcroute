#!/bin/sh
# Verifies the topology query: when a bridge port starts forwarding
# the querier on a VLAN interface on top of the bridge sends a general
# query at once, instead of at the next query interval.
#set -x

# shellcheck source=/dev/null
. "$(dirname "$0")/lib.sh"

LEFT=/tmp/$NM/b1
RIGHT=/tmp/$NM/b2

print "Creating world ..."
topo isolated bridge "$LEFT" "$RIGHT"

ip addr add 10.0.0.1/24 dev vlan1
nsenter --net="$LEFT"  -- ip addr add 10.0.0.10/24 dev eth0
ip addr add 20.0.0.1/24 dev vlan2
nsenter --net="$RIGHT" -- ip addr add 20.0.0.10/24 dev eth0
bridge link
ip -br a

print "Creating config ..."
cat <<EOF > "/tmp/$NM/conf"
phyint vlan1 enable downstream
EOF
cat "/tmp/$NM/conf"

print "Starting smcrouted ..."
../src/smcrouted -f "/tmp/$NM/conf" -n -N -P "/tmp/$NM/pid" -l debug -u "/tmp/$NM/sock" &
sleep 2

print "Starting collector, the startup query is already sent ..."
nsenter --net="$LEFT" -- tshark -lni eth0 -w "/tmp/$NM/b1.pcap" 'igmp' >/dev/null 2>&1 &
C1=$!
sleep 1

print "Flapping bridge port b1 ..."
ip link set b1 down
sleep 1
ip link set b1 up
sleep 3
kill $C1
sleep 1

print "Analyzing ..."
tshark -r "/tmp/$NM/b1.pcap" 2>/dev/null
b1=$(tshark -r "/tmp/$NM/b1.pcap" -Y 'igmp.type == 0x11' 2>/dev/null | grep -c .)
echo " => $b1 IGMP queries on b1 after the port came up, expected >= 1"

# shellcheck disable=SC2086
[ $b1 -ge 1 ] && OK
FAIL
