#!/bin/sh
# Verifies the IGMP/MLD querier on a downstream interface: general
# queries are sent at startup, a leave is followed by a group-specific
# query, and forwarding stops within the last member query time.
#set -x

# shellcheck source=/dev/null
. "$(dirname "$0")/lib.sh"
check_dep mreceive

UP=/tmp/$NM/wan
DOWN=/tmp/$NM/lan
UIF=$(basename "$UP")
DIF=$(basename "$DOWN")

print "Creating world ..."
topo isolated "$UP" "$DOWN"

ip addr add 10.0.0.1/24 dev "$UIF"
nsenter --net="$UP" -- ip addr add 10.0.0.10/24 dev eth0

ip addr add 20.0.0.1/24 dev "$DIF"
nsenter --net="$DOWN" -- ip addr add 20.0.0.10/24 dev eth0

ip -br a

print "Creating config ..."
cat <<EOF > "/tmp/$NM/conf"
phyint $UIF enable upstream
phyint $DIF enable downstream
EOF
cat "/tmp/$NM/conf"

print "Starting control traffic collector on downstream host ..."
nsenter --net="$DOWN" -- tshark -lni eth0 -w "/tmp/$NM/ctrl.pcap" 'igmp or ip6' 2>/dev/null &
CTRL=$!
echo $CTRL >> "/tmp/$NM/PIDs"
sleep 1

print "Starting smcrouted ..."
../src/smcrouted -f "/tmp/$NM/conf" -n -N -P "/tmp/$NM/pid" -l debug -u "/tmp/$NM/sock" &
sleep 2

print "Joining 225.1.2.3 on downstream host for 4 sec ..."
nsenter --net="$DOWN" -- timeout 4 mreceive -q -I eth0 -g 225.1.2.3 >/dev/null 2>&1 &
echo $! >> "/tmp/$NM/PIDs"
sleep 1

print "Verifying forwarding while member ..."
nsenter --net="$DOWN" -- tshark -c 3 -lni eth0 -w "/tmp/$NM/join.pcap" 'dst 225.1.2.3' 2>/dev/null &
echo $! >> "/tmp/$NM/PIDs"
sleep 1
nsenter --net="$UP" -- ping -c 3 -W 1 -I eth0 -t 3 225.1.2.3 >/dev/null

print "Waiting for the host to leave and the group to time out ..."
sleep 6
show_mroute

print "Verifying forwarding stopped ..."
nsenter --net="$DOWN" -- timeout 6 tshark -c 3 -lni eth0 -w "/tmp/$NM/leave.pcap" 'dst 225.1.2.3' 2>/dev/null &
echo $! >> "/tmp/$NM/PIDs"
sleep 1
nsenter --net="$UP" -- ping -c 3 -W 1 -I eth0 -t 3 225.1.2.3 >/dev/null
sleep 2
kill $CTRL
sleep 1

print "Analyzing ..."
tshark -r "/tmp/$NM/ctrl.pcap" 2>/dev/null | tee "/tmp/$NM/ctrl"
general=$(grep -c "Membership Query, general" "/tmp/$NM/ctrl")
specific=$(grep -c "Membership Query, specific for group 225.1.2.3" "/tmp/$NM/ctrl")
mld=$(grep -c "Multicast Listener Query" "/tmp/$NM/ctrl")
joined=$(tshark -r "/tmp/$NM/join.pcap" 2>/dev/null | grep -c ICMP)
left=$(tshark -r "/tmp/$NM/leave.pcap" 2>/dev/null | grep -c ICMP)
echo " => $general IGMP general queries, expected >= 1"
echo " => $mld MLD general queries, expected >= 1"
echo " => $specific group-specific queries for 225.1.2.3, expected >= 1"
echo " => $joined frames forwarded while member, expected >= 2"
echo " => $left frames forwarded after leave, expected 0"

# shellcheck disable=SC2166 disable=SC2086
[ $general -ge 1 -a $mld -ge 1 -a $specific -ge 1 -a $joined -ge 2 -a $left -eq 0 ] && OK
FAIL
