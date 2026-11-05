#!/bin/sh
# Verifies IGMP/MLD proxying: a host on the downstream interface joins
# groups and traffic from the upstream side is routed to it, groups
# nobody joined are not.
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
ip addr add 2001:1::1/64 dev "$UIF"
nsenter --net="$UP" -- ip addr add 10.0.0.10/24 dev eth0
nsenter --net="$UP" -- ip addr add 2001:1::10/64 dev eth0

ip addr add 20.0.0.1/24 dev "$DIF"
ip addr add 2001:2::1/64 dev "$DIF"
nsenter --net="$DOWN" -- ip addr add 20.0.0.10/24 dev eth0
nsenter --net="$DOWN" -- ip addr add 2001:2::10/64 dev eth0

ip -br a

print "Creating config ..."
cat <<EOF > "/tmp/$NM/conf"
phyint $UIF enable upstream
phyint $DIF enable downstream
EOF
cat "/tmp/$NM/conf"

print "Starting smcrouted ..."
../src/smcrouted -f "/tmp/$NM/conf" -n -N -P "/tmp/$NM/pid" -l debug -u "/tmp/$NM/sock" &
sleep 1

print "Joining groups on downstream host ..."
nsenter --net="$DOWN" -- timeout 60 mreceive -q -I eth0 -g 225.1.2.3 -p 4441 >/dev/null 2>&1 &
echo $! >> "/tmp/$NM/PIDs"
nsenter --net="$DOWN" -- timeout 60 mreceive -q -I eth0 -g ff2e::42 -p 4442 >/dev/null 2>&1 &
echo $! >> "/tmp/$NM/PIDs"
sleep 1
nsenter --net="$DOWN" -- sh -c 'echo 2 > /proc/sys/net/ipv4/conf/eth0/force_igmp_version'
nsenter --net="$DOWN" -- timeout 60 mreceive -q -I eth0 -g 225.1.2.5 -p 4443 >/dev/null 2>&1 &
echo $! >> "/tmp/$NM/PIDs"
sleep 2

echo "-----------------------------------------------------------------------------------"
../src/smcroutectl -pdu "/tmp/$NM/sock" show members | tee "/tmp/$NM/members"
echo "-----------------------------------------------------------------------------------"

print "Starting collector ..."
nsenter --net="$DOWN" -- tshark -c 12 -lni eth0 -w "/tmp/$NM/pcap" \
	'dst 225.1.2.3 or dst 225.1.2.4 or dst 225.1.2.5 or dst ff2e::42' &
echo $! >> "/tmp/$NM/PIDs"
sleep 1

print "Starting emitter ..."
nsenter --net="$UP" -- ping    -c 3 -W 1 -I eth0       -t 3 225.1.2.3 >/dev/null
nsenter --net="$UP" -- ping    -c 3 -W 1 -I eth0       -t 3 225.1.2.4 >/dev/null
nsenter --net="$UP" -- ping    -c 3 -W 1 -I eth0       -t 3 225.1.2.5 >/dev/null
nsenter --net="$UP" -- ping -6 -c 3 -W 1 -I 2001:1::10 -t 3 ff2e::42  >/dev/null
show_mroute

print "Analyzing ..."
tshark -r "/tmp/$NM/pcap" 2>/dev/null | tee "/tmp/$NM/result"
lines1=$(grep ICMP "/tmp/$NM/result" | grep -c 225.1.2.3)
lines2=$(grep ICMP "/tmp/$NM/result" | grep -c 225.1.2.4)
lines3=$(grep ICMP "/tmp/$NM/result" | grep -c 225.1.2.5)
lines4=$(grep ICMP "/tmp/$NM/result" | grep -c ff2e::42 )
members=$(grep -c "^225.1.2.3 .*exclude\|^225.1.2.5 .*exclude\|^ff2e::42 .*exclude" "/tmp/$NM/members")
echo " => $lines1 for 225.1.2.3 (IGMPv3), expected >= 2"
echo " => $lines2 for 225.1.2.4 (no member), expected 0"
echo " => $lines3 for 225.1.2.5 (IGMPv2), expected >= 2"
echo " => $lines4 for ff2e::42 (MLDv2), expected >= 2"
echo " => $members memberships listed, expected 3"

# shellcheck disable=SC2166 disable=SC2086
[ $lines1 -ge 2 -a $lines2 -eq 0 -a $lines3 -ge 2 -a $lines4 -ge 2 -a $members -eq 3 ] && OK
FAIL
