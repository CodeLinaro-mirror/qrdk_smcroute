#!/bin/sh
# Verifies the host side of the proxy: memberships learned on the
# downstream are reported on the upstream, any-source and
# source-specific alike, and an SSM stream is routed through.
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

print "Starting control traffic collector on upstream ..."
nsenter --net="$UP" -- tshark -lni eth0 -w "/tmp/$NM/ctrl.pcap" 'igmp or ip6' 2>/dev/null &
CTRL=$!
echo $CTRL >> "/tmp/$NM/PIDs"
sleep 1

print "Starting smcrouted ..."
../src/smcrouted -f "/tmp/$NM/conf" -n -N -P "/tmp/$NM/pid" -l debug -u "/tmp/$NM/sock" &
sleep 2

print "Joining groups on downstream host for 8 sec ..."
nsenter --net="$DOWN" -- timeout 8 mreceive -q -I eth0 -g 225.1.2.3 -p 4441 >/dev/null 2>&1 &
echo $! >> "/tmp/$NM/PIDs"
nsenter --net="$DOWN" -- timeout 8 mreceive -q -I eth0 -g 232.1.1.1 -s 10.0.0.10 -p 4442 >/dev/null 2>&1 &
echo $! >> "/tmp/$NM/PIDs"
nsenter --net="$DOWN" -- timeout 8 mreceive -q -I eth0 -g ff2e::42 -p 4443 >/dev/null 2>&1 &
echo $! >> "/tmp/$NM/PIDs"
sleep 2

print "Verifying forwarding ..."
nsenter --net="$DOWN" -- tshark -c 6 -lni eth0 -w "/tmp/$NM/data.pcap" 'dst 225.1.2.3 or dst 232.1.1.1' 2>/dev/null &
echo $! >> "/tmp/$NM/PIDs"
sleep 1
nsenter --net="$UP" -- ping -c 3 -W 1 -I eth0 -t 3 225.1.2.3 >/dev/null
nsenter --net="$UP" -- ping -c 3 -W 1 -I eth0 -t 3 232.1.1.1 >/dev/null
show_mroute

print "Waiting for the host to leave ..."
sleep 6
kill $CTRL
sleep 1

print "Analyzing ..."
tshark -r "/tmp/$NM/ctrl.pcap" 2>/dev/null | grep "10.0.0.1 \|2001:1::1 \|fe80.*→ ff02::16" | tee "/tmp/$NM/ctrl"
asm=$(grep -c "Join group 225.1.2.3" "/tmp/$NM/ctrl")
ssm=$(grep "232.1.1.1" "/tmp/$NM/ctrl" | grep -c "10.0.0.10")
mld=$(tshark -r "/tmp/$NM/ctrl.pcap" -T fields -e icmpv6.mldr.mar.multicast_address 2>/dev/null | grep -c ff2e::42)
left=$(grep -c "Leave group 225.1.2.3" "/tmp/$NM/ctrl")
data1=$(tshark -r "/tmp/$NM/data.pcap" 2>/dev/null | grep ICMP | grep -c 225.1.2.3)
data2=$(tshark -r "/tmp/$NM/data.pcap" 2>/dev/null | grep ICMP | grep -c 232.1.1.1)
echo " => $asm upstream joins of 225.1.2.3, expected >= 1"
echo " => $ssm upstream joins of (10.0.0.10,232.1.1.1), expected >= 1"
echo " => $mld upstream MLDv2 reports, expected >= 1"
echo " => $left upstream leaves of 225.1.2.3, expected >= 1"
echo " => $data1 frames of 225.1.2.3 forwarded, expected >= 2"
echo " => $data2 frames of 232.1.1.1 forwarded, expected >= 2"

# shellcheck disable=SC2166 disable=SC2086
[ $asm -ge 1 -a $ssm -ge 1 -a $mld -ge 1 -a $left -ge 1 -a $data1 -ge 2 -a $data2 -ge 2 ] && OK
FAIL
