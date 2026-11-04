#!/bin/sh
# Verifies proxy queries from the unspecified address: a downstream
# without an address queries from 0.0.0.0 and ::, as does one with an
# address and the proxy-querier flag, and both stand down as soon as a
# real querier is heard.
#set -x

# shellcheck source=/dev/null
. "$(dirname "$0")/lib.sh"
check_dep python3

LAN1=/tmp/$NM/lan1
LAN2=/tmp/$NM/lan2
IF1=$(basename "$LAN1")
IF2=$(basename "$LAN2")

print "Creating world ..."
topo isolated "$LAN1" "$LAN2"

ip addr add 20.0.0.1/24 dev "$IF1"
nsenter --net="$LAN1" -- ip addr add 20.0.0.10/24 dev eth0
nsenter --net="$LAN2" -- ip addr add 30.0.0.10/24 dev eth0

ip -br a

print "Creating config ..."
cat <<EOF > "/tmp/$NM/conf"
global-query-interval 4
router-alert off
phyint $IF1 enable downstream proxy-querier
phyint $IF2 enable downstream
EOF
cat "/tmp/$NM/conf"

capture()
{
    nsenter --net="$1" -- tshark -lni eth0 -w "$2" 'igmp or ip6' >/dev/null 2>&1 &
    echo $!
}

count()
{
    tshark -r "$1" -Y "$2" 2>/dev/null | grep -c .
}

print "Starting control traffic collectors ..."
C1=$(capture "$LAN1" "/tmp/$NM/lan1.pcap")
C2=$(capture "$LAN2" "/tmp/$NM/lan2.pcap")
sleep 1

print "Starting smcrouted ..."
../src/smcrouted -f "/tmp/$NM/conf" -n -N -P "/tmp/$NM/pid" -l debug -u "/tmp/$NM/sock" &
sleep 5
kill $C1 $C2
sleep 1

print "Sending an IGMPv2 general query from the host on $IF1 ..."
nsenter --net="$LAN1" -- python3 -c '
import socket, struct
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IGMP)
s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton("20.0.0.10"))
s.setsockopt(socket.IPPROTO_IP, socket.IP_OPTIONS, bytes([148, 4, 0, 0]))
pkt = bytes([0x11, 100, 0, 0, 0, 0, 0, 0])
csum = sum(struct.unpack("!4H", pkt))
csum = (csum >> 16) + (csum & 0xffff)
pkt = pkt[:2] + struct.pack("!H", ~csum & 0xffff) + pkt[4:]
s.sendto(pkt, ("224.0.0.1", 0))
'
sleep 1

print "Verifying the host is now querier on $IF1 ..."
../src/smcroutectl -u "/tmp/$NM/sock" -d show members | tee "/tmp/$NM/members"
../src/smcroutectl -u "/tmp/$NM/sock" show querier | tee "/tmp/$NM/querier"
C1=$(capture "$LAN1" "/tmp/$NM/lan1-after.pcap")
sleep 5
kill $C1
sleep 1

print "Analyzing ..."
tshark -r "/tmp/$NM/lan1.pcap" 2>/dev/null
q1=$(count "/tmp/$NM/lan1.pcap" 'igmp.type == 0x11 && ip.src == 0.0.0.0')
noopt=$(count "/tmp/$NM/lan1.pcap" "igmp.type == 0x11 && ip.src == 0.0.0.0 && ip.hdr_len == 20")
q2=$(count "/tmp/$NM/lan2.pcap" 'igmp.type == 0x11 && ip.src == 0.0.0.0')
m1=$(count "/tmp/$NM/lan1.pcap" 'icmpv6.type == 130 && ipv6.src == ::')
m2=$(count "/tmp/$NM/lan2.pcap" 'icmpv6.type == 130 && ipv6.src != ::')
after=$(count "/tmp/$NM/lan1-after.pcap" 'igmp.type == 0x11 && ip.src == 0.0.0.0')
host=$(grep -c "^$IF1 .*downstream *20.0.0.10" "/tmp/$NM/members")
querier=$(grep -c "^$IF1 *IGMP *proxy *20.0.0.10 " "/tmp/$NM/querier")
echo " => $q1 IGMP queries from 0.0.0.0 on $IF1 (proxy-querier), expected >= 2"
echo " => $noopt of them without Router Alert, expected $q1"
echo " => $q2 IGMP queries from 0.0.0.0 on $IF2 (no address), expected >= 2"
echo " => $m1 MLD queries from :: on $IF1, expected >= 2"
echo " => $m2 MLD queries from the link-local address on $IF2, expected >= 2"
echo " => $host lines showing the host as IGMP querier on $IF1, expected 1"
echo " => $querier lines of show querier with the host as IGMP querier on $IF1, expected 1"
echo " => $after IGMP queries from 0.0.0.0 on $IF1 after standing down, expected 0"

# shellcheck disable=SC2166 disable=SC2086
[ $q1 -ge 2 -a $q2 -ge 2 -a $m1 -ge 2 -a $m2 -ge 2 -a $host -eq 1 -a $querier -eq 1 -a $after -eq 0 -a $noopt -eq $q1 ] && OK
FAIL
