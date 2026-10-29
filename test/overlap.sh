#!/bin/sh
# Verifies that an (S,G) learned from a NOCACHE upcall gets the oifs of
# every (*,G) rule covering it when two rules overlap
#set -x

# shellcheck source=/dev/null
. "$(dirname "$0")/lib.sh"

print "Creating world ..."
topo plus
ip addr add 10.0.0.1/24 dev a1
ip -br a

print "Creating config ..."
cat <<EOF > "/tmp/$NM/conf"
phyint a1 enable
phyint a2 enable
phyint a3 enable

mroute from a1 group 225.1.2.0/24 to a2
mroute from a1 group 225.1.2.3    to a3
EOF
cat "/tmp/$NM/conf"

print "Starting smcrouted ..."
../src/smcrouted -f "/tmp/$NM/conf" -n -N -P "/tmp/$NM/pid" -l debug -u "/tmp/$NM/sock" &
sleep 1

collect a2 -i a3 -c12 'dst 225.1.2.3 or dst 225.1.2.4'

print "Starting emitter ..."
ping -c 3 -W 1 -I a1 -t 2 225.1.2.3 >/dev/null
ping -c 3 -W 1 -I a1 -t 2 225.1.2.4 >/dev/null
show_mroute

print "Analyzing ..."
tshark -r "/tmp/$NM/pcap" -T fields -e frame.interface_name -e ip.dst 2>/dev/null | tee "/tmp/$NM/result"
lines1=$(grep -c "^a2.*225.1.2.3" "/tmp/$NM/result")
lines2=$(grep -c "^a3.*225.1.2.3" "/tmp/$NM/result")
lines3=$(grep -c "^a2.*225.1.2.4" "/tmp/$NM/result")
lines4=$(grep -c "^a3.*225.1.2.4" "/tmp/$NM/result")
echo " => $lines1 for 225.1.2.3 on a2, expected >= 2"
echo " => $lines2 for 225.1.2.3 on a3, expected >= 2"
echo " => $lines3 for 225.1.2.4 on a2, expected >= 2"
echo " => $lines4 for 225.1.2.4 on a3, expected 0"

# shellcheck disable=SC2166 disable=SC2086
[ $lines1 -ge 2 -a $lines2 -ge 2 -a $lines3 -ge 2 -a $lines4 -eq 0 ] && OK
FAIL
