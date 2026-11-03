#!/bin/sh
# Verifies .conf line continuation with a trailing backslash, and that
# a comment after the continued directive is ignored.

# shellcheck source=/dev/null
. "$(dirname "$0")/lib.sh"

print "Creating world ..."
topo basic
ip addr add 10.0.0.1/24 dev a1
ip addr add 20.0.0.1/24 dev a2

print "Creating config ..."
cat <<EOF > "/tmp/$NM/conf"
phyint a1 enable   \\
       ttl-threshold 3
mroute from a1 \\
       group 225.1.2.3 \\
       to a2                # a comment, not an interface
EOF
cat "/tmp/$NM/conf"

print "Starting smcrouted ..."
../src/smcrouted -f "/tmp/$NM/conf" -n -N -P "/tmp/$NM/pid" -l debug -u "/tmp/$NM/sock" &
sleep 1

print "Verifying ..."
../src/smcroutectl -u "/tmp/$NM/sock" show routes | tee "/tmp/$NM/routes"
route=$(grep -c "225.1.2.3) *a1 *a2$" "/tmp/$NM/routes")
echo " => $route route from a1 to a2 only, expected 1"

# shellcheck disable=SC2086
[ $route -eq 1 ] && OK
FAIL
