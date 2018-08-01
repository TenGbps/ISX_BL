#!/bin/bash
iptables -D INPUT -j DROP -m set --match-set isxbl src > /dev/null 2>&1
ipset flush isxbl > /dev/null 2>&1
ipset destroy isxbl > /dev/null 2>&1
wget -qO- http://bl.isx.fr/ipset | ipset restore
iptables -I INPUT -j DROP -m set --match-set isxbl src
