#!/usr/bin/env bash

curl -LO https://raw.githubusercontent.com/firehol/blocklist-ipsets/refs/heads/master/blocklist_net_ua.ipset

sed -i '/^#.*$/d' blocklist_net_ua.ipset