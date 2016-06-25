#!/bin/bash

sudo ./'capture-1-min-wlan0.sh'
./'get-connection-summary.sh'
rm -fv capture-1-min.pcap
