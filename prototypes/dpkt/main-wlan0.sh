#!/bin/bash

sudo ./'capture-1-min-wlan0.sh'
python get-connections.py
rm -fv capture-1-min.pcap
