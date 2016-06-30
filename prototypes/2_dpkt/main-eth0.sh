#!/bin/bash

sudo ./'capture-1-min-eth0.sh'
python get-connections.py
rm -fv capture-1-min.pcap
