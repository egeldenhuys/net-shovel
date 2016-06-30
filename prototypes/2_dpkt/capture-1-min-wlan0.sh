#!/bin/bash

tcpdump -G 60 -W 1 -w capture-1-min.pcap -i wlan0 -n -s 96
