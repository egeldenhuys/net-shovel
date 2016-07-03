#!/bin/bash

sudo tcpdump -G 10 -w 'trace/%Y-%m-%d_%H_%M_%S.pcap' -i $1 -n -s 96
