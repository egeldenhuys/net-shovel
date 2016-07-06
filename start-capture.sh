
#!/bin/bash

mkdir tcpdump
sudo tcpdump -G 1 -w 'tcpdump/%Y-%m-%d_%H_%M_%S.pcap' -i wlp5s0 -n -s 96
