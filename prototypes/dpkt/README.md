## Aim
- Parse pcap file using python and dpkt library
- Get source and destination IPs and total bytes transfered

## Method
- `sudo apt-get install python-pip`
- `sudo pip install dpkt`
- Capture using capture-1-min-wlan0.sh
- Place capture file in same dir named `capture-1-min.pcap`
- `python get-connections.py` to parse using dpkt

## Output
```
Source | Destination | Total bytes transfered
```

## Remarks
- Confirmed output with Wireshark. Matches!

## Links
- https://jon.oberheide.org/blog/2008/10/15/dpkt-tutorial-2-parsing-a-pcap-file/
- https://github.com/kbandla/dpkt
- https://dpkt.readthedocs.org
