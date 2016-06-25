## Aim
- Parse pcap file using python and dpkt library
- Get source and destination IPs and total bytes transfered

## Method
- `sudo apt-get install python-pip`
- `sudo pip install dpkt`
- Capture using capture-1-min-wlan0.sh
- Place capture file in same dir named `capture-1-min.pcap`
- `python get-connections.py` to parse using dpkt

## Usage
- `./main-wlan0.sh`

## Output

- `Source | Destination | Total bytes transfered`

```
192.30.253.124	192.168.1.154	163
192.168.1.6	192.168.1.255	2300
192.168.1.154	192.168.1.255	346
72.14.249.132	192.168.1.154	4062
192.168.1.6	224.0.0.252	1242
192.168.1.154	162.125.17.3	485
192.168.1.154	255.255.255.255	346
192.168.1.154	54.243.65.90	66
192.168.1.154	91.235.140.145	2390
192.168.1.1	192.168.1.154	296
54.243.65.90	192.168.1.154	132
192.168.1.154	192.30.253.124	101
162.125.17.3	192.168.1.154	466
999.999.999.999	999.999.999.999	0
192.168.1.154	192.168.1.1	79
91.235.140.145	192.168.1.154	1330
192.168.1.154	72.14.249.132	5284
Total Bytes: 19088
```

## Remarks
- Confirmed output with Wireshark. Matches!

## Links
- https://jon.oberheide.org/blog/2008/10/15/dpkt-tutorial-2-parsing-a-pcap-file/
- https://github.com/kbandla/dpkt
- https://dpkt.readthedocs.org
