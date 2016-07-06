net-shovel
==========

Dig up statistics on your network traffic!

----
## Branch: feature-session-summary
- Capture every 10 seconds using tcpdump
- When a 10 second capture file is finished analyse it
- Print connection summary to stdout
  - Total
  - Current analysis
- Format: `Local | Remote | Down | Up`

### TODO
Fix:
```
File "net-shovel.py", line 210, in <module>
  main()
File "net-shovel.py", line 34, in main
  dirSummary = getDirSummary(directory, True)
File "net-shovel.py", line 96, in getDirSummary
  fileSummary = getFileSummary(directory + fileName)
File "net-shovel.py", line 113, in getFileSummary
  for ts, buf in pcap:
File "/home/john-bool/.local/lib/python2.7/site-packages/dpkt/pcap.py", line 186, in __iter__
  hdr = self.__ph(buf)
File "/home/john-bool/.local/lib/python2.7/site-packages/dpkt/dpkt.py", line 90, in __init__
  raise NeedData
dpkt.dpkt.NeedData
```

### Development Environment

- Linux Mint 18

#### Dependencies
- Python 2.7.11+
	- python-pip
		- dpkt
		- setuptools
		- IPy
		- dnspython
- tcpdump 4.7.4
- libpcap 1.7.4
- OpenSSL 1.0.2g-fips  1 Mar 2016
