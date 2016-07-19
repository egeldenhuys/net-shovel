net-shovel
==========

## feature-pipe-tcpdump
We want to avoid writing files to the disk

### Aim
- Call tcpdump from net-shovel.py and pipe the output - DONE 2016-07-19, @9910207
- tcpdump should operate on its own thread - DONE 2016-07-19, @9910207
- Analyze the packets as they arrive

### Links
- http://stackoverflow.com/questions/17904231/handling-tcpdump-output-in-python
- http://unix.stackexchange.com/questions/15989/how-to-process-pipe-tcpdumps-output-in-realtime

### TODO
- Parse the tcpdump output
	- `19:58:20.784848 IP 10.0.1.3.38114 > 8.8.4.4.53: 3438+ A? clients4.google.com. (37)`
		- src: 10.0.1.3
		- dst: 8.8.4.4
		- len: 37 + 14?
	- `19:59:46.387671 IP 10.0.1.3.46502 > 216.58.210.46.443: Flags [P.], seq 1488:1526, ack 4327, win 318, options [nop,nop,TS val 5016233 ecr 2636918661], length 38`
		- src: 10.0.1.3
		- dst: 215.58.210.46
		- len: 38 + 14?

----

net-shovel is currently under active development and a fully functional version is not yet available. The requirements will change as the project develops.

See the [develop](https://github.com/egeldenhuys/net-shovel/tree/develop) branch and other [branches](https://github.com/egeldenhuys/net-shovel/branches) for the current state of the project.

## Problem
A machine on the network is consuming all the Internet bandwidth.

## Aim
View which machine is consuming all the bandwidth by collection statistics on Internet traffic passing through the machine running net-shovel.

### Requirements for statistics
- List `local | remote | down | up`
- View top local down and up
- List connections for a certain IP
- View totals for a certain IP
- Sort down, up for a certain list
- View stats by minute, hour, day, week, month

## Development Environment

- Linux Mint 18

### Dependencies
- Python 2.7.11+
	- python-pip
		- dpkt
		- setuptools
		- IPy
		- dnspython
- tcpdump
