net-shovel
==========

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
- Python 2.7.11
	- python-pip
		- setuptools
		- IPy
- tcpdump
