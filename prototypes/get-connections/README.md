## Aim
- Run on local machine, no forwarding required
- Capture packets to pcap file using tcpdump
- Use tcptrace for analysis of the pcap file
- Generate list of `connection number | local:port | host:port`

## Usage
- `./main-eth0.sh`

## Output
- `id | src:port | dst:port | bytes sent | bytes received`

```
  1: 192.168.1.154:41310 - 91.235.140.145:80 (a2b)    10>   10<
  2: 192.168.1.154:38477 - 72.14.249.132:443 (c2d)    24>   34<
  3: 162.125.17.3:443 - 192.168.1.154:56279 (e2f)      4>    2<
  4: 192.30.253.124:443 - 192.168.1.154:34562 (g2h)    2>    1<

```

## Links
- [tcpdump](http://linux.die.net/man/8/tcpdump)
- [tcptrace](http://linux.die.net/man/1/tcptrace)
