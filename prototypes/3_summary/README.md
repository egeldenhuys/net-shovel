## Aim
- Produce the following summary:
`local ip | remote ip | download | upload`

## Procedure
- Use tcpdump to capture to .pcap file
    - Start a new capture file every 10 seconds
- Every time a new file is started analyze it using dpkt

## Dependencies
- tcpdump
- dpkt
- IPy

## Links
- https://clutterbox.de/2010/08/tcpdump-with-rotating-capture-files/
