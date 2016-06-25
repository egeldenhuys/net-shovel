import dpkt
import socket

def ip_to_str(address):
    """Print out an IP address given a string

    Args:
        address (inet struct): inet network address
    Returns:
        str: Printable/readable IP address
    """
    return socket.inet_ntop(socket.AF_INET, address)

connection_list = {'999.999.999.999\t999.999.999.999': (0,0)}
total = 0

f = open('capture-1-min.pcap')
pcap = dpkt.pcap.Reader(f)

for timestamp, buf in pcap:
	eth = dpkt.ethernet.Ethernet(buf)

	# Make sure the Ethernet frame contains an IP packet
    # EtherType (IP, ARP, PPPoE, IP6... see http://en.wikipedia.org/wiki/EtherType)
	
	if eth.type != dpkt.ethernet.ETH_TYPE_IP:
		# print('Non IP Packet type not supported %s\n' % eth.data.__class__.__name__)
		continue
	
	ip = eth.data

	key = '{0}\t{1}'.format(ip_to_str(ip.src), ip_to_str(ip.dst))
	bytes = ip.len + 14

	if (key in connection_list):
		connection_list[key] = (connection_list[key] + bytes)
	else:
		connection_list[key] = bytes

	total += bytes

	# print('{0}\t{1}\t{2}'.format(ip_to_str(ip.src), ip_to_str(ip.dst), len(ip.data)))

for con in connection_list.keys():
	print('{0}\t{1}'.format(con, connection_list[con]))

print('Total Bytes: {0}'.format(total))
