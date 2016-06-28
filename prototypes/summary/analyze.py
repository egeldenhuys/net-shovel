import dpkt
import socket
from IPy import IP
import sys
from dns import resolver,reversename
import os
import time

t_mergeDicts = 0
t_getConnections = 0
t_printSummary = 0
t_getDirSummary = 0
t_ip_to_str = 0

t_d1 = 0
t_d2 = 0
t_d3 = 0

def main():
    cons = getDirSummary(sys.argv[1])
    printSummary(cons, False, sys.argv[2])

    #print('getConnections: ' + str(t_getConnections))
    #print('1:' + str(t_d1))
    #print('2:' + str(t_d2))
    #print('3:' + str(t_d3))

def getDirSummary(directory):
    current = 1
    total = -1

    sys.stdout.write('getDirSummary: ')

    start = time.clock()

    roller = { }
    fileSummary = { }

    total = len(os.listdir(directory))

    for fileName in os.listdir(directory):
        print('[{0} / {1}] Analyzing {2}...'.format(current, total, directory + fileName))
        current += 1

        statinfo = os.stat(directory + fileName)

        if (statinfo.st_size > 0):
            fileSummary = getConnections(directory + fileName)

        roller = mergeDicts(fileSummary, roller)
        fileSummary.clear()

    end = time.clock()
    diff = (end - start) * 1000
    global t_getDirSummary
    t_getDirSummary += diff
    # print('{0:f} {1}'.format(diff, 'ms'))

    return roller

def mergeDicts(src, dst):

    # sys.stdout.write('mergeDicts: ')
    start = time.clock()

    result = dst.copy()

    for key in src.keys():
        if (result.has_key(key)):
            result[key] += src[key]
        else:
            result[key] = src[key]

    end = time.clock()
    diff = (end - start) * 1000
    global t_mergeDicts
    t_mergeDicts += diff
    # print('{0:f} {1}'.format(diff, 'ms'))

    return result

def ip_to_str(address):
    """Print out an IP address given a string

    Args:
        address (inet struct): inet network address
    Returns:
        str: Printable/readable IP address
    """

    # sys.stdout.write('ip_to_str: ')
    start = time.clock()

    result = socket.inet_ntop(socket.AF_INET, address)

    end = time.clock()
    diff = (end - start) * 1000
    global t_ip_to_str
    t_ip_to_str += diff
    # print('{0:f} {1}'.format(diff, 'ms'))

    return result

def getConnections(file):
    """Get the connections from a .pcap file

    Format:
        local | remote | direction || bytes
    Args:
        file - the .pcap file
    Returns:
        dict with key format local:remote:direction = bytes
    Direction:
        d - download. local <- remote
        u - upload. local -> remote
    """

    # sys.stdout.write('getConnections: ')
    start = time.clock()

    #connections = {'999.999.999.999:0:z': -2}
    s3 = time.clock()

    connections = { }
    f = open(file)
    pcap = dpkt.pcap.Reader(f)

    e3 = time.clock()
    d3 = (e3 - s3) * 1000
    global t_d3
    t_d3 += d3

    for timestamp, buf in pcap:
        s1 = time.clock()

    	eth = dpkt.ethernet.Ethernet(buf)

        if (eth.type != dpkt.ethernet.ETH_TYPE_IP):
    		continue

    	ip = eth.data

        src = ip_to_str(ip.src)
        dst = ip_to_str(ip.dst)
        size = ip.len + 14
        direction = 'z'

        e1 = time.clock()
        d1 = (e1 - s1) * 1000
        global t_d1
        t_d1 += d1

        s2 = time.clock()

        tmpIP = IP(ip_to_str(ip.src))
        if (tmpIP.iptype() == 'PRIVATE'):
            direction = 'u'
            local = src
            remote = dst
        else:
            direction = 'd'
            remote = src
            local = dst

        key = '{0}:{1}:{2}'.format(local, remote, direction)

        if (connections.has_key(key)):
            connections[key] = connections[key] + size
        else:
            connections[key] = size

        e2 = time.clock()
        d2 = (e2 - s2) * 1000
        global t_d2
        t_d2 += d2

    end = time.clock()
    diff = (end - start) * 1000
    global t_getConnections
    t_getConnections += diff

    # print('{0:f} {1}'.format(diff, 'ms'))

    f.close()
    return connections

def addUnits(size):

    val = ''

    if (size > 1024*1024):
        size = float(size / (1024*1024))
        val = '{0} {1}'.format(size, 'MiB')
    elif (size > 1024):
        size = float(size / 1024)
        val = '{0} {1}'.format(size, 'KiB')

    else:
        val = size

    return val

def printSummary(connections, resolve, dumpPath):
    """
    Format:
        local | remote | down | up
    """

    sys.stdout.write('printSummary: ')
    start = time.clock()

    out = open(dumpPath, 'w')
    out.write('local,remote,download,upload\n')

    for con in connections.keys():

        if (connections[con] == -2):
            continue

        loc, rem, dire = con.split(':')

        down = 0
        up = 0

        if (dire == 'd'):
            down = connections[con]

            dire2 = 'u'
            con2 = '{0}:{1}:{2}'.format(loc, rem, dire2)

            if (connections.has_key(con2)):
                up = connections[con2]
                connections[con2] = -2
        else:
            up = connections[con]

            dire2 = 'd'
            con2 = '{0}:{1}:{2}'.format(loc, rem, dire2)

            if (connections.has_key(con2)):
                down = connections[con2]
                connections[con2] -2

            if (resolve == True):
                try:
                    addr=reversename.from_address(rem)
                    remStr = str(resolver.query(addr,"PTR")[0])
                    remStr = remStr[0:len(remStr) - 1]
                except (resolver.NXDOMAIN, resolver.NoNameservers, resolver.NoAnswer, \
                resolver.Timeout):
                    remStr = rem

                print('{0:<12} {1:<16} {2:<60} {3:<10} {4}'.format(loc, rem, remStr, \
                addUnits(down), addUnits(up)))

                out.write('{0},{1},{2},{3},{4}\n'.format(loc, rem, remStr, down, up))

            else:
                print('{0:<12} {1:<16} {2:<10} {3}'.format(loc, rem, \
                addUnits(down), addUnits(up)))

                out.write('{0},{1},{2},{3}\n'.format(loc, rem, down, up))

    out.close()

    end = time.clock()
    diff = (end - start) * 1000
    global t_printSummary
    t_printSummary += diff
    #print('{0:f} {1}'.format(diff, 'ms'))

main()
