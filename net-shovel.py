import dpkt
import socket
from IPy import IP
import sys
from dns import resolver,reversename
import os
import time

def main():
    directory = sys.argv[1]

    totalSummary = getDirSummary(directory)
    printSummary(totalSummary, False, 'total.csv')

    fileCountOld = len(os.listdir(directory))
    fileCountNew = fileCountOld + 1

    totalSummary = { }

    while (True):

        if (fileCountNew > fileCountOld):
            dirSummary = getDirSummary(directory)
            totalSummary = mergeDicts(dirSummary, totalSummary)

            print('TOTAL')
            for key in totalSummary:
                print('{0} = {1}'.format(key, totalSummary[key]))

            print('Total Summary:')
            printSummary(totalSummary, False, 'total.csv')

            print('Directory Summary:')
            printSummary(dirSummary, False, 'directory.csv')

        fileCountNew = len(os.listdir(directory))
        time.sleep(1)

def getDirSummary(directory):
    current = 1
    total = -1

    totalSummary = { }
    fileSummary = { }

    total = len(os.listdir(directory))

    for fileName in os.listdir(directory):
        filenameTmp, file_extension = os.path.splitext(fileName)

        if (file_extension == '.pcap'):

            print('[{0} / {1}] Analyzing {2}...'.format(current, total, directory + fileName))
            current += 1

            statinfo = os.stat(directory + fileName)

            if (statinfo.st_size > 0):
                fileSummary = getConnections(directory + fileName)
                os.remove(directory + fileName)

            totalSummary = mergeDicts(fileSummary, totalSummary)
            fileSummary.clear()

    return totalSummary

def mergeDicts(src, dst):

    result = dst.copy()

    for key in src.keys():
        if (result.has_key(key)):
            result[key] += src[key]
        else:
            result[key] = src[key]

    print('Source:')
    for a in src.keys():
        print(a)

    print('Dest:')
    for b in dst.keys():
        print(b)

    print('Result:')
    for c in result.keys():
        print('{0} = {1}'.format(c, result[c]))

    return result

def ip_to_str(address):
    """Print out an IP address given a string

    Args:
        address (inet struct): inet network address
    Returns:
        str: Printable/readable IP address
    """

    result = socket.inet_ntop(socket.AF_INET, address)
    return result

def getConnections(file):
    """Get the connections from a .pcap file

    Dict Format:
        local:remote:direction = bytes
    Args:
        file - the .pcap file
    Returns:
        dict with key format local:remote:direction = bytes
    Direction:
        d - download. local <- remote
        u - upload. local -> remote
    """
    connections = { }
    f = open(file)
    pcap = dpkt.pcap.Reader(f)

    for timestamp, buf in pcap:
    	eth = dpkt.ethernet.Ethernet(buf)
        if (eth.type != dpkt.ethernet.ETH_TYPE_IP):
    		continue

    	ip = eth.data

        src = ip_to_str(ip.src)
        dst = ip_to_str(ip.dst)
        size = ip.len + 14
        direction = 'z'

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

    connectionsTmp = connections.copy()

    out = open(dumpPath, 'w')
    out.write('local,remote,download,upload\n')

    for con in connectionsTmp.keys():

        if (connectionsTmp[con] == -2):
            continue

        loc, rem, dire = con.split(':')

        down = 0
        up = 0

        if (dire == 'd'):
            down = connectionsTmp[con]

            dire2 = 'u'
            con2 = '{0}:{1}:{2}'.format(loc, rem, dire2)

            if (connectionsTmp.has_key(con2)):
                up = connectionsTmp[con2]
                connectionsTmp[con2] = -2
        else:
            up = connectionsTmp[con]

            dire2 = 'd'
            con2 = '{0}:{1}:{2}'.format(loc, rem, dire2)

            if (connectionsTmp.has_key(con2)):
                down = connectionsTmp[con2]
                connectionsTmp[con2] -2

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

main()
