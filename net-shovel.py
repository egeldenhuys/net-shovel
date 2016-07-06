"""
net-shovel
==========

session-summary:
- Capture every 10 seconds using tcpdump
- When a 10 second capture file is finished analyse it using dpkt
- Print connection summary to stdout
- Local | Remote | Down | Up

"""
import dpkt
import socket
from IPy import IP
import os
import time

def main():
    directory = '/home/john-bool/github/net-shovel/tcpdump/'

    print('Total Summary:')
    totalSummary = getDirSummary(directory, True)
    printConnectionList(totalSummary)

    fileCountOld = len(os.listdir(directory))
    fileCountNew = fileCountOld

    while (True):

        if (fileCountNew > fileCountOld):
            time.sleep(1)
            
            dirSummary = {}
            dirSummary = getDirSummary(directory, True)
            totalSummary = mergeDicts(dirSummary, totalSummary)

            print('Total Summary:')
            printConnectionList(totalSummary)

            print('Directory Summary:')
            printConnectionList(dirSummary)

            fileCountOld = len(os.listdir(directory))

        fileCountNew = len(os.listdir(directory))
        time.sleep(1)

def getBytes(connectionList):
    down = -1
    up = -1

    for key in connectionList.keys():
        local, remote, direction = key.split(':')

        if (direction == "d"):
            down = down + connectionList[key]
        elif (direction == "u"):
            up = up + connectionList[key]

    total = down + up

    return down, up, total

def mergeDicts(src, dst):

    result = dst.copy()

    for key in src.keys():
        if (result.has_key(key)):
            result[key] = result[key] + src[key]
        else:
            result[key] = src[key]

    return result

def getDirSummary(directory, consume=False):
    fileCounter = 1
    totalFiles = -1

    totalSummary = {}
    fileSummary = {}

    totalFiles = len(os.listdir(directory))

    for fileName in os.listdir(directory):
        filenameTmp, file_extension = os.path.splitext(fileName)

        if (file_extension == '.pcap'):

            statinfo = os.stat(directory + fileName)

            if (statinfo.st_size > 0):
                print('[{0} / {1}] Analyzing {2}...'.format(fileCounter, totalFiles, directory + fileName))
                fileCounter += 1

                fileSummary = getFileSummary(directory + fileName)

                if (consume == True):
                    os.remove(directory + fileName)

            totalSummary = mergeDicts(fileSummary, totalSummary)
            fileSummary = {}

    return totalSummary

def getFileSummary(filePath):
    connectionList = {}

    f = open(filePath, 'r')

    pcap = dpkt.pcap.Reader(f)

    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        if (eth.type != dpkt.ethernet.ETH_TYPE_IP):
    		continue

        ip = eth.data

        src = ip_to_str(ip.src)
        dst = ip_to_str(ip.dst)
        size = ip.len + 14

        tmpIP = IP(src)

        # Determine packet direction
        direction = 'z'
        if (tmpIP.iptype() == 'PRIVATE'):
            direction = 'u'
            local = src
            remote = dst
        else:
            direction = 'd'
            remote = src
            local = dst

        key = '{0}:{1}:{2}'.format(local, remote, direction)

        # Add connection to the dict
        if (connectionList.has_key(key)):
            connectionList[key] = connectionList[key] + size
        else:
            connectionList[key] = size

    f.close()
    return connectionList

def printConnectionList(connectionList):
    """
    Format:
        local | remote | down | up
    """

    connectionsTmp = connectionList.copy()

    for key in connectionsTmp.keys():

        # -2 means we already checked this key
        if (connectionsTmp[key] == -2):
            continue

        local, remote, direction = key.split(':')

        down = 0
        up = 0

        if (direction == 'd'):
            down = connectionsTmp[key]

            directionOther = 'u'
            keyOther = '{0}:{1}:{2}'.format(local, remote, directionOther)

            if (connectionsTmp.has_key(keyOther)):
                up = connectionsTmp[keyOther]
                connectionsTmp[keyOther] = -2
        else:
            up = connectionsTmp[key]

            directionOther = 'd'
            keyOther = '{0}:{1}:{2}'.format(local, remote, directionOther)

            if (connectionsTmp.has_key(keyOther)):
                down = connectionsTmp[keyOther]
                connectionsTmp[keyOther] = -2

        a = ''
        b = ''

        if (connectionsTmp.has_key(key)):
            a = '{0} = {1}'.format(key, connectionsTmp[key])
        if (connectionsTmp.has_key(keyOther)):
            b = '{0} = {1}'.format(keyOther, connectionsTmp[keyOther])

        c = a + ' | ' + b

        print('{0:<16} {1:<16} {2:<10} {3:<10} | {4}'.format(local, remote, down, up, c))

def ip_to_str(address):
    """Print out an IP address given a string

    Args:
        address (inet struct): inet network address
    Returns:
        str: Printable/readable IP address
    """

    result = socket.inet_ntop(socket.AF_INET, address)
    return result

main()
