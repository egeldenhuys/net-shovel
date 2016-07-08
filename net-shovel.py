"""net-shovel

Description:
    This program will analyse .pcap files in the ./tcpdump/ directory
    and print the total summary and the partial summary when a new
    .pcap file is detected.

Known Bugs:
    Sometimes attempts to analyze a pcap file before it has been completely
    written by tcpdump. See getDirSummary()

Outputs to stdout:
    local | remote | down | up | debug...

Author:
    Evert Geldenhuys (egeldenuys)
"""
import socket
import os
import time
import datetime
import shutil

import dpkt
from IPy import IP

def main():


def getBytes(connectionList):
    """Get the total bytes transfered in the given ConnectionList dict format

    Args:
        connectionList: The special format connectionList dict
    Returns:
        total down, total up, total combined
    Example:
        connections = getFileSummary(filePath)
        down, up, total = getBytes(connections)
    """

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
    """Merge two connection dicts. Copies new keys to dst and increments
    values for existing keys

    Args:
        src: Source connections dict
        dst: Destination connections dict
    Notes:
        The dst dict should be the larger dict
    Returns:
        A new connections dict containing the combined keys and values
    """

    # TODO: How efficient is this?
    result = dst.copy()

    for key in src.keys():
        if (result.has_key(key)):
            result[key] = result[key] + src[key]
        else:
            result[key] = src[key]

    return result

def getDirSummary(directory, consume=False):
    """Get the connection summary for all .pcap files in given directory

    Args:
        directory: The directory to search for .pcap fileSummary
        consume  : If True, will move the processed .pcap file to
                    directory/'processed'
    Returns:
        A connections dict containing the combined summary of all .pcap fileSummary
        in 'directory'
    """

    fileCounter = 1
    totalFiles = -1

    totalSummary = {}
    fileSummary = {}

    try:
        os.mkdir(directory + 'processed/')
    except OSError:
        fileCounter = 1

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
                    # TODO: Moving files for debugging purposes. Delete when done.
                    os.rename(directory + fileName, directory + 'processed/' + fileName)
                    # os.remove(directory + fileName)

            totalSummary = mergeDicts(fileSummary, totalSummary)
            fileSummary = {}

    return totalSummary


def getFileSummary(filePath):
    """Get the connection summary from the given .pcap file

    Args:
        filePath: The path of the .pcap format file
    Returns:
        A special format dict:
            Key: local:remote:direction
                local       - local IP string
                remote      - remote IP string
                direction   - Direction of bytes transfered. ('d'/'u')
            Example:
                192.168.1.1:8.8.8.8:d
            Value: bytes transfered in 'direction' between the two IPs
    """

    connectionList = {}

    f = open(filePath, 'rb')

    pcap = dpkt.pcap.Reader(f)

    try:
        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            if (eth.type != dpkt.ethernet.ETH_TYPE_IP):
        		continue

            ip = eth.data
            try:
                src = ip_to_str(ip.src)
            except AttributeError:
                print('[EXCEPTION] AtributeError')
                print('Packet Timestamp: ' + str(datetime.datetime.utcfromtimestamp(ts)))
                print('filePath = ' + filePath)
                break

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

    except dpkt.dpkt.NeedData:
        print('[EXCEPTION] NeedData')
        print('Packet Timestamp: ' + str(datetime.datetime.utcfromtimestamp(ts)))
        print('filePath = ' + filePath)

    f.close()
    return connectionList

def printConnectionList(connectionList):
    """Print the connection summary from the given connections dict

    Args:
        connectionList - The special format connections dict to print
    Prints:
        local remote download upload | key1 = val1 | key2 = val2
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
        else:
            up = connectionsTmp[key]

            directionOther = 'd'
            keyOther = '{0}:{1}:{2}'.format(local, remote, directionOther)

            if (connectionsTmp.has_key(keyOther)):
                down = connectionsTmp[keyOther]

        # Debug. Show keys and values that make up the printed summary
        transferA = ''
        transferB = ''

        if (connectionsTmp.has_key(key) and connectionsTmp[key] != -2):
            transferA = '{0} = {1}'.format(key, connectionsTmp[key])
        if (connectionsTmp.has_key(keyOther) and connectionsTmp[keyOther] != -2):
            transferB = '{0} = {1}'.format(keyOther, connectionsTmp[keyOther])

        transferParts = '{0:<40} | {1}'.format(transferA, transferB)

        # Mark the key as processed
        connectionsTmp[keyOther] = -2

        print('{0:<16} {1:<16} {2:<10} {3:<10} | {4}'.format(local, remote, down, up, transferParts))

def ip_to_str(address):
    """Print out an IP address given a string

    Args:
        address (inet struct): inet network address
    Returns:
        str: Printable/readable IP address
    """

    result = socket.inet_ntop(socket.AF_INET, address)
    return result

def mac_addr(address):
    """Convert a MAC address to a readable/printable string

       Args:
           address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
       Returns:
           str: Printable/readable MAC address
    """
    return ':'.join('%02x' % ord(b) for b in address)

main()
