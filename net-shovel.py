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
import time
import subprocess
from IPy import IP

def main():
    otherTotal = 0

    conList = {}
    refresh = time.time()

    p = subprocess.Popen(('sudo', 'tcpdump', '-ieth0', '-s96', '-l', '-n', '-e'), stdout=subprocess.PIPE)
    for row in iter(p.stdout.readline, b''):
        rawData = row.rstrip()
        print(rawData)

        splitData = rawData.split(' ')

        length = 0
        for index in range(len(splitData)):
            if (splitData[index] == 'length'):
                length = int(splitData[index + 1].strip(':'))
                break

        # packetType = splitData[1]
        # if (packetType != 'IP'):
        #     otherTotal += size
        #    continue

        srcAndPort = splitData[1]
        dstAndPort = splitData[3]

        #src = getIpOnly(srcAndPort)
        #dst = getIpOnly(dstAndPort)

        src = '192.168.1.1'
        dst = '200.1.1.1'

        conList = addToConnectionList(src, dst, length, conList)

        #if time.time() - refresh > 1:
        refresh = time.time()
        print('--------------------------------------')
        # printConnectionList(conList)

        down, up, total = getBytes(conList)
        print('Bytes: ')
        print('Down  : ' + str(down))
        print('Up    : ' + str(up))
        print('Total : ' + str(total + otherTotal))

def getIpOnly(ipAndPort):
    """Gets the IP from a IP.PORT formatted string

    Args:
        ipAndPort: A string of the format IP.PORT (123.123.123.80)
    Returns:
        A string containing only the IP
    """

    tmpSrc = ipAndPort.split('.')
    src = tmpSrc[0] + '.' + tmpSrc[1] + '.' + tmpSrc[2] + '.' + tmpSrc[3]
    src = src.strip(':')

    return src

def addToConnectionList(src, dst, size, connectionList):
    """Add the given connection to the Connection List

    Args:
        src: The source  IP address string
        dst: The destination IP address string
        size: The size of the packet (inluding the 14 byte link header). TODO: Confirm this!
        connectionList: The special formatted dict containing the connections
    dict Key Format:
        Key: local:remote:direction
            local       - local IP string
            remote      - remote IP string
            direction   - Direction of bytes transfered. ('d'/'u')
        Example:
            192.168.1.1:8.8.8.8:d
        Value: bytes transfered in 'direction' between the two IPs
    Returns:
        Special key format dict containing all the connections
    """

    tmpSrcIP = IP(src)

    direction = 'z'
    if (tmpSrcIP.iptype() == 'PRIVATE'):
        direction = 'u'
        directionSwap = 'd'
        local = src
        remote = dst
    else:
        direction = 'd'
        directionSwap = 'u'
        remote = src
        local = dst

    key = '{0}:{1}:{2}'.format(local, remote, direction)

    # Somtimes they are both PRIVATE IPs so we check if we have seen one of
    # them before in the connection list. Otherwise direction is always upload
    keySwapped_compare = '{0}:{1}:{2}'.format(remote, local, direction)
    keySwapped_insert = '{0}:{1}:{2}'.format(remote, local, directionSwap)

    # Add connection to the dict
    if (connectionList.has_key(key)):
        connectionList[key] = connectionList[key] + size
    else:
        if connectionList.has_key(keySwapped_compare):
            if connectionList.has_key(keySwapped_insert):
                connectionList[keySwapped_insert] = size + connectionList[keySwapped_insert]
            else:
                connectionList[keySwapped_insert] = size
        else:
            connectionList[key] = size

    return connectionList


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

    down = 0
    up = 0

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
