import dpkt
import socket
from IPy import IP
import os
import time
import datetime
import shutil

def main():
    directory = '/home/john-bool/github/net-shovel/tcpdump/'

    print('Total Summary:')
    totalSummary = getDirSummary(directory, True)
    printConnectionList(totalSummary)

    fileCountOld = len(os.listdir(directory))
    fileCountNew = fileCountOld

    while (True):

        if (fileCountNew > fileCountOld):

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
                    os.rename(directory + fileName, directory + '/processed/' + fileName)
                    #os.remove(directory + fileName)

            totalSummary = mergeDicts(fileSummary, totalSummary)
            fileSummary = {}

    return totalSummary


def getFileSummary(filePath):
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
