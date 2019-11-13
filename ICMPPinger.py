import os
import sys
import struct
import time
import select
import socket

ICMP_ECHO_REQUEST_RATE = 8

# This function returns the time delay between sending and receiving a single ping.
def perform_one_ping(destination_add, timeout):
    icmp_ping = socket.getprotobyname("icmp")
    mySocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp_ping)
    myID = os.getpid() & 0xFFFF
    sendsingle_icmpping(mySocket, destination_add, myID)
    delay = receivesingle_icmpping(mySocket, myID, timeout, destination_add)
    mySocket.close()
    return delay

# This function receives a single ping.
def receivesingle_icmpping(mySocket, ID, timeout, destAddr):
    global roundTrip_min, roundTrip_max, roundTrip_sum, roundTrip_cnt
    timeRemain = timeout
    while 1:
        startedSelect = time.time()
        arr = select.select([mySocket], [], [], timeRemain)
        howLongInSelect = (time.time() - startedSelect)
        if arr[0] == []:
            return "Request timed out."
        timeReceived = time.time()
        received_Packet, addr = mySocket.recvfrom(1024)
        type, code, checksum, id, seq = struct.unpack('bbHHh', received_Packet[20:28])
        if type != 0:
            return 'expected type=0, but got {}'.format(type)
        if code != 0:
            return 'expected code=0, but got {}'.format(code)
        if ID != id:
            return 'expected id={}, but got {}'.format(ID, id)
        trans_time, = struct.unpack('d', received_Packet[28:])
        roundTrip = (timeReceived - trans_time) * 1000
        roundTrip_cnt += 1
        roundTrip_sum += roundTrip
        roundTrip_min = min(roundTrip_min, roundTrip)
        roundTrip_max = max(roundTrip_max, roundTrip)
        ip_pkt_head = struct.unpack('!BBHHHBBH4s4s', received_Packet[:20])
        ttl = ip_pkt_head[5]
        saddr = socket.inet_ntoa(ip_pkt_head[8])
        length = len(received_Packet) - 20
        return '{} bytes from {}: icmp_seq={} ttl={} time={:.3f} ms'.format(length, saddr, seq, ttl, roundTrip)
        timeRemain = timeRemain - howLongInSelect
        if timeRemain <= 0:
            return "Request timed out."


# The checksum function used to evaluate the checksum.
# The answer of the checksum calculation is returned.
def checksum(str):
    count_sum = 0
    countTo = (len(str) / 2) * 2
    count = 0
    while count < countTo:
        thisVal = ord(str[count + 1]) * 256 + ord(str[count])
        count_sum = count_sum + thisVal
        count_sum = count_sum & 0xffffffffL
        count = count + 2
    if countTo < len(str):
        count_sum = count_sum + ord(str[len(str) - 1])
        count_sum = count_sum & 0xffffffffL
    count_sum = (count_sum >> 16) + (count_sum & 0xffff)
    count_sum = count_sum + (count_sum >> 16)
    calc = ~count_sum
    calc = calc & 0xffff
    calc = calc >> 8 | (calc << 8 & 0xff00)
    return calc


# This function sends a single ping.
def sendsingle_icmpping(mySocket, destination_add, ID):
    count_checksum = 0
    pkt_head = struct.pack("bbHHh", ICMP_ECHO_REQUEST_RATE, 0, count_checksum, ID, 1)
    data = struct.pack("d", time.time())
    count_checksum = checksum(pkt_head + data)
    if sys.platform == 'darwin':
        count_checksum = socket.htons(count_checksum) & 0xffff
    else:
        count_checksum = socket.htons(count_checksum)
    pkt_head = struct.pack("bbHHh", ICMP_ECHO_REQUEST_RATE, 0, count_checksum, ID, 1)
    packet = pkt_head + data
    mySocket.sendto(packet, (destination_add, 1))




# This function displays the ping statistics.
def icmp_ping(host, timeout=1):
    global roundTrip_min, roundTrip_max, roundTrip_sum, roundTrip_cnt
    roundTrip_min = float('+inf')
    roundTrip_max = float('-inf')
    roundTrip_sum = 0
    roundTrip_cnt = 0
    count = 0
    dest = socket.gethostbyname(host)
    print "Pinging " + dest + " using Python:"
    try:
        while True:
            count += 1
            print perform_one_ping(dest, timeout)
            time.sleep(1)
    except KeyboardInterrupt:
        if count != 0:
            print '--- {} ping statistics ---'.format(host)
            print '{} packets transmitted, {} packets received, {:.1f}% packet loss'.format(count, roundTrip_cnt,
                                                                                            100.0 - roundTrip_cnt * 100.0 / count)
            if roundTrip_cnt != 0:
                print 'round-trip min/avg/max {:.3f}/{:.3f}/{:.3f} ms'.format(roundTrip_min, roundTrip_sum / roundTrip_cnt, roundTrip_max)


icmp_ping("www.google.com")