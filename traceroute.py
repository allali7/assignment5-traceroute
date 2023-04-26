from socket import *
import os
import sys
import struct
import time
import select
import binascii
import pandas as pd

ICMP_ECHO_REQUEST = 8
MAX_HOPS = 60
TIMEOUT = 2.0
TRIES = 1


# The packet that we shall send to each router along the path is the ICMP echo
# request packet, which is exactly what we had used in the ICMP ping exercise.
# We shall use the same packet that we built in the Ping exercise

def checksum(string):
    # In this function we make the checksum of our packet
    csum = 0
    countTo = (len(string) // 2) * 2
    count = 0

    while count < countTo:
        thisVal = (string[count + 1]) * 256 + (string[count])
        csum += thisVal
        csum &= 0xffffffff
        count += 2

    if countTo < len(string):
        csum += (string[len(string) - 1])
        csum &= 0xffffffff

    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer


def build_packet():
    # Fill in start
    # In the sendOnePing() method of the ICMP Ping exercise ,firstly the header of our
    # packet to be sent was made, secondly the checksum was appended to the header and
    # then finally the complete packet was sent to the destination.

    # Make the header in a similar way to the ping exercise.
    # Append checksum to the header.
    myChecksum = 0
    myID = os.getpid() & 0xFFFF
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, myID, 1)
    data = struct.pack("d", time.time())
    myChecksum = checksum(header + data)
    # Get the right checksum, and put it in the header
    if sys.platform == 'darwin':
        myChecksum = htons(myChecksum) & 0xffff  # Convert 16-bit integers to network byte order on macOS
    else:
        myChecksum = htons(myChecksum)  # Convert 16-bit integers from host to network  byte order
        # Convert 16-bit integers to network byte order on other platforms

    # Repack the header with the correct checksum
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, myID, 1)
    # Don’t send the packet yet , just return the final packet in this function.
    # Fill in end

    # So the function ending should look like this

    packet = header + data
    return packet


def get_route(hostname):
    timeLeft = TIMEOUT
    df = pd.DataFrame(columns=['Hop Count', 'Try', 'IP', 'Hostname', 'Response Code'])
    destAddr = gethostbyname(hostname)

    # a nested loop is used to send ICMP packets with incrementing
    # TTL values and record the responses.
    # This is done to trace the route to the destination.

    # outer loop iterates over TTL values from 1 to MAX_HOPS.
    # TTL is the maximum number of hops (routers) the packet
    # can pass through before being discarded.
    for ttl in range(1, MAX_HOPS):
        # This inner loop iterates over the number of tries
        # specified by the TRIES constant. If a response is not
        # received within the given TIMEOUT, the script will retry
        # sending the ICMP packet up to TRIES times.
        #for tries in range(TRIES):
        for tries in range(1, TRIES + 1):

            # Fill in start
            # Make a raw socket named mySocket

            # By creating a new socket for each TTL, the code ensures that each
            # socket is initialized with the correct TTL value for that particular iteration.
            # It can also help avoid potential issues or side effects caused by reusing the
            # same socket for multiple requests with different options.
            # However, an alternative approach is to reuse the same socket and update
            # the TTL value for each iteration by calling setsockopt() with the new TTL value.
            # This can be more efficient in terms of resource usage, as fewer sockets
            # are created and closed.

            # BUUUTTTT in this code we are creating a new socket inside the nested loops
            # for each combination of TTL value and try. This ensures a fresh socket is
            # used for each request.
            # The setsockopt() method is called immediately after creating the socket to
            # set the TTL value for the current iteration. This is necessary because the
            # TTL value changes with each iteration, and we want to make sure that the
            # correct TTL is set for the packet being sent.
            icmp = getprotobyname("icmp")  # Get the protocol number for ICMP
            mySocket = socket(AF_INET, SOCK_RAW, icmp)  # Create a raw socket for ICMP
            #myID = os.getpid() & 0xFFFF

            # Fill in end
            # By using mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', ttl)),
            # the code sets the TTL value for the IP packets sent using the mySocket
            # object. As the ttl value increases in the for ttl in range(1,MAX_HOPS):
            # loop, the ICMP packets will be able to traverse more hops (routers) before
            # being discarded. This is a crucial part of the traceroute process, as it
            # allows the program to discover each intermediate router in the path to the destination.

            # IPPROTO_IP: This constant represents the IP protocol level.
            # It is used to indicate that the option you're setting is related to the IP protocol.

            # IP_TTL: This constant represents the Time-To-Live (TTL) option for the IP protocol.
            # TTL is a value that determines the maximum number of routers (hops) a packe
            # t can traverse before being discarded. Each time a router processes the packet,
            # it decrements the TTL value by 1. When the TTL value reaches 0, the packet is
            # discarded, and the router sends an ICMP Time Exceeded message back to the sender.

            # struct.pack('I', ttl): This part of the code packs the TTL value (ttl) as
            # an unsigned integer ('I') using the struct module. The packed TTL value
            # will be passed as the option value for the IP_TTL option.
            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', ttl))
            mySocket.settimeout(TIMEOUT)  # if the socket doesn't receive any data within the
            # specified timeout period, it will raise a timeout exception.

            # sends the ICMP packet and waits for a response. If the socket times out, it will raise an exception
            try:
                d = build_packet()  # function to create an ICMP packet
                # the 0 is used as a placeholder for the port number. Since you are using ICMP,
                # which is a connectionless protocol and operates on the network layer, it
                # does not use port numbers like TCP or UDP, which operate on the transport layer.
                # When sending an ICMP packet using a raw socket, the operating system does
                # not expect a port number. However, the sendto() function requires a tuple
                # containing an IP address and a port number as the destination address.
                # By providing 0 as the port number, you satisfy the function's argument requirements
                # without actually specifying a meaningful port number, because ICMP doesn't use ports.
                mySocket.sendto(d, (hostname, 0))  # Sends the ICMP packet to the specified hostname

                t = time.time()  # record current time
                startedSelect = time.time()  # record current time in sep variable
                whatReady = select.select([mySocket], [], [],
                                          timeLeft)  # Waits for the socket to be ready for reading or until the timeLeft expires.
                ###testing mught need back#  timeLeft = timeLeft - (time.time() - startedSelect)

                # select.select function is used to monitor multiple sockets and wait for specific events,
                # such as data becoming available for reading or a socket becoming ready for writing.
                # It can be used to implement timeouts or to handle multiple connections simultaneously.
                # [mySocket]: This is a list of sockets to monitor for readability. In this case,
                # it contains just one socket, mySocket. The function will check if there is any data
                # available to read from this socket.
                # []: This is an empty list, which would normally contain sockets to monitor for writability.
                # Since we're not interested in monitoring any sockets for writability in this case, an empty list is
                # provided.
                # []: This is another empty list, which would normally contain sockets to monitor for exceptional
                # conditions. Again, we're not interested in monitoring any sockets for exceptional conditions, so
                # an empty list is provided.
                # timeLeft: This is the timeout value, specified in seconds. The select.select() function will wait
                # for the specified amount of time for any of the monitored events to occur. If the timeout expires
                # and no events occur, the function will return.
                # The select.select() function returns three lists: the sockets that are readable, the sockets that
                # are writable, and the sockets with exceptional conditions. In this case, since we're only interested
                # in monitoring mySocket for readability, the function will return a list containing mySocket if
                # there is data available to read, or an empty list if the timeout expires and no data is available.
                # The line whatReady = select.select([mySocket], [], [], timeLeft) assigns the returned value
                # (the list of sockets that are readable) to the variable whatReady. If whatReady[0] == [], it means
                # the timeout has expired, and no data is available to read from mySocket.
                #whatReady = select.select([mySocket], [], [],timeLeft)  # Waits for the socket to be ready for reading or until the timeLeft expires.
                howLongInSelect = (
                            time.time() - startedSelect)  # Calculates the time spent waiting for the socket to become ready

                # If no response is received within the given timeout, a "Timeout" entry is appended to the DataFrame.
                # checks if the select.select() function has timed out, meaning there is no data to read from the socket
                if whatReady[0] == []:  # Timeout of select.select
                    # Fill in start
                    # append response to your dataframe including hop #, try #, and "timeout" responses as required by the acceptance criteria
                    df = df.append({'Hop Count': ttl, 'Try': tries, 'IP': "Timeout", 'Hostname': "Timeout",
                                    'Response Code': "Timeout"}, ignore_index=True)
                    #(df)
                    # Fill in end

                # If the select.select() did not timeout, this line receives the packet and its source address.
                # The maximum packet size to be received is set to 1024 bytes.
                recvPacket, addr = mySocket.recvfrom(1024)  # addr is a tuple oof ip addr and socket
                timeReceived = time.time()  # packet recieved time
                timeLeft = timeLeft - howLongInSelect  # updates the timeLeft variable by subtracting the time spent in the select.select() function.
                #timeLeft = max(0, timeLeft)
                # If timeLeft is exhausted, the following block of code appends a new row to the df DataFrame,
                # similar to the first case when a timeout occurred.
                # difference between whatready and timeleft timouts. whatReady timeout checks whether the select.select()
                # function has timed out waiting for a response from the router.
                # timeLeft timeout checks whether the overall time for the process has exceeded the allowed TIMEOUT.
                if timeLeft <= 0:
                    # checks if there's no remaining time for the current loop iteration. If there's no time left,
                    # the program appends another row to the DataFrame with the 'Response Code' as 'Timeout'.

                    # Fill in start
                    # append response to your dataframe including hop #, try #, and "timeout" responses as required
                    # by the acceptance criteria
                    df = df.append({'Hop Count': ttl, 'Try': tries, 'IP': "Timeout", 'Hostname': "Timeout",
                                    'Response Code': "Timeout"}, ignore_index=True)
                    #print(df)
                    # Fill in end
            except Exception as e:
                #print(e)  # uncomment to view exceptions
                # continue statement ensures that the program does not terminate
                # due to the error. Instead, it will move on to the next try in the inner loop
                continue  # inner loop if timeout

            else:  # this executes if there is no exception - try else just means continue of no exception here
                # Fill in start
                # Fetch the icmp type from the IP packet

                icmp_header = recvPacket[20:28]  # Extract the ICMP header from the received packet
                types, icmp_code, icmp_checksum, icmp_id, icmp_seq = struct.unpack("bbHHh",
                                                                                   icmp_header)  # Unpack the ICMP header into its components

                # Fill in end
                try:  # try to fetch the hostname of the router that returned the packet - don't confuse with the hostname that you are tracing

                    # Fill in start
                    # srcIP= struct.unpack("!I", recvPacket[12:16])[0]
                    # srcIPstring = socket.inet_ntoa(struct.pack("!I", srcIP))

                    ###srcIP = recvPacket[12:16] #12-15 inclusive
                    # a function that takes an IPv4 address as a string and returns a tuple containing information about
                    # the host with that IP address. The function performs a reverse DNS lookup, which is a process of finding
                    # the domain name associated with a given IP address.
                    # host = gethostbyaddr(str(srcIPstring))
                    host = gethostbyaddr(str(addr[0]))
                    routerHostname = host[0]

                    # Fill in end
                except herror:  # if the router host does not provide a hostname use "hostname not returnable"
                    # Fill in start
                    routerHostname = "hostname not returnable"
                # Fill in end

                if types == 11:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 +
                                                                bytes])[0]
                    # Fill in start
                    # You should update your dataframe with the required column field responses here

                    df = df.append({
                        'Hop Count': ttl,
                        'Try': tries,
                        'IP': addr[0],
                        'Hostname': routerHostname,
                        'Response Code': '11'}, ignore_index=True)

                    # Fill in end
                elif types == 3:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    # Fill in start
                    # You should update your dataframe with the required column field responses here

                    df = df.append({
                        'Hop Count': ttl,
                        'Try': tries,
                        'IP': addr[0],
                        'Hostname': routerHostname,
                        'Response Code': '3'}, ignore_index=True)
                    # Fill in end
                elif types == 0:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    # Fill in start
                    # You should update your dataframe with the required column field responses here

                    df = df.append({
                        'Hop Count': ttl,
                        'Try': tries,
                        'IP': addr[0],
                        'Hostname': routerHostname,
                        'Response Code': '0'}, ignore_index=True)
                    # Fill in end
                    return df
                else:
                    # Fill in start
                    # If there is an exception/error to your if statements, you should append that to your df here
                    df = df.append({
                        'Hop Count': ttl,
                        'Try': tries,
                        'IP': addr[0],
                        'Hostname': routerHostname,
                        'Response Code': "Timeout"}, ignore_index=True)
                    # Fill in end
            break  # exit tires inner loop
    return df


if __name__ == '__main__':
    get_route("google.co.il")