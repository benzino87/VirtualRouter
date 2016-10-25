import netifaces, socket, struct, binascii, threading
ETH_P_ALL = 3

def createInterfaces():
    #get list of interfaces or something
    if netifaces.interfaces() == -1:
        print("getifaddrs")
        return 1
    ifaces = netifaces.interfaces()

    #Get the list of interfaces
    for iface in ifaces:
    #Check if this is a packet address, there will be one per
    #interface.  There are IPv4 and IPv6 as well, but we don't care
    #about those for the purpose of enumerating interfaces. We can
    #use the AF_INET addresses in this list for example to get a list
    #of our own IP addresses
        #print("Interface name:", iface[3:])
        print "INTERFACE NAME: :", iface
        addrs = netifaces.ifaddresses(iface)
        #print addrs
        interface = addrs[netifaces.AF_INET]
        #IP address
        #hostAddress = interface[0]['addr']
        routeripaddress = addrs[2][0]['addr']
        routermacaddress = addrs[17][0]['addr']

        #t = threading.Thread(target=interfaceSlaveThread, args=(iface, ))
        #t.start()

        #Convert ip address from string to int
        #hostAddress = hostAddress.replace(".", "")
        #convertedHostAddress = int(hostAddress)
        #print hostAddress
        #print interface
        #print("Creating socket...")





#def interfaceSlaveThread(iface):
    try:
        #Create a raw socket or something like that
        packet_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
        print("Socket created...")

        #Bind socket to the address
        packet_socket.bind((iface, socket.htons(0x0806)))
        print("Socket bound...")

        if packet_socket < 0:
            print("error creating socket")

        #t = threading.Thread(target=arpHandler, args=(packet_socket, ))
        #t.start()
    except socket:
        print("Something went wrong creating socket")



#loop and recieve packets. We are only looking at one interface,
#for the project you will probably want to look at more (to do so,
#a good way is to have one socket per interface and use select to
#see which ones have data)
#def arpHandler(packet_socket):
    while 1:
        count = 1

        #rawSocket.settimeout(0.5)
        response = packet_socket.recvfrom(2048)
        print response
        if count == 1:
            broadcast = binascii.hexlify(response[0][0:6])
            print "Broadcast:", broadcast
        else:
            sourceMAC = binascii.hexlify(response[0][0:6])
            print "SourceMAC:", sourceMAC
        responseMACraw = binascii.hexlify(response[0][6:12])
        responseMAC = ":".join(responseMACraw[x:x+2] for x in xrange(0, len(responseMACraw), 2))
        responseIP = socket.inet_ntoa(response[0][28:32])


        print "MAC ADDRESS RAW 6-12:", responseMACraw
        print "IPADRESS", responseIP
        #construct packet
        eth_hdr = struct.pack("!6s6s2s", '\xff\xff\xff\xff\xff\xff', routermacaddress.replace(':','').decode('hex'), '\x08\x06')
        arp_hdr = struct.pack("!2s2s1s1s2s", '\x00\x01', '\x08\x00', '\x06', '\x04', '\x00\x01')
        arp_sender = struct.pack("!6s4s", routermacaddress.replace(':','').decode('hex'), socket.inet_aton(routeripaddress))
        arp_target = struct.pack("!6s4s", '\x00\x00\x00\x00\x00\x00', socket.inet_aton("10.1.1.5"))


        #if "10.1.1.5" == responseIP:
            #print "PING - MAC: %s | IP: %s" % (responseMAC, responseIP)
        # receive a package
        #packet = packet_socket.recvfrom(4096)
        packet_socket.send(eth_hdr+arp_hdr+arp_sender+arp_target)
        #packet_length = len(packet)
        #print "================================================================================="
        #print packet
        #print "================================================================================="

        count+=count
createInterfaces()
