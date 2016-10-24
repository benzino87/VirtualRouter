import netifaces, socket, struct, binascii, threading

def initiateSockets():
    global packet_sockets
    global r1_routingTable
    global r2_routingTable
    global dest_MAC_address
    global eth_icmp_header
    global ipv4_header
    global ipv4_icmp_header
    global icmp_source_ip
    packet_sockets = {}

    #SET UP ROUTING TABLES
    r1_routingTable = {"10.0.0.0/16":"r1-eth0",
                       "10.1.0.0/24":"r1-eth1",
                       "10.1.1.0/24":"r1-eth2",
                       "10.3.0.0/24":"r1-eth0",
                       "10.0.0.2":"r1-eth0"}

    r2_routingTable = {"10.0.0.0/16":"r2-eth0",
                       "10.3.0.0/24":"r2-eth1",
                       "10.3.1.0/24":"r2-eth2",
                       "10.3.4.0/24":"r2-eth3",
                       "10.1.0.0/16":"r2-eth0",
                       "10.0.0.1":"r2-eth0"}

    #get list of interfaces
    ifaces = netifaces.interfaces()

    #iterate through list of interfaces and attach sockets
    for iface in ifaces:
    # #Check if this is a packet address, there will be one per
    # #interface.  There are IPv4 and IPv6 as well, but we don't care
    # #about those for the purpose of enumerating interfaces. We can
    # #use the AF_INET addresses in this list for example to get a list
    # #of our own IP addresses
        try:
            #Create a raw socket
            packet_sockets[iface] = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))

            #Bind socket to interface address
            packet_sockets[iface].bind((iface, 0))


            print "INTERFACE NAME: :", iface
            print packet_sockets[iface]

            #get addresses for each interface and print address for testing
            addresses = netifaces.ifaddresses(iface)
            routerip = addresses[2][0]['addr']
            routermac =  addresses[17][0]['addr']
            print routerip
            print routermac

            #create thread for each interface
            threading.Thread(target = createInterfaceRawSockets,
                             args = (iface, packet_sockets[iface])).start()

        except socket:
            print("Something went wrong creating socket")
            
def constructAndSendInitialICMP_packet(packet_socket, destination_mac, destination_ip, source_mac):
    #Destination address, source address, type
    eth_hdr = struct.pack("!6s6s2s",
                        destination_mac.decode('hex'),
                        source_mac.replace(':','').decode('hex'),
                        headerType.decode('hex'))

    #Source IP
    ipv_source = struct.pack("!4s",  socket.inet_aton(icmp_source_ip))
    #Desination IP
    ipv_target = struct.pack("!4s", socket.inet_aton(destination_ip))

    #re-construct packet
    packet = eth_hdr + ipv4_header + ipv_source + ipv_target + ipv4_icmp_header

    packet_socket.send(packet)




# Sends a default ARP request to host to find MAC address so IPV4 request can be passsed along
def constructAndSendDefaultARP_packet(interface, ip_address, mac_address, destination_ip):
    #construct default ARP request to send on required interface
    eth_hdr = struct.pack("!6s6s2s",
                            '\xff\xff\xff\xff\xff\xff',
                            mac_address.replace(':','').decode('hex'),
                            '\x08\x06')
    arp_hdr = struct.pack("!2s2s1s1s2s",
                            '\x00\x01',
                            '\x08\x00',
                            '\x06',
                            '\x04',
                            '\x00\x01')
    arp_sender = struct.pack("!6s4s",
                            mac_address.replace(':','').decode('hex'),
                            socket.inet_aton(ip_address))
    arp_target = struct.pack("!6s4s",
                            '\x00\x00\x00\x00\x00\x00',
                            socket.inet_aton(destination_ip))

    packet = eth_hdr + arp_hdr + arp_sender + arp_target

    packet_sockets[interface].send(packet)

def createInterfaceRawSockets(interface, packet_socket):


    networkdetails = netifaces.ifaddresses(interface)
    routeripaddress = networkdetails[2][0]['addr']
    routermacaddress =  networkdetails[17][0]['addr']

    print interface + routeripaddress + routermacaddress


    #loop and recieve packets. We are only looking at one interface,
    #for the project you will probably want to look at more (to do so,
    #a good way is to have one socket per interface and use select to
    #see which ones have data)

    print "Ready to recieve..."
    while 1:
        packet = packet_socket.recvfrom(2048)


        #Get ethernet frame
        ethernet_header_raw = packet[0][0:14]
        ethernet_header = struct.unpack("!6s6s2s", ethernet_header_raw)

        headerType = binascii.hexlify(ethernet_header[2])


        #Check for IPv4 request
        if headerType == '0800':
            ip_header_raw = packet[0][14:34]
            ip_header = struct.unpack("9s1s2s4s4s", ip_header_raw)

            icmp_header_raw = packet[0][34:98]
            icmp_header = struct.unpack("1s1s2s60s", icmp_header_raw)


            print "_______________ETHERNET HEADER________________"
            print "Destination MAC:    ", binascii.hexlify(ethernet_header[0])
            print "Source MAC:         ", binascii.hexlify(ethernet_header[1])
            print "Type:               ", binascii.hexlify(ethernet_header[2])

            print "________________IPv4 HEADER___________________"
            print "IP Protocol:        ", binascii.hexlify(ip_header[1])
            print "Header Checksum:    ", binascii.hexlify(ip_header[2])
            print "Source IP:          ", socket.inet_ntoa(ip_header[3])
            print "Destination IP:     ", socket.inet_ntoa(ip_header[4])

            protocolType = binascii.hexlify(ip_header[1])
            #Check if ICMP request
            if protocolType == '01':
                print "__________________ICMP HEADER__________________"
                print "Type:           ", binascii.hexlify(icmp_header[0])
                print "Code:           ", binascii.hexlify(icmp_header[1])
                print "Checksum:       ", binascii.hexlify(icmp_header[2])

                #CONSTRUCT PACKET FOR ICMP REPLY
                icmp_source_ip = socket.inet_ntoa(ip_header[3])
                destination_ip = socket.inet_ntoa(ip_header[4])
                is_interfaceFound = False
                required_interface = ""

                #Look up routing table to find required interface
                if destination_ip != routeripaddress:
                    for dest in r1_routingTable:
                        if dest[0:6] == destination_ip[0:6]:
                            required_interface = r1_routingTable[dest]
                            is_interfaceFound = True
                    if is_interfaceFound == False:
                        for dest in r2_routingTable:
                            if dest[0:6] == destination_ip[0:6]:
                                required_interface = r2_routingTable[dest]
                                is_interfaceFound = True

                    alt_network_details = netifaces.ifaddresses(interface)
                    alt_routeripaddress = alt_network_details[2][0]['addr']
                    alt_routermacaddress =  alt_network_details[17][0]['addr']

                    constructAndSendDefaultARP_packet(required_interface,
                                                        alt_routeripaddress,
                                                        alt_routermacaddress,
                                                        destination_ip)

                    ipv4_header = struct.pack("!9s1s2s",
                                        binascii.hexlify(ip_header[0]).decode('hex'),
                                        '\x01',
                                        binascii.hexlify(ip_header[2]).decode('hex'))

                    #ICMP TYPE, CODE, CHECKSUM, REMAINING
                    ipv4_icmp_header = struct.pack("1s1s2s60s",
                                        '\x00', '\x00',
                                        binascii.hexlify(icmp_header[2]).decode('hex'),
                                        binascii.hexlify(icmp_header[3]).decode('hex'))

                else:
                    #Destination address, source address, type
                    eth_hdr = struct.pack("!6s6s2s",
                                        binascii.hexlify(ethernet_header[1]).decode('hex'),
                                        routermacaddress.replace(':','').decode('hex'),
                                        headerType.decode('hex'))
                    #Version/IHL, DSCP/ECN, Total Length, Identification, Flags/FragOffset, IP Protocol, HeaderChecksum,
                    ipv_hdr = struct.pack("!9s1s2s",
                                        binascii.hexlify(ip_header[0]).decode('hex'),
                                        '\x01',
                                        binascii.hexlify(ip_header[2]).decode('hex'))
                    #Source IP
                    ipv_source = struct.pack("!4s",  socket.inet_aton(routeripaddress))
                    #Desination IP
                    ipv_target = struct.pack("!4s", socket.inet_aton(socket.inet_ntoa(ip_header[3])))
                    #ICMP TYPE, CODE, CHECKSUM, REMAINING
                    icmp_hdr = struct.pack("1s1s2s60s",
                                        '\x00', '\x00',
                                        binascii.hexlify(icmp_header[2]).decode('hex'),
                                        binascii.hexlify(icmp_header[3]).decode('hex'))


                    #re-construct packet
                    packet = eth_hdr + ipv_hdr + ipv_source + ipv_target + icmp_hdr

                    #Send reply
                    packet_socket.send(packet)

        #Check for ARP Request
        if headerType =='0806':
            arp_header_raw = packet[0][14:42]
            arp_header = struct.unpack("6s2s6s4s6s4s", arp_header_raw)
            print "_______________ETHERNET HEADER________________"
            print "Destination MAC:    ", binascii.hexlify(ethernet_header[0])
            print "Source MAC:         ", binascii.hexlify(ethernet_header[1])
            print "Type:               ", binascii.hexlify(ethernet_header[2])
            print "_________________ARP HEADER___________________"
            print "Source MAC:        ", binascii.hexlify(arp_header[2])
            print "Source IP:         ", socket.inet_ntoa(arp_header[3])
            print "Dest MAC:          ", binascii.hexlify(arp_header[4])
            print "Dest IP:           ", socket.inet_ntoa(arp_header[5])
            print "______________________________________________"

            # check for ARP REPLY if ARP reply send the initial ICMP request
            is_reply = binascii.hexlify(arp_header[1])
            if is_reply == 2:
                destination_mac = binascii.hexlify(ethernet_header[1])
                destination_ip = socket.inet_ntoa(arp_header[3])

                constructAndSendInitialICMP_packet(packet_socket,
                                                    destination_mac,
                                                    destination_ip,
                                                    routermacaddress)



            #CONSTRUCT PACKET AND REPLY TO REQUEST
            #Destination address, source address, type
            eth_hdr = struct.pack("!6s6s2s",
                                    binascii.hexlify(ethernet_header[1]).decode('hex'),
                                    routermacaddress.replace(':','').decode('hex'),
                                    headerType.decode('hex'))
            #Hardware type, protocol type, hardware size, protocol size, OP CODE
            arp_hdr = struct.pack("!6s2s",
                                    binascii.hexlify(arp_header[0]).decode('hex'),
                                    '\x00\x02')
            #Source MAC address, Source IP address
            arp_source = struct.pack("!6s4s",
                                    routermacaddress.replace(':','').decode('hex'),
                                    socket.inet_aton(routeripaddress))
            #Destination MAC address, Destination IP address
            arp_target = struct.pack("!6s4s",
                                    binascii.hexlify(ethernet_header[2]).decode('hex'),
                                    socket.inet_aton(socket.inet_ntoa(arp_header[3])))

            #Construct packet
            packet = eth_hdr + arp_hdr + arp_source + arp_target

            #Send Reply
            packet_socket.send(packet)

initiateSockets()
