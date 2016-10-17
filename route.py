import netifaces, socket, struct, binascii

def main():
    #get list of interfaces or something
    # if netifaces.interfaces() == -1:
    #     print("getifaddrs")
    #     return 1
    # ifaces = netifaces.interfaces()
    #
    # #Get the list of interfaces
    # for iface in ifaces:
    # #Check if this is a packet address, there will be one per
    # #interface.  There are IPv4 and IPv6 as well, but we don't care
    # #about those for the purpose of enumerating interfaces. We can
    # #use the AF_INET addresses in this list for example to get a list
    # #of our own IP addresses
    #     #print("Interface name:", iface[3:])
    #     print "INTERFACE NAME: :", iface
    #     addrs = netifaces.ifaddresses(iface)
    #     #print addrs
    #     #interface = addrs[netifaces.AF_INET]
    #     #IP address
    #     #hostAddress = interface[0]['addr']
    #
    #     #routeripaddress = addrs[2][0]['addr']
    #     #routermacaddress = addrs[17][0]['addr']
    #
    #     #Convert ip address from string to int
    #     #hostAddress = hostAddress.replace(".", "")
    #     #convertedHostAddress = int(hostAddress)
    #     print("Creating socket...")
    #
    #     try:
    #         #Create a raw socket or something like that
    #         packet_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    #         print("Socket created...")
    #
    #         #Bind socket to the address
    #         packet_socket.bind((iface, 0))
    #         print("Socket bound...")
    #
    #
    #
    #         if packet_socket < 0:
    #             print("error creating socket")
    #
    #     except socket:
    #         print("Something went wrong creating socket")




    #loop and recieve packets. We are only looking at one interface,
    #for the project you will probably want to look at more (to do so,
    #a good way is to have one socket per interface and use select to
    #see which ones have data)
    networkdetails = netifaces.ifaddresses('r1-eth0')
    routeripaddress = networkdetails[2][0]['addr']
    routermacaddress = networkdetails[17][0]['addr']

    packet_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))

    print "Ready to recieve..."
    count = 1
    while 1:

        packet = packet_socket.recvfrom(2048)

        #Get ethernet frame
        ethernet_header_raw = packet[0][0:14]
        ethernet_header = struct.unpack("!6s6s2s", ethernet_header_raw)

        arp_header_raw = packet[0][14:42]
        arp_header = struct.unpack("2s2s1s1s2s6s4s6s4s", arp_header_raw)

        print "_______________ETHERNET HEADER________________"
        print "Destination MAC:    ", binascii.hexlify(ethernet_header[0])
        print "Source MAC:         ", binascii.hexlify(ethernet_header[1])
        print "Type:               ", binascii.hexlify(ethernet_header[2])
        print "_________________ARP HEADER___________________"
        print "Hardware type:     ", binascii.hexlify(arp_header[0])
        print "Protocol type:     ", binascii.hexlify(arp_header[1])
        print "Hardware size:     ", binascii.hexlify(arp_header[2])
        print "Protocol size:     ", binascii.hexlify(arp_header[3])
        print "Opcode:            ", binascii.hexlify(arp_header[4])
        print "Source MAC:        ", binascii.hexlify(arp_header[5])
        print "Source IP:         ", socket.inet_ntoa(arp_header[6])
        print "Dest MAC:          ", binascii.hexlify(arp_header[7])
        print "Dest IP:           ", socket.inet_ntoa(arp_header[8])
        print "______________________________________________"


        #construct packet for arp reply
        eth_hdr = struct.pack("!6s6s2s", binascii.hexlify(arp_header[5]).decode('hex'), routermacaddress.replace(':','').decode('hex'), '\x08\x06')
        arp_hdr = struct.pack("!2s2s1s1s2s", '\x00\x01', '\x09\x00', '\x06', '\x04', '\x00\x01')
        arp_sender = struct.pack("!6s4s", routermacaddress.replace(':','').decode('hex'), socket.inet_aton(routeripaddress))
        arp_target = struct.pack("!6s4s", binascii.hexlify(arp_header[5]).decode('hex'), socket.inet_aton(socket.inet_ntoa(arp_header[6])))

        #STILL BROKEN
        packet_socket.send(eth_hdr + arp_hdr + arp_sender + arp_target)

        count+=count
main()
