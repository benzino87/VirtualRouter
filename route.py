import netifaces, socket
ETH_P_ALL = 3
def main():
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
        print("Interface name:", iface[3:])
        addrs = netifaces.ifaddresses(iface)
        interface = addrs[netifaces.AF_INET]
        print("***************************************************************")
        #IP address
        print interface[0]['addr']
        print("***************************************************************")
        print("Creating socket...")
    #if(tmp->ifa_addr->sa_family==AF_PACKET
        try:
            packet_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
            print("Socket created...")
            packet_socket.bind(interface[0])
            print("Socket bound...\n")

            if packet_socket < 0:
                print("error creating socket")
            #print("socket bound")
        except socket:
            print("Something went wrong creating socket")
    #s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, htons(ETH_P_ALL));
    #print("socket created")
main()
