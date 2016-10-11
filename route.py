import netifaces, socket

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
        print iface
        addrs = netifaces.ifaddresses(iface)
        print addrs[netifaces.AF_INET]
    #if(tmp->ifa_addr->sa_family==AF_PACKET
        packet_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        if packet_socket < 0:
            print("error creating socket")
        packet_socket.bind(("eth1", 0))
        print("socket bound")
        print("socket created")
    #s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, htons(ETH_P_ALL));
    #print("socket created")
main()
