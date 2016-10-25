#!/usr/bin/env python
"""
Author:     phillips321 contact at phillips321.co.uk
License:    CC BY-SA 3.0
Use:        Simple python arpscanner
Released:   www.phillips321.co.uk
Dependencies:
    netifaces (needs python-dev then easy_install netifaces)
ChangeLog:
    v0.1 - first release
"""
version = "0.1"
import socket, struct, sys, netifaces, binascii, thread, time
if len(sys.argv) == 2 :
    interface = sys.argv[1]
else: #no values defined print help
    print "Usage: %s [interface] \n   eg: %s eth0" % (sys.argv[0],sys.argv[0])
    exit(1)

networkdetails = netifaces.ifaddresses(interface)
sourceipaddress = networkdetails[2][0]['addr']
sourcemacaddress = networkdetails[17][0]['addr']

def worker_thread(target, sourceipaddress, sourcemacaddress):
    # create packet
    eth_hdr = struct.pack("!6s6s2s", '\xff\xff\xff\xff\xff\xff', sourcemacaddress.replace(':','').decode('hex'), '\x08\x06')
    arp_hdr = struct.pack("!2s2s1s1s2s", '\x00\x01', '\x08\x00', '\x06', '\x04', '\x00\x01')
    arp_sender = struct.pack("!6s4s", sourcemacaddress.replace(':','').decode('hex'), socket.inet_aton(sourceipaddress))
    arp_target = struct.pack("!6s4s", '\x00\x00\x00\x00\x00\x00', socket.inet_aton(target))
    try:
        # send packet
        rawSocket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
        rawSocket.bind((interface, socket.htons(0x0806)))
        rawSocket.send(eth_hdr + arp_hdr + arp_sender + arp_target)

        # wait for response
        rawSocket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
        rawSocket.settimeout(0.5)
        response = rawSocket.recvfrom(2048)
        responseMACraw = binascii.hexlify(response[0][6:12])
        responseMAC = ":".join(responseMACraw[x:x+2] for x in xrange(0, len(responseMACraw), 2))
        responseIP = socket.inet_ntoa(response[0][28:32])
        if target == responseIP:
            print "Response from the mac %s on IP %s" % (responseMAC, responseIP)
    except socket.timeout:
        time.sleep(1)

for i in range(256):
    target = "192.168.0." + str(i)
    thread.start_new_thread(worker_thread, (target, sourceipaddress, sourcemacaddress))
    time.sleep(0.2)
