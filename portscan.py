#!/usr/bin/env python

import argparse
import socket
import sys
from datetime import datetime
import errno
import os

""" Argument setup
"""
parser = argparse.ArgumentParser()

target_group = parser.add_mutually_exclusive_group(required=True)

target_group.add_argument('-t', action='store', dest='target_ip', metavar='<TARGET IP>',
                    help='Target IP Address to scan')

target_group.add_argument('-l', action='store', dest='target_list', metavar='<HOST LIST>',
                    help='List of target IP Addresses to scan')

parser.add_argument('-p', action='store', dest='port_range', metavar='<PORT RANGE>',
                    help='Range of ports to scan. Ex. -p 1-1024. Default=1-1024', default='1-1024')

parser.add_argument('-timeout', action='store', dest='timeout', metavar='<TIMEOUT VALUE>',
                    help='Give up on port after <timeout> seconds. Default=0.5s', default=0.5)

parser.add_argument("-v", help="Turn on verbose mode",
                    action="store_true")

parser.add_argument("-d", help="Turn on service discovery for open ports",
                    action="store_true")

parser.add_argument("-tr", help="Perform traceroute",
                    action="store_true")
                    
parser.add_argument("-sT", help="Perform TCP scan", action="store_true")

parser.add_argument("-sU", help="Perform UDP scan", action="store_true")

results = parser.parse_args()

low_port = 0
high_port = 0

if results.port_range == '-': results.port_range = '1-65535'

if '-' in results.port_range:
    low_port, high_port = results.port_range.split('-')
else:
    low_port = results.port_range
    high_port = results.port_range

tcp_ports = []
udp_ports = []


def main():
    """ Main program body
    """
    t1 = datetime.now()

    if(results.target_list != None): #Target list supplied
        with open(results.target_list) as f:
                for line in f:
                    remoteServerIP  = socket.gethostbyname(line) 
                    if(results.sT): scan_host_tcp(remoteServerIP)
                    if(results.sU): scan_host_udp(remoteServerIP)
                    if(results.tr): traceroute(remoteServerIP)
    else:   #Target IP supplied
        remoteServerIP  = socket.gethostbyname(results.target_ip) 
        if(results.sT): scan_host_tcp(remoteServerIP)
        if(results.sU): scan_host_udp(remoteServerIP)
        if(results.tr): traceroute(remoteServerIP)

    t2 = datetime.now()
    total = t2-t1

    print "<--------------SUMMARY------------------------------->"
    print 'Scanning Completed in: ', total, "seconds."

    print "Open TCP Ports:"
    for port in tcp_ports:
        print port,

        if(results.d):
            service = ''
            try:
                service = socket.getservbyport(port, 'tcp')
            except:
                service = "Unknown"

            print service
        else: 
            print

    print "\nOpen/Filtered UDP Ports:",
    for port in udp_ports:
        print port,

        if(results.d):
            service = ''
            try:
                service = socket.getservbyport(port, 'udp')
            except:
                service = "Unknown"

            print service
        else: 
            print

def scan_host_udp(ip_address):
    """ Performs a UDP port scan across the range of ports as given on the 
    command line. This scan is only performed if the '-sU' option is given. 
    """
    print "<--------------UDP SCAN------------------------------>"
    for port in range(int(low_port),int(high_port)+1):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(float(results.timeout))
            s.sendto("", (ip_address, port))
            recv, svr = s.recvfrom(255)
        except Exception,e:
            try:
                # print e 
                errno, errtxt = e
            except ValueError:
                udp_ports.append(port)
                print "{",ip_address,"}", "UDP Port:",port, " ",
                print " OPEN/FILTERED"
            else:
                if(results.v):
                    print "{",ip_address,"}","UDP Port:",port, " ",
                    print " CLOSED"
        s.close()
    print ""


def traceroute(ip_address):
    """ Performs a UDP tracerout to the target IP address.
    This is only performed if the '-tr' option is given. 
    """
    print "<-------------TRACE ROUTE---------------------------->"
    icmp = socket.getprotobyname('icmp')
    max_hops = 30
    ttl = 1
    while True:
        try:
            recv = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
            send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            send.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
            recv.bind(("", 33434))
            send.sendto("", (ip_address, 33434))
        except socket.error, e:
            print "Error:",
            print os.strerror(e.errno)
            return
        address = None
        try:
            _, address = recv.recvfrom(512)
            address = address[0]
            try:
                curr_name = socket.gethostbyaddr(address)[0]
            except socket.error:
                curr_name = address
        except socket.error:
            pass
        
        send.close()
        recv.close()

        if address is not None:
            curr_host = "%s (%s)" % (curr_name, address)
        else:
            curr_host = "*"
        print "%d\t%s" % (ttl, curr_host)

        ttl = ttl + 1
        if (address == ip_address) or (ttl > max_hops):
            break
    print ""

def scan_host_tcp(ip_address):
    """ Performs a TCP port scan across the range of ports as given on the 
    command line. This scan is only performed if the '-sT' option is given. 
    """
    print "<--------------TCP SCAN------------------------------>"
    try:
        for port in range(int(low_port),int(high_port)+1):  
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(float(results.timeout))
            r = s.connect_ex((ip_address, port))   
            if(r == 0):
                tcp_ports.append(port)
                print "{",ip_address,"}", "TCP Port:",port, " ",
                print "	OPEN"
            elif (results.v):
                print "{",ip_address,"}","TCP Port:",port, " ",
                print "	CLOSED"

                s.close()

    except socket.error:
        print "Couldn't connect to server"
        sys.exit()

    except socket.gaierror:
        print 'Hostname could not be resolved. Exiting'
        sys.exit()

    except KeyboardInterrupt:
        print "Keyboard Interrupt"
        sys.exit()

    print ""

if __name__ == "__main__":
    main()
