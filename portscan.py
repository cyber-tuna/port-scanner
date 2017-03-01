#!/usr/bin/env python

import argparse
import socket
import sys
from datetime import datetime

low_port = 0
high_port = 0

parser = argparse.ArgumentParser()

target_group = parser.add_mutually_exclusive_group(required=True)


target_group.add_argument('-t', action='store', dest='target_ip',
                    help='Target IP Address to scan')

target_group.add_argument('-l', action='store', dest='target_list',
                    help='List of target IP Addresses to scan')

parser.add_argument('-p', action='store', dest='port_range',
                    help='Range of ports to scan. Ex. -p 1-1024', default=-1)

parser.add_argument('-timeout', action='store', dest='timeout',
                    help='Give up on port after <timeout> seconds. Default=0.5s', default=0.5)

parser.add_argument("-v", help="Turn on verbose mode",
                    action="store_true")
                    
parser.add_argument("-sT", help="Perform TCP scan", action="store_true")
parser.add_argument("-sU", help="Perform UDP scan", action="store_true")

results = parser.parse_args()

print 'target_ip     =', results.target_ip
print 'target_list     =', results.target_list
print 'timeout     =', results.timeout
#print 'port range     =', results.port_range	

if results.port_range == '-': results.port_range = '1-65535'

if '-' in results.port_range:
    low_port, high_port = results.port_range.split('-')
else:
    low_port = results.port_range
    high_port = results.port_range


print "low port",low_port
print "high port",high_port

tcp_ports = []
udp_ports = []

def main():
    
    t1 = datetime.now()

    if(results.target_list != None): #Target list supplied
        with open(results.target_list) as f:
                for line in f:
                    remoteServerIP  = socket.gethostbyname(line) 
                    if(results.sT): scan_host_tcp(remoteServerIP)
                    if(results.sU): scan_host_udp(remoteServerIP)
    else:   #Target IP supplied
        remoteServerIP  = socket.gethostbyname(results.target_ip) 
        if(results.sT): scan_host_tcp(remoteServerIP)
        if(results.sU): scan_host_udp(remoteServerIP)

    t2 = datetime.now()
    total = t2-t1

    # Printing the information to screen
    print 'Scanning Completed in: ', total, "seconds."

    print "Open TCP Ports:",
    print tcp_ports

    print "Open UDP Ports:",
    print udp_ports

def scan_host_udp(ip_address):
    for port in range(int(low_port),int(high_port)+1):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(float(results.timeout))
            s.sendto("TEST LINE", (ip_address, port))
            recv, svr = s.recvfrom(255)
            print recv
            print svr
        except Exception,e:
            try:
                print e 
                errno, errtxt = e
            except ValueError:
                udp_ports.append(port)
                print "{",ip_address,"}", "UDP Port:",port, " ",
                print " OPEN/FILTERED"
            else:
                print "{",ip_address,"}","UDP Port:",port, " ",
                print " CLOSED"
        s.close()

def scan_host_tcp(ip_address):
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


if __name__ == "__main__":
    main()