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

low_port, high_port = results.port_range.split('-')
print "low port",low_port
print "high port",high_port

def main():
    # if(results.target_list != None): #Target list supplied
    #     with open(results.target_list) as f:
    #             for line in f:
    #                 print line
    # else:	#Target IP supplied
    #     print "target"
    
    remoteServerIP  = socket.gethostbyname(results.target_ip)

    if(results.sT):
        print "Scanning TCP" 
        scan_host(remoteServerIP, socket.SOCK_STREAM)
    if(results.sU): 
        print "Scanning UDP"
        scan_host(remoteServerIP, socket.SOCK_DGRAM)

    open_ports = []

    t1 = datetime.now()

    # Checking the time again
    t2 = datetime.now()

    # Calculates the difference of time, to see how long it took to run the script
    total =  t2 - t1

    # Printing the information to screen
    print 'Scanning Completed in: ', total, "seconds."

    print "Open Ports:"
    print open_ports



def scan_host_tcp(ip_address):
    try:
        for port in range(int(low_port),int(high_port)+1):  
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(float(results.timeout))
            r = s.connect_ex((ip_address, port))
            
            if(r == 0):
                # open_ports.append(port) #TODO Make list global
                print "Port:",port, " ",
                print "	OPEN"
            elif (results.v):
                print "Port:",port, " ",
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
