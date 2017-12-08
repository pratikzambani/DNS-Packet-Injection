#!/usr/bin/python
import sys, getopt
from netifaces import AF_INET, AF_INET6, AF_LINK, AF_PACKET, AF_BRIDGE
import netifaces
from scapy.all import *

hips = dict()
#pkt.getlayer(DNS).qr == 0
def get_localhost_ip(interface=None):
    if interface:
        return netifaces.ifaddresses(interface)[AF_INET][0]['addr']
    else:
        for interface in netifaces.interfaces():
            try:
                #links = netifaces.ifaddresses(interface)[netifaces.AF_INET]
                for link in netifaces.ifaddresses(interface)[netifaces.AF_INET]:
                    #if "10." in link['addr'] or "172." in link['addr'] or "192." in link['addr']:
                    if "127.0.0.1" not in link['addr']:
                        return link['addr']
            except Exception as e:
                pass
    return None

def process_pkt(pkt):
    if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
        print pkt
    return

def main(argv):

    interface = None
    hostsfile = None
    try:
        opts, args = getopt.getopt(argv,"i:h:",["interface=","hostsfile="])
    except getopt.GetoptError:
        print 'dnsinject.py -i <interface> -h <hostsfile>'
        sys.exit(2)

    for opt, arg in opts:
        if opt in ("-i", "--interface"):
            interface = arg
        elif opt in ("-h", "--hostsfile"):
            hostsfile = arg

    print interface
    print hostsfile

    print get_localhost_ip()

    if hostsfile:
        with open(hostsfile) as f:
            lines = f.readlines()

        for line in lines:
            ip, hostname = line.split()
            hips[hostname] = ip

        print hips

    if interface:
        sniff(iface=interface, filter='udp and port 53', store=0, prn=process_pkt)
    else:
        sniff(filter='udp and port 53', store=0, prn=process_pkt)

if __name__ == "__main__":
   main(sys.argv[1:])
