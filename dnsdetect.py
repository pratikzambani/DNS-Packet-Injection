#!/usr/bin/python
import sys, getopt
from scapy.all import *
from datetime import datetime

DICT_LIMIT = 4096
dns_queries = dict()
ttl = dict()

def detect_dns_attack(pkt):
    if IP in pkt and pkt.haslayer(DNS):
        if pkt.getlayer(DNS).qr == 0:
            key = str(pkt[DNS].id) + pkt[DNSQR].qname
            #print 'query key', key
            dns_queries[key] = 'queried'
        elif pkt.getlayer(DNS).qr == 1:
            poisoning_atmpt = False
            key = str(pkt[DNS].id) + pkt[DNS].qd.qname
            #print 'response key', key

            a_count = pkt[DNS].ancount
            i = a_count + 4
            value = []
            while i > 4:
                value.append(pkt[0][i].rdata)
                i -= 1

            if key in dns_queries.keys() and dns_queries[key] == 'queried':
                dns_queries[key] = value
                ttl[key] = pkt[DNSRR].ttl
                #print 'original ttl bro', pkt[DNSRR].ttl
            elif key in dns_queries.keys():
                #if ttl same:
                #    then fine
                if (len(dns_queries[key]) != len(value)) or \
                  len(set(dns_queries[key]) & set(value)) != len(value) or \
                  ttl[key] != pkt[DNSRR].ttl:
                    poisoning_atmpt = True
                #print 'second ttl bro', pkt[DNSRR].ttl
            else:
                poisoning_atmpt = True

            if poisoning_atmpt and key in dns_queries:
                print datetime.now().strftime('%Y%m%d-%H:%M:%S.%f'), 'DNS poisoning attempt'
                print 'TXID', hex(pkt[DNS].id), 'Request', pkt[DNS].qd.qname.rstrip('.')
                print 'Answer1', dns_queries[key]
                print 'Answer2', value
                print '\n'
                del dns_queries[key]
                del ttl[key]

            if len(dns_queries) > DICT_LIMIT:
                dns_queries.clear()
                ttl.clear()

def main(argv):

    interface = None
    tracefile = None
    try:
        opts, args = getopt.getopt(argv,"i:r:",["interface=","tracefile="])
    except getopt.GetoptError:
        print 'dnsinject.py -i <interface> -r <tracefile>'
        sys.exit(2)

    for opt, arg in opts:
        if opt in ("-i", "--interface"):
            interface = arg
        elif opt in ("-r", "--tracefile"):
            tracefile = arg

    #print interface
    #print tracefile

    if interface and tracefile:
        print 'Use either -i or -r, not both'
        sys.exit(2)

    expression = None
    if tracefile:
        sniff(filter=expression, offline=tracefile, store=0, prn=detect_dns_attack)
    elif interface:
        sniff(filter=expression, iface=interface, store=0, prn=detect_dns_attack)
    else:
        sniff(filter=expression, store=0, prn=detect_dns_attack)

if __name__ == "__main__":
   main(sys.argv[1:])
