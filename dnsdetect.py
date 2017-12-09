#!/usr/bin/python
import sys, getopt
import datetime import datetime

dns_queries = dict()

def detect_dns_attack(pkt):
    if IP in pkt and pkt.haslayer(DNS):
        # DNSRR ?
        print key
        if pkt.getlayer(DNS).qr == 0:
            key = pkt[DNS].id+ pkt[DNSQR].qname
            dns_queries[key] = 1
            print 'printing all queries',dns_queries
        elif pkt.getlayer(DNS).qr == 1:
            key = pkt[DNS].id+ pkt[DNSRR].qname
            #if key in dns_queries.keys() and dns_queries[key]:
            print datetime.now().strftime('%Y%m%d-%H:%M:%S.%f'), ' DNS poisoning attempt'
            # qd.qname or not?
            print 'TXID: '+str(pkt[DNS].id)+ '   Request: '+pkt.getlayer(DNS).qd.qname
            print 'Answer1: ', dns_queries[pkt[DNS].id]
            print 'Answer2: ', str(pkt[DNSRR].rdata)


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

    print interface
    print tracefile

    if interface and tracefile:
        print 'Use either -i or -r, not both'
        sys.exit(2)

    if tracefile:
        sniff(filter=expression, offline=tracefile, store=0, prn=detect_dns_attack)
    elif interface:
        sniff(filter=expression, iface=interface, store=0, prn=detect_dns_attack)
    else:
        sniff(filter=expression, store=0, prn=detect_dns_attack)

if __name__ == "__main__":
   main(sys.argv[1:])
