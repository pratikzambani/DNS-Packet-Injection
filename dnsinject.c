#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<string.h>
#include<signal.h>
#include<libnet.h>
#include<stdint.h>
#include<pcap.h>
#include <sys/types.h>
#include <arpa/nameser.h>
#include <netinet/in.h>
#include <resolv.h>


#define SNAP_LEN 1518
#define SIZE_ETHERNET 14
#define UDP_HEADER_SIZE 8

u_int32_t localhost_ip;

/* Ethernet header */
struct ethernet_header {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct ip_header {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
/* TCP header */
typedef u_int tcp_seq;

struct tcp_header {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
        #define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

/* UDP header */
struct udp_header {
        u_short uh_sport;
        u_short uh_dport;
        u_short uh_ulen;
        u_short uh_sum;
};

struct dns_header{
	u_short	id;		/* query identification number */
#if BYTE_ORDER == BIG_ENDIAN
			/* fields in third byte */
	u_int	qr:1;		/* response flag */
	u_int	opcode:4;	/* purpose of message */
	u_int	aa:1;		/* authoritive answer */
	u_int	tc:1;		/* truncated message */
	u_int	rd:1;		/* recursion desired */
			/* fields in fourth byte */
	u_int	ra:1;		/* recursion available */
	u_int	pr:1;		/* primary server required (non standard) */
	u_int	unused:2;	/* unused bits */
	u_int	rcode:4;	/* response code */
#endif
#if BYTE_ORDER == LITTLE_ENDIAN
			/* fields in third byte */
	u_int	rd:1;		/* recursion desired */
	u_int	tc:1;		/* truncated message */
	u_int	aa:1;		/* authoritive answer */
	u_int	opcode:4;	/* purpose of message */
	u_int	qr:1;		/* response flag */
			/* fields in fourth byte */
	u_int	rcode:4;	/* response code */
	u_int	unused:2;	/* unused bits */
	u_int	pr:1;		/* primary server required (non standard) */
	u_int	ra:1;		/* recursion available */
#endif
			/* remaining bytes */
	u_short	qdcount;	/* number of question entries */
	u_short	ancount;	/* number of answer entries */
	u_short	nscount;	/* number of authority entries */
	u_short	arcount;	/* number of resource entries */
};

#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

struct host_ip
{
  char ip[16];
  char hostname[100];
};

//volatile int run=1;

//void sigint_handler(int signum)
//{
//  run=0;
//}

u_int32_t get_localhost_ip()
{
  libnet_t *l;
  char errbuf[LIBNET_ERRBUF_SIZE];
  u_int32_t ip_addr = libnet_get_ipaddr4(l);

  l = libnet_init(LIBNET_RAW4, NULL, errbuf);
  if ( l == NULL ) {
    fprintf(stderr, "libnet_init() failed: %s\n", errbuf);
    exit(EXIT_FAILURE);
  }

  ip_addr = libnet_get_ipaddr4(l);

  if ( ip_addr != -1 )
    printf("Own IP address: %s\n", libnet_addr2name4(ip_addr,\
                            LIBNET_DONT_RESOLVE));
  else
    fprintf(stderr, "Couldn't get own IP address: %s\n",\
                    libnet_geterror(l));
  libnet_destroy(l);

  return ip_addr;

}

//struct host_ip*
struct host_ip ** read_hostsfile(char *hostnames_file)
{
  FILE *f = fopen(hostnames_file, "r");
  if(!f)
    return NULL;

  struct host_ip **hip_arr = malloc(1000*sizeof(struct host_ip *));
  //struct host_ip *hip_arr[1000];
  size_t r, len;
  char *line = NULL;
  int j=0;

  while((r = getline(&line, &len, f)) != -1)
  {
    struct host_ip *hip = malloc(sizeof(struct host_ip));
    char *p = line;
    int i=0;
    while(*p != ' ')
    {
      hip->ip[i] = *p;
      p++;
      i++;
    }
    hip->ip[i] = '\0';
    //printf("%s ", hip->ip);

    while(*p == ' ')
      p++;

    i=0;
    while(*p != ' ' && *p != '\n' && *p != '\t')
    {
        hip->hostname[i] = *p;
        p++;
        i++;
    }
    hip->hostname[i] = '\0';
    //printf("%s\n", hip->hostname);

    hip_arr[j] = hip;
    j++;
  }

  struct host_ip **hips = hip_arr;
  fclose(f);

  return hips;
}

void pkt_receive_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  //printf("aaya packet!\n");
  //struct libnet_ipv4_hdr *ip;
	//struct libnet_udp_hdr *udp;

  const struct ip_header *ip;
  const struct udp_header *udp;
  const struct dns_header *dns;
  //HEADER *dns;

  ip = (struct ip_header*)(packet + SIZE_ETHERNET);
  if(ip->ip_p != IPPROTO_UDP)
    return;
  int size_ip = IP_HL(ip)*4;
  udp = (struct udp_header*)(packet + SIZE_ETHERNET + size_ip);
  dns = (struct dns_header*)(((char*) udp) + UDP_HEADER_SIZE);
  //dns = (HEADER *)(udp+1);
  // check differently
  if (dns->opcode != QUERY || dns->nscount || dns->arcount)
		return;

  u_char *dns_pkt = (u_char *)(dns + 1);
  u_char *dns_pkt_end = (u_char *)packet + header->caplen;
  int dns_pkt_len = (u_char *)dns_pkt_end - (u_char *)dns;

  char domain[100];
  int comp_domain_name_size = dn_expand((u_char *)dns, dns_pkt_end, dns_pkt, domain, sizeof(domain));
  if (comp_domain_name_size == -1)
    return;

  dns_pkt += comp_domain_name_size;

  u_short dns_type = _getshort(dns_pkt);
  u_short dns_class = _getshort(dns_pkt);

  if(dns_class != 1)
    return;

  in_addr_t inj_ip;

  if(dns_type == T_A && args != NULL)
  {
    struct host_ip **hips = (struct host_ip **)args;
    struct host_ip **ptr = hips;
    while(*ptr)
    {
      printf("comparing %s and %s\n", (*ptr)->hostname, domain);
      if(!strcmp((*ptr)->hostname, domain))
      {
        inj_ip = inet_addr((*ptr)->ip);
        printf("badhai ho\n");
        break;
      }
      //printf("oh bc %s %s\n", (*ptr)->hostname, (*ptr)->ip);
      ptr++;
    }
  }
  else if(dns_type == T_A)
  {
    inj_ip = localhost_ip;
  }
  else
    return;

  //printf("%d\n", dns_pkt_len);

}
int main(int argc, char **argv)
{
  char *interface = NULL;
  char *hostnames_file = NULL;
  char filter_expr[] = "";
  char errbuffer[PCAP_ERRBUF_SIZE];
  char libnet_errbuffer[LIBNET_ERRBUF_SIZE];
  char *mstr;
  pcap_t *handle;
  struct bpf_program fp;
  bpf_u_int32 mask;
  bpf_u_int32 net;
  int c, index;

  //signal(SIGINT, sigint_handler);

  // reading input from command line args
  while ((c = getopt(argc, argv, "i:h:")) != -1)
  {
    switch (c) {
      case 'i':
        interface = optarg;
        break;
      case 'h':
        hostnames_file = optarg;
        break;
      case '?':
        if(optopt == 'i' || optopt == 'h')
          fprintf(stderr, "Option -%c requires an argument\n", optopt);
        else
          fprintf(stderr, "Unknown option\n");
        return 1;
    }
  }
  for(index=optind; index<argc; index++)
  {
    if(filter_expr == "")
      strcpy(filter_expr, argv[index]);
    else
      strcat(filter_expr, argv[index]);
    if(index != argc-1)
      strcat(filter_expr, " ");
  }
  if(interface == NULL)
  {
    interface = pcap_lookupdev(errbuffer);
    if(interface == NULL)
    {
      fprintf(stderr, "Couldn't find default interface: %s\n", errbuffer);
      exit(EXIT_FAILURE);
    }
  }
  printf("yo2\n");
  if(pcap_lookupnet(interface, &net, &mask, errbuffer) == -1)
  {
    fprintf(stderr, "Couldn't get netmask for interface %s: %s\n",interface, errbuffer);
    net=0;
    mask=0;
  }
  handle = pcap_open_live(interface, SNAP_LEN, 1, 10000, errbuffer);
  if (handle == NULL)
  {
    fprintf(stderr, "Couldn't open interface %s:%s\n",interface, errbuffer);
    exit(EXIT_FAILURE);
  }

  if (pcap_datalink(handle) != DLT_EN10MB)
  {
    fprintf(stderr, "interface %s is not on Ethernet protocol\n", interface);
    exit(EXIT_FAILURE);
  }
  if(filter_expr != "")
  {
    if (pcap_compile(handle, &fp, filter_expr, 0, net) == -1)
    {
      fprintf(stderr, "Couldn't parse filter %s:%s\n", filter_expr, pcap_geterr(handle));
      exit(EXIT_FAILURE);
    }

    if (pcap_setfilter(handle, &fp) == -1)
    {
      fprintf(stderr, "Couldn't install filter %s:%s\n",filter_expr, pcap_geterr(handle));
      exit(EXIT_FAILURE);
    }
  }
  printf("listening on %s\n", interface);
  struct host_ip **hips = read_hostsfile(hostnames_file);
  // struct host_ip **ptr = hips;
  // while(*ptr)
  // {
  //   printf("%s %s\n", (*ptr)->hostname, (*ptr)->ip);
  //   ptr++;
  // }
  printf("read the hosts file\n");

  localhost_ip = get_localhost_ip();

  libnet_t *l;
  l = libnet_init(LIBNET_RAW4, interface, libnet_errbuffer);
  if(l == NULL)
  {
    fprintf(stderr, "libnet initialization failed%s\n", libnet_errbuffer);
    exit(EXIT_FAILURE);
  }
  libnet_seed_prand(l);

  pcap_loop(handle, -1, pkt_receive_callback, (u_char *)hips);
  printf("yo7\n");
  pcap_close(handle);
  return 0;
}
