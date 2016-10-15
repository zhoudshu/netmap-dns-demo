
#include <stdio.h>
#include <pthread.h>

#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>
#include <sys/poll.h>

#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#include <sys/mman.h> /* PROT_* */
#include <sys/ioctl.h> /* ioctl */
#include <sys/param.h>
#include <sys/socket.h> /* sockaddr.. */
#include <arpa/inet.h> /* ntohs */


#include <net/if.h>	/* ifreq */
#include <net/ethernet.h>

#include <netinet/if_ether.h>
#include <netinet/in.h> /* sockaddr_in */
#include <netinet/ip.h>
#include <netinet/udp.h>



int verbose = 0;

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <resolv.h>

#define IP_SIZE 16
#define REQUEST_SIZE 1024
#define PCAP_INTERFACENAME_SIZE 16
#define FILTER_SIZE 200
//#define ETHER_ADDR_LEN  6
#define DATAGRAM_SIZE 8192

typedef struct thread_info_ {
    int thread_id;
    struct nm_desc* nm_receiver;
    struct nm_desc* nm_sender;

} thread_info;

typedef struct _SpoofParams_ {
    char ip[IP_SIZE];                        /* ip address (xxx.xxx.xxx.xxx) */
    char request[REQUEST_SIZE];              /* request address (www.example.com) */
    char interface[PCAP_INTERFACENAME_SIZE]; /* interface name */
} SpoofParams;

/* ethernet header definition */
struct etherhdr{
    u_char ether_dhost[ETHER_ADDR_LEN]; /* dst address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* src address */
    u_short ether_type; /* network protocol */
};

/* DNS header definition */
struct dnshdr {
    char id[2];
    char flags[2];
    char qdcount[2];
    char ancount[2];
    char nscount[2];
    char arcount[2];
};

/* DNS query structure */
struct dnsquery {
    char *qname;
    char qtype[2];
    char qclass[2];
};

/* DNS answer structure */
struct dnsanswer {
    char *name;
    char atype[2];
    char aclass[2];
    char ttl[4];
    char RdataLen[2];
    char *Rdata;
};

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  dump_hex
 *  Description:  
 * =====================================================================================
 */

void dump_hex_file(char * str, int len)
{
    char buf[100];
    snprintf(buf, 100, "/tmp/dns_packet_dump_%ld.pcap", time(NULL));
    FILE* fp = fopen(buf, "w");

    char d[17];
    d[16] = 0;
    unsigned int i, bytes, index = 0;
    int left_len = len;

    while(left_len > 0)
    {
        if(left_len/16 >= 1)
        {
            memcpy(d,str+index,16);
            bytes = 16;
        }
        else
        {
            memcpy(d,str+index,left_len);
            bytes = left_len;
        }

        //fprintf(fp, "%08X\t", index);

        index += 16;

        for (i = 0; i < bytes; i++)
        {
            fprintf(fp, "%02X", (unsigned char)(d[i]));

            if ((i + 1) % 4 == 0)
            {
                fprintf(fp, " ");
            }


            if (d[i] == 127 || d[i] < -127 || (d[i] >= 0 && d[i] <= 31))
                d[i] = '.';
        }

        if (bytes < 16)
        {
            for(i = bytes; i < 16; i++)
            {
                fprintf(fp, "   ");
                if ((i + 1) % 4 == 0)
                {
                    fprintf(fp, " ");
                }
            }
            d[bytes] = '\0';
        }

        //fprintf(fp, "%s\n", d);
        left_len -= 16;
    }

    fclose(fp);
}

unsigned short udpchecksum(unsigned short *buffer, int size)
{
    unsigned long cksum=0;

    while (size > 1)
    {
        cksum += *buffer++;
        size  -= sizeof(unsigned short);
    }
    if (size)
    {
        cksum += *(unsigned char *)buffer;
    }
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >>16);

    return (unsigned short)(~cksum);
}

void CalculateCheckSum(
        void    *iphdr,
        struct udphdr *udphdr,
        char    *payload,
        int      payloadlen)
{
    struct iphdr  *v4hdr=NULL;
    unsigned long zero=0;
    char          buf[1000],
                  *ptr=NULL;
    int           chksumlen=0,                                                                           
                  i;                                                                                         

    ptr = buf;                                                                                           

    v4hdr = (struct iphdr *)iphdr;                                                                       

    // Include the source and destination IP addresses                                                   
    memcpy(ptr, &v4hdr->saddr,  sizeof(v4hdr->saddr));                                                   
    ptr += sizeof(v4hdr->saddr);                                                                         
    chksumlen += sizeof(v4hdr->saddr);                                                                   

    memcpy(ptr, &v4hdr->daddr, sizeof(v4hdr->daddr));                                                    
    ptr += sizeof(v4hdr->daddr);                                                                         
    chksumlen += sizeof(v4hdr->daddr);                                                                   

    // Include the 8 bit zero field                                                                      
    memcpy(ptr, &zero, 1);                                                                               
    ptr++;                                                                                               
    chksumlen += 1;                                                                                      

    // Protocol                                                                                          
    memcpy(ptr, &v4hdr->protocol, sizeof(v4hdr->protocol));                                              
    ptr += sizeof(v4hdr->protocol);                                                                      
    chksumlen += sizeof(v4hdr->protocol);                                                                

    // UDP length                                                                                        
    memcpy(ptr, &udphdr->len, sizeof(udphdr->len));                                                      
    ptr += sizeof(udphdr->len);                                                                          
    chksumlen += sizeof(udphdr->len);                                                                    

    // UDP source port                                                                                   
    memcpy(ptr, &udphdr->source, sizeof(udphdr->source));                                                
    ptr += sizeof(udphdr->source);                                                                       
    chksumlen += sizeof(udphdr->source);                                                                 

    // UDP destination port                                                                              
    memcpy(ptr, &udphdr->dest, sizeof(udphdr->dest));                                                    
    ptr += sizeof(udphdr->dest);                                                                         
    chksumlen += sizeof(udphdr->dest);                                                                   

    // UDP length again                                                                                  
    memcpy(ptr, &udphdr->len, sizeof(udphdr->len));                                                      
    ptr += sizeof(udphdr->len);                                                                          
    chksumlen += sizeof(udphdr->len);                                                                    

    // 16-bit UDP checksum, zero                                                                         
    memcpy(ptr, &zero, sizeof(unsigned short));                                                          
    ptr += sizeof(unsigned short);                                                                       
    chksumlen += sizeof(unsigned short);                                                                 

    // payload                                                                                           
    memcpy(ptr, payload, payloadlen);                                                                    
    ptr += payloadlen;                                                                                   
    chksumlen += payloadlen;                                                                             

    // pad to next 16-bit boundary                                                                       
    for(i=0 ; i < payloadlen%2 ; i++, ptr++)                                                             
    {                                                                                                    
        *ptr = 0;                                                                                        
        ptr++;                                                                                           
        chksumlen++;                                                                                     
    }                                                                                                    

    // Compute the checksum and put it in the UDP header                                                 
    udphdr->check = udpchecksum((unsigned short *)buf, chksumlen);                                          

    return;                                                                                              
}      

/**
 * Calculates a igned short)hecksum for a given header
 */
unsigned short checksum(unsigned short *buffer, int size)
{
    unsigned long cksum=0;
    while (size > 1)
    {
        cksum += * buffer++;
        size  -= 2;
    }
    if (size)
    {
        cksum += *buffer;
    }

    //while(cksum>>16){
    //     cksum = (cksum >> 16) + (cksum & 0xffff);
    //}

    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);

    return (unsigned short)(~cksum);
}

inline u_int16_t ip_fast_csum(const void *iph, unsigned int ihl) //calculate ip checksum
{
    unsigned int sum;
    __asm__ __volatile__(
            "movl (%1), %0 ;\n"
            "subl $4,   %2 ;\n"
            "jbe 2f        ;\n"
            "addl 4(%1), %0 ;\n"
            "adcl 8(%1), %0 ;\n"
            "adcl 12(%1),%0 ;\n"
            "1:     adcl 16(%1), %0 ;\n"
            "lea 4(%1), %1 ;\n"
            "decl %2        ;\n"
            "jne 1b        ;\n"
            "adcl $0, %0    ;\n"
            "movl %0, %2    ;\n"
            "shrl $16, %0   ;\n"
            "addw %w2, %w0 ;\n"
            "adcl $0, %0    ;\n"
            "notl %0        ;\n"
            "2:                     ;\n"
            : "=r" (sum), "=r" (iph), "=r" (ihl)
            : "1" (iph), "2" (ihl)
            : "memory");
    return sum;
}

/**
 * Builds an UDP/IP datagram
 */
void build_udp_ip_datagram(char* datagram, unsigned int payload_size, char* src_ip, char* dst_ip, u_int16_t port){

    struct ip *ip_hdr = (struct ip *) datagram;
    struct udphdr *udp_hdr = (struct udphdr *) (datagram + sizeof (struct ip));

    unsigned int iplen = sizeof(struct ip) + sizeof(struct udphdr) + payload_size;
    ip_hdr->ip_hl = 5; //header length
    ip_hdr->ip_v = 4; //version
    ip_hdr->ip_tos = 0; //tos
    ip_hdr->ip_len = htons(iplen);  //length
    ip_hdr->ip_id = 0; //id
    ip_hdr->ip_off = 0; //fragment offset
    ip_hdr->ip_ttl = 255; //ttl
    ip_hdr->ip_p = 17; //protocol
    ip_hdr->ip_sum = 0; //temp checksum
    ip_hdr->ip_src.s_addr = inet_addr (dst_ip); //src ip - spoofed
    ip_hdr->ip_dst.s_addr = inet_addr(src_ip); //dst ip

    udp_hdr->source = htons(53); //src port - spoofed
    udp_hdr->dest = htons(port); //dst port
    udp_hdr->len = htons(sizeof(struct udphdr) + payload_size); //length
    udp_hdr->check = 0; //checksum - disabled

    //CalculateCheckSum(ip_hdr, udp_hdr, datagram + sizeof(struct ip) + sizeof(struct udphdr), payload_size);
    //ip_hdr->ip_sum = checksum((unsigned short *) datagram, sizeof(struct iphdr));
    //printf("slow checksum %d\n", ip_hdr->ip_sum);
    //ip_hdr->ip_sum = 0;

    ip_hdr->ip_sum = ip_fast_csum((unsigned short *) datagram, ip_hdr->ip_hl);
    //printf("fast ip checksum %d\n", ip_hdr->ip_sum);

    //ip_hdr->ip_sum = 40680; //real checksum
    //printf("succ checksum %d\n", ip_hdr->ip_sum);

}

/**
 * Builds a DNS answer
 */
//unsigned int build_dns_answer(SpoofParams *spoof_params, struct dnshdr *dns_hdr, struct dnsquery *dns_query, char* answer, char* request){
unsigned int build_dns_answer(struct dnshdr *dns_hdr, char* answer, unsigned int domain_len) {

    unsigned int size = 0; /* answer size */
    //struct dnsquery *dns_query;
    unsigned char ans[4];
    unsigned char ans1[4];

    //sscanf(spoof_params->ip, "%d.%d.%d.%d",(int *)&ans[0],(int *)&ans[1], (int *)&ans[2], (int *)&ans[3]);
    sscanf("10.10.1.232", "%d.%d.%d.%d",(int *)&ans[0],(int *)&ans[1], (int *)&ans[2], (int *)&ans[3]);
    sscanf("10.10.1.231", "%d.%d.%d.%d",(int *)&ans1[0],(int *)&ans1[1], (int *)&ans1[2], (int *)&ans1[3]);

    char* qname  = ((char*) dns_hdr) + sizeof(struct dnshdr);
    //  struct dnsquery dns_query_clone;
    // printf("query doman %s \n", qname);
    //  dns_query_clone.qname = strdup(dns_query->qname); 
    //  dns_query_clone.qtype[0] = dns_query->qtype[0];
    //  dns_query_clone.qtype[1] = dns_query->qtype[1];
    //
    //  dns_query_clone.qclass[0]= dns_query->qclass[0];
    //  dns_query_clone.qclass[1]= dns_query->qclass[1];
    //dns_hdr
    memcpy(&answer[0], dns_hdr->id, 2); //id
    memcpy(&answer[2], "\x81\x80", 2); //flags
    memcpy(&answer[4], "\x00\x01", 2); //qdcount
    memcpy(&answer[6], "\x00\x02", 2); //ancount
    memcpy(&answer[8], "\x00\x00", 2); //nscount
    memcpy(&answer[10], "\x00\x00", 2); //arcount

    //dns_query
    //size = strlen(qname);
    size = domain_len;
    memcpy(&answer[12], qname, size); //qname
    //memcpy(&answer[12], "\x03\x77\x77\x77\x02\x71\x71\x03\x63\x6f\x6d\x00", size); //qname

    size+=12;
    memcpy(&answer[size], "\x00\x01", 2); //type
    size+=2;
    memcpy(&answer[size], "\x00\x01", 2); //class
    size+=2;

    //dns_answer
    memcpy(&answer[size], "\xc0\x0c", 2); //pointer to qname
    size+=2;
    memcpy(&answer[size], "\x00\x01", 2); //type
    size+=2;
    memcpy(&answer[size], "\x00\x01", 2); //class
    size+=2;
    memcpy(&answer[size], "\x00\x00\x00\x22", 4); //ttl - 34s
    size+=4;
    memcpy(&answer[size], "\x00\x04", 2); //rdata length
    size+=2;
    memcpy(&answer[size], ans, 4); //rdata
    size+=4;

    memcpy(&answer[size], "\xc0\x0c", 2); //pointer to qname
    size+=2;
    memcpy(&answer[size], "\x00\x01", 2); //type
    size+=2;
    memcpy(&answer[size], "\x00\x01", 2); //class
    size+=2;
    memcpy(&answer[size], "\x00\x00\x00\x22", 4); //ttl - 34s
    size+=4;
    memcpy(&answer[size], "\x00\x04", 2); //rdata length
    size+=2;
    memcpy(&answer[size], ans1, 4); //rdata
    size+=4;

    answer[size]='\0';
    return size;

}

/**
 * Extracts the request from a dns query
 * It comes in this format: [3]www[7]example[3]com[0]
 * And it is returned in this: www.example.com
 */
unsigned int  extract_dns_request(struct dnsquery *dns_query, char *request){
    unsigned int i, j, k;
    char *curr = dns_query->qname;
    unsigned int size;
    if(curr==NULL)
        return 1;

    size = curr[0];
    j=0;
    i=1;
   
    while(size > 0){
        //D("%u size j %d u %u", size, j, i );
        for(k=0; k<size; k++){
            if(j>=100)
                return 1;
            request[j++] = curr[i+k];
        }
        request[j++]='.';
        i+=size;
        size = curr[i++];
    }
    //D("%u  i j %u ", i, j);
    if (j>=1)
       request[--j] = '\0';
    
    return i;

}

/**
 * Extracts the src port from a udp header
 */
void extract_port_from_udphdr(struct udphdr* udp, u_int16_t* port){
    (*port) = ntohs((*(u_int16_t*)udp));
}

/**
 * Extracts an ip from a ip header
 */
void extract_ip_from_iphdr(u_int32_t raw_ip, char* ip){
    int i;
    int aux[4];

    for(i=0;i<4;i++){
        aux[i] = (raw_ip >> (i*8)) & 0xff;
    }

    sprintf(ip, "%d.%d.%d.%d",aux[0], aux[1], aux[2], aux[3]);
}

/**
 * Extracts DNS query and ip from packet
 */
void extract_dns_data(const u_char *packet, struct dnshdr **dns_hdr, struct dnsquery *dns_query, char* src_ip, char* dst_ip, u_int16_t *port){
    struct etherhdr *ether;
    struct iphdr *ip;
    struct udphdr *udp;
    unsigned int ip_header_size;

    /* ethernet header */
    ether = (struct etherhdr*)(packet);

    /* ip header */
    ip = (struct iphdr*)(((char*) ether) + sizeof(struct etherhdr));
    extract_ip_from_iphdr(ip->saddr, src_ip);
    extract_ip_from_iphdr(ip->daddr, dst_ip);

    /* udp header */
    ip_header_size = ip->ihl*4;
    udp = (struct udphdr *)(((char*) ip) + ip_header_size);
    extract_port_from_udphdr(udp, port);

    /* dns header */
    *dns_hdr = (struct dnshdr*)(((char*) udp) + sizeof(struct udphdr));

    dns_query->qname = ((char*) *dns_hdr) + sizeof(struct dnshdr);

}

/**
 * Parse arguments
 */

int answer_dns_query(char *buff, int n){
    //SpoofParams spoof_params;
    // 
    // strncpy(spoof_params.interface, "netmap:eth5", PCAP_INTERFACENAME_SIZE-1);
    // spoof_params.interface[PCAP_INTERFACENAME_SIZE-1] = '\0';

    //strncpy(spoof_params.request, "www.qq.com", REQUEST_SIZE-1);
    //spoof_params.request[REQUEST_SIZE-1] = '\0';

    //strncpy(spoof_params.ip, "10.10.1.232", IP_SIZE-1);
    //spoof_params.ip[IP_SIZE-1] = '\0';

    struct dnsquery dns_query;
    struct dnshdr *dns_hdr;

    char request[REQUEST_SIZE]= {0};
    
    char src_ip[IP_SIZE], dst_ip[IP_SIZE];
    u_int16_t port;

    char* answer;
    unsigned int datagram_size; 

    //dump_hex_file(buff, n);
    extract_dns_data((const u_char*) buff, &dns_hdr, &dns_query, src_ip, dst_ip, &port);
    if (dns_hdr == NULL){
        return 1;
    }
    unsigned int domain_len = extract_dns_request(&dns_query, request);
    if(domain_len==1){
        return -1;
    }
    if (verbose)
        D("domain name %s", request); 
    /* if it is the request that we are looking for */
    //if(!strcmp(request, spoof_params.request))
    {

        // change Ethnet header
        {
            unsigned char mac_temp[ETH_ALEN] = {0};
            struct ethhdr *eh = (struct ethhdr *)buff;
            //struct ethhdr *hdr = (struct ethhdr *)buff;
            // D("proto = 0x%x, dst= %X:%X:%X:%X:%X:%X\n", ntohs(
            // 				  hdr->h_proto),
            //   hdr->h_dest[0], hdr->h_dest[1],
            //   hdr->h_dest[2],
            //   hdr->h_dest[3], hdr->h_dest[4],
            //   hdr->h_dest[5]);

            // D("proto = 0x%x, src= %X:%X:%X:%X:%X:%X\n", ntohs(
            // 				  hdr->h_proto),
            //   hdr->h_source[0], hdr->h_source[1],
            //   hdr->h_source[2],
            //   hdr->h_source[3], hdr->h_source[4],
            //   hdr->h_source[5]);

            memcpy(mac_temp,eh->h_dest,ETH_ALEN);
            memcpy(eh->h_dest, eh->h_source, ETH_ALEN);
            //memcpy(eh->h_dest, "e4:68:a3:87:46:d9", ETH_ALEN);
            memcpy(eh->h_source, mac_temp, ETH_ALEN);

            //        unsigned char ans[6];
            //sscanf("E4:68:A3:87:46:D9", "%2X:%2x:%2x:%2x:%2x:%2x",
            //sscanf("E4:68:A3:87:46:D8", "%2X:%2x:%2x:%2x:%2x:%2x",
            //        sscanf("0C:C4:7A:47:DE:25", "%2X:%2x:%2x:%2x:%2x:%2x",
            //		   (int *)&ans[0],(int *) &ans[1], 
            //		   (int *)&ans[2], (int *)&ans[3],
            //		   (int *)&ans[4], (int *)&ans[5]);
            // 
            //	memcpy(eh->h_dest, ans, ETH_ALEN);
            //        D("proto = 0x%x, dst= %X:%X:%X:%X:%X:%X\n", ntohs(
            //					  eh->h_proto),
            //	  eh->h_dest[0], eh->h_dest[1],
            //          eh->h_dest[2],
            //          eh->h_dest[3], eh->h_dest[4],
            //          eh->h_dest[5]);
            //        D("proto = 0x%x, src= %X:%X:%X:%X:%X:%X\n", ntohs(
            //					  eh->h_proto),
            //	  eh->h_source[0], eh->h_source[1],
            //          eh->h_source[2],
            //          eh->h_source[3], eh->h_source[4],
            //          eh->h_source[5]);
            //

            //	D("mac len %d", ETH_ALEN);
        }


        /* answer is pointed to the beginning of dns header */

        answer = buff + sizeof(struct ethhdr) + sizeof(struct ip) + sizeof(struct udphdr);

        /* modifies answer to attend our dns spoof and returns its size */
        //datagram_size = build_dns_answer(&spoof_params, dns_hdr, &dns_query, answer, request);
        //datagram_size = build_dns_answer(&spoof_params, dns_hdr, answer, request);
        datagram_size = build_dns_answer(dns_hdr, answer, domain_len);

        /* modifies udp/ip to attend our dns spoof */
        build_udp_ip_datagram(buff + sizeof(struct ethhdr), datagram_size, src_ip, dst_ip, port);

        /* update the datagram size with ip and udp header */
        datagram_size += sizeof(struct ethhdr) + (sizeof(struct ip) + sizeof(struct udphdr));

        //dump_hex_file(buff, datagram_size);
        if(((unsigned int)n) != datagram_size){
            //printf("n != datagram_size %d %d \n", n, datagram_size);
        }
    }
    //else{
    //printf("wrong domain request %s\n", request);
    //}

    return datagram_size;

}

static int do_abort = 0;
static int zerocopy = 1; /* enable zerocopy if possible */

    static void
sigint_h(int sig)
{
    (void)sig;	/* UNUSED */
    do_abort = 1;
    signal(SIGINT, SIG_DFL);
}

struct pesudo_udphdr { 
    unsigned int saddr, daddr; 
    unsigned char unused; 
    unsigned char protocol; 
    unsigned short udplen; 
}; 

unsigned short in_cksum(unsigned short *addr, int len) 
{ 
    int sum=0; 
    unsigned short res=0; 
    while( len > 1)  { 
        sum += *addr++; 
        len -=2; 
    } 
    if( len == 1) { 
        *((unsigned char *)(&res))=*((unsigned char *)addr); 
        sum += res; 
    } 
    sum = (sum >>16) + (sum & 0xffff); 
    sum += (sum >>16) ; 
    res = ~sum; 
    return res; 
}

int is_dns_query(char *buff, int len)
{
    struct ethhdr *eh;
    struct iphdr *ip;
    struct udphdr *udp;

    char *ip_buff = buff + 14;

    eh = (struct ethhdr*)buff;
    ip = (struct iphdr*) (ip_buff);
    udp = (struct udphdr *) (ip_buff + sizeof(struct iphdr));

    if (eh->h_proto != ntohs(0x0800))
    {
        return 1;
    }

    if (ip->protocol != IPPROTO_UDP )
    {
        return 2;
    }

    if (udp->dest != ntohs(53))
    {
        return 3;
    }

    char *p = (ip_buff ) + 12;               
    if (verbose >= 1)
    {
        D("recv:%d, IP:%d.%d.%d.%d:%d => %d.%d.%d.%d:%d\n", len,
                p[0]&0XFF,p[1]&0XFF,p[2]&0XFF,p[3]&0XFF, htons(udp->dest),
                p[4]&0XFF,p[5]&0XFF,p[6]&0XFF,p[7]&0XFF, htons(udp->source)); 
    }

    return 0;
}

int echo_dns_query(char *buff, int n)
{
    u_int32_t tmpaddr;
    u_int16_t tmpport;
    char check_buf[512] = {0};

    char *ip_buff = buff + 14;

    struct iphdr* ip = (struct iphdr*)ip_buff; 
    struct udphdr * udp = (struct udphdr*) (ip_buff + sizeof(struct iphdr ));
    char *query = (char *)( ip_buff + sizeof(struct iphdr ) + sizeof(struct udphdr));

    //chage DNS query flag 
    query[2] |= 0x80;

    //Change ip header
    tmpaddr = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = tmpaddr;
    ip->check = 0;
    ip->check = in_cksum((unsigned short *)ip_buff, sizeof(struct iphdr));  

    // change UDP header
    tmpport = udp->source;
    udp->source = udp->dest;
    udp->dest = tmpport;
    udp->check = 0;

    {
        int udp_len = n - sizeof(struct iphdr ) - 14;

        memset(check_buf, 0x0, 512);
        memcpy(check_buf + sizeof(struct pesudo_udphdr), (char*)udp, udp_len);
        struct pesudo_udphdr * pudph = (struct pesudo_udphdr *)check_buf;

        pudph->saddr = ip->saddr ; 
        pudph->daddr = ip->daddr; 
        pudph->unused=0; 
        pudph->protocol=IPPROTO_UDP; 
        pudph->udplen=htons(udp_len);

        udp->check = in_cksum((unsigned short *)check_buf, 
                udp_len +  sizeof(struct pesudo_udphdr) );
    }

    // change Ethnet header
    {
        unsigned char mac_temp[ETH_ALEN]={0};
        struct ethhdr *eh = (struct ethhdr *)buff;

        memcpy(mac_temp,eh->h_dest,ETH_ALEN);
        memcpy(eh->h_dest, eh->h_source, ETH_ALEN);
        memcpy(eh->h_source, mac_temp, ETH_ALEN);
    }

    return 0;
}

int dns_packet_process(char *buff, int len)
{
    //if(len >256)
    //    return 1;

    //echo_dns_query(buff, len);
    //return len;

    return answer_dns_query(buff, len);
}



/*
 * how many packets on this set of queues ?
 */
    int
pkt_queued(struct nm_desc *d, int tx)
{
    u_int i, tot = 0;

    if (tx) {
        for (i = d->first_tx_ring; i <= d->last_tx_ring; i++) {
            tot += nm_ring_space(NETMAP_TXRING(d->nifp, i));
        }
    } else {
        for (i = d->first_rx_ring; i <= d->last_rx_ring; i++) {
            tot += nm_ring_space(NETMAP_RXRING(d->nifp, i));
        }
    }
    return tot;
}

/*
 * move up to 'limit' pkts from rxring to txring swapping buffers.
 */
    static int
process_rings(struct netmap_ring *rxring, struct netmap_ring *txring,
        u_int limit, const char *msg, int modify)
{
    u_int j, k, m = 0;

    /* print a warning if any of the ring flags is set (e.g. NM_REINIT) */
    //if (rxring->flags || txring->flags)
    //		D("%s rxflags %x txflags %x",
    //			msg, rxring->flags, txring->flags);
    j = rxring->cur; /* RX */
    k = txring->cur; /* TX */
    m = nm_ring_space(rxring);
    if (m < limit)
        limit = m;
    m = nm_ring_space(txring);
    if (m < limit)
        limit = m;
    m = limit;

    modify = 0;

    while (limit-- > 0) {
        struct netmap_slot *rs = &rxring->slot[j];
        struct netmap_slot *ts = &txring->slot[k];
        char *rxbuf = NETMAP_BUF(rxring, rs->buf_idx);

        int ret = is_dns_query(rxbuf, rs->len);
        if(ret){ 
            j = nm_ring_next(rxring, j);
            k = nm_ring_next(txring, k);
            continue;
        }

        if (verbose >= 1) D("echo: rx[%d] is DNS query", j);
        int send_len = dns_packet_process(rxbuf, rxring->slot[j].len);
        if(send_len == -1){
            j = nm_ring_next(rxring, j);
            k = nm_ring_next(txring, k);
            continue;
        }

        /* swap packets */
        if (ts->buf_idx < 2 || rs->buf_idx < 2) {
            D("wrong index rx[%d] = %d  -> tx[%d] = %d",
                    j, rs->buf_idx, k, ts->buf_idx);
            sleep(2);
        }
        /* copy the packet length. */
        if (rs->len > 2048) {
            D("wrong len %d rx[%d] -> tx[%d]", rs->len, j, k);
            rs->len = 0;
        } else if (verbose >= 1) {
            D("%s send len %d rx[%d] -> tx[%d]", msg, rs->len, j, k);
        }
        //ts->len = rs->len;
        ts->len = send_len;
        if (zerocopy) {
            //D("enter zerocopy");
            uint32_t pkt = ts->buf_idx;
            ts->buf_idx = rs->buf_idx;
            rs->buf_idx = pkt;
            /* report the buffer change. */
            ts->flags |= NS_BUF_CHANGED;
            rs->flags |= NS_BUF_CHANGED;
        } else {
            D("enter none zerocopy");
            //char *rxbuf = NETMAP_BUF(rxring, rs->buf_idx);
            char *txbuf = NETMAP_BUF(txring, ts->buf_idx);
            nm_pkt_copy(rxbuf, txbuf, ts->len);
        }
        j = nm_ring_next(rxring, j);
        k = nm_ring_next(txring, k);
    }
    rxring->head = rxring->cur = j;
    txring->head = txring->cur = k;
    if (verbose && m > 0)
        D("%s sent %d packets to %p", msg, m, txring);

    return (m);
}

/* move packts from src to destination */
    static int
move(struct nm_desc *src, struct nm_desc *dst, u_int limit, int modify)
{
    struct netmap_ring *txring, *rxring;
    u_int m = 0, si = src->first_rx_ring, di = dst->first_tx_ring;
    const char *msg = (src->req.nr_ringid & NETMAP_SW_RING) ?
        "host->net" : "net->host";

    while (si <= src->last_rx_ring && di <= dst->last_tx_ring) {
        rxring = NETMAP_RXRING(src->nifp, si);
        txring = NETMAP_TXRING(dst->nifp, di);
        ND("txring %p rxring %p", txring, rxring);
        if (nm_ring_empty(rxring)) {
            si++;
            continue;
        }
        if (nm_ring_empty(txring)) {
            di++;
            continue;
        }
        m += process_rings(rxring, txring, limit, msg, modify);
    }

    return (m);
}

static void *thread_main(void *arg){

    u_int burst = 1024 ;
    thread_info *info = (thread_info *)arg;

    struct nm_desc *pa = NULL, *pb = NULL;
    struct pollfd pollfd[2];
    /* setup poll(2) variables. */
    memset(pollfd, 0, sizeof(pollfd));

    pa = info->nm_receiver;
    pb = info->nm_sender;
    pollfd[0].fd = pa->fd;
    pollfd[1].fd = pb->fd;

    D("enter thread main %d input %d output %d ", info->thread_id, pa->fd, pb->fd);
    int  thread_id = info->thread_id;
    int n0=0; 
    int ret=0;
    //long count=0;
    while (!do_abort) {

        pollfd[0].events = pollfd[1].events = 0;
        pollfd[0].revents = pollfd[1].revents = 0;

        if (n0)
            pollfd[1].events |= POLLOUT;
        else
            pollfd[0].events |= POLLIN;

        ret = poll(pollfd, 2, 25000);
        if (ret <= 0 || verbose)
            D("poll thread %d %s [0] ev %x %x rx %d@%d tx %d,"
                    " [1] ev %x %x rx %d@%d tx %d",thread_id,
                    ret <= 0 ? "timeout" : "ok",
                    pollfd[0].events,
                    pollfd[0].revents,
                    pkt_queued(pa, 0),
                    NETMAP_RXRING(pa->nifp, pa->cur_rx_ring)->cur,
                    pkt_queued(pa, 1),
                    pollfd[1].events,
                    pollfd[1].revents,
                    pkt_queued(pb, 0),
                    NETMAP_RXRING(pb->nifp, pb->cur_rx_ring)->cur,
                    pkt_queued(pb, 1)
             );

        if (ret < 0)
            continue;

        if(pollfd[0].revents & POLLERR) {
            struct netmap_ring *rx = NETMAP_RXRING(pa->nifp, pa->cur_rx_ring);
            D("error on fd0, rx [%d,%d,%d)",
                    rx->head, rx->cur, rx->tail);
            continue;
        }
        if (pollfd[1].revents & POLLERR) {
            struct netmap_ring *rx = NETMAP_RXRING(pb->nifp, pb->cur_rx_ring);
            D("error on fd1, rx [%d,%d,%d)",
                    rx->head, rx->cur, rx->tail);
            continue;
        }
        if (pollfd[0].revents & POLLIN) {
            //D("enter fd 0 for receive %ld ", count);
            n0=1; 
            continue;
        }

        if (pollfd[1].revents & POLLOUT) {
            //count++;
            //D("enter fd 1 for receive thread %d ", thread_id);
            move(pa, pb, burst, 1);
            n0=0; 
        }
    }

    D("exiting");
    nm_close(pb);
    nm_close(pa);
    free(info);

    return (0);
}


static void
usage(void)
{
    fprintf(stderr,
            "usage: dns-resp [-v] [-c] [-i ifa] [-i ifb] [-b burst] [-w wait_time] \n\n");
    fprintf(stderr,
              "Supported options:\n"
              "  -v  if run with debug default close.\n"
              "  -c  if used zerocopy default open.\n"
              "  -i  Specify intput or output nic name for netmap.\n"
              "  -b  max-packet in netmap ring default 1024 .\n"
              "  -w  wait time in seconds default 4.\n\n"
              );
    fprintf(stderr, "Example:\n");
    fprintf(stderr, "  ./dns-resp -i netmap:eth4 -i netmap:eth5 \n\n");     

    exit(1);
}

int
main(int argc, char **argv)
{
    struct pollfd pollfd[2];
    int ch;
    u_int burst = 1024, wait_link = 4;
    struct nm_desc *pa = NULL, *pb = NULL;
    char *ifa = NULL, *ifb = NULL;
    char ifabuf[64] = { 0 };

    fprintf(stderr, "%s built %s %s\n",
            argv[0], __DATE__, __TIME__);

    while ( (ch = getopt(argc, argv, "b:ci:vw:")) != -1) {
        switch (ch) {
            default:
                D("bad option %c %s", ch, optarg);
                usage();
                break;
            case 'b':	/* burst */
                burst = atoi(optarg);
                break;
            case 'i':	/* interface */
                if (ifa == NULL)
                    ifa = optarg;
                else if (ifb == NULL)
                    ifb = optarg;
                else
                    D("%s ignored, already have 2 interfaces",
                            optarg);
                break;
            case 'c':
                zerocopy = 0; /* do not zerocopy */
                break;
            case 'v':
                verbose++;
                break;
            case 'w':
                wait_link = atoi(optarg);
                break;
        }

    }

    argc -= optind;
    argv += optind;

    if (argc > 1)
        ifa = argv[1];
    if (argc > 2)
        ifb = argv[2];
    if (argc > 3)
        burst = atoi(argv[3]);
    if (!ifb)
        ifb = ifa;
    if (!ifa) {
        D("missing interface");
        usage();
    }
    if (burst < 1 || burst > 8192) {
        D("invalid burst %d, set to 1024", burst);
        burst = 1024;
    }
    if (wait_link > 100) {
        D("invalid wait_link %d, set to 4", wait_link);
        wait_link = 4;
    }
    if (!strcmp(ifa, ifb)) {
        D("same interface, endpoint 0 goes to host");
        snprintf(ifabuf, sizeof(ifabuf) - 1, "%s^", ifa);
        D("ifa ifb ifabuf %s %s %s ", ifa, ifb, ifabuf);
        ifa = ifabuf;
    } else {
        /* two different interfaces. Take all rings on if1 */
    }
    pa = nm_open(ifa, NULL, 0, NULL);
    if (pa == NULL) {
        D("cannot open %s", ifa);
        return (1);
    }
    // XXX use a single mmap ?
    pb = nm_open(ifb, NULL, NM_OPEN_NO_MMAP, pa);
    if (pb == NULL) {
        D("cannot open %s", ifb);
        nm_close(pa);
        return (1);
    }

    signal(SIGINT, sigint_h);

    zerocopy = zerocopy && (pa->mem == pb->mem);
    D("------- zerocopy %ssupported", zerocopy ? "" : "NOT ");

    /* setup poll(2) variables. */
    memset(pollfd, 0, sizeof(pollfd));
    pollfd[0].fd = pa->fd;
    pollfd[1].fd = pb->fd;

    D("Wait %d secs for link to come up...", wait_link);
    sleep(wait_link);
    D("Ready to go, %s 0x%x/%d <-> %s 0x%x/%d.",
            pa->req.nr_name, pa->first_rx_ring, pa->req.nr_rx_rings,
            pb->req.nr_name, pb->first_rx_ring, pb->req.nr_rx_rings);

    u_int num_cpus = 8;
    if (num_cpus > pa->req.nr_rx_rings) {
        num_cpus = pa->req.nr_rx_rings;
    }

    if (num_cpus > pb->req.nr_rx_rings) {
        num_cpus = pb->req.nr_rx_rings;
    }

    D("Ooops, num cpus is %d", num_cpus);
    pthread_t thread_worker[8];
    memset(thread_worker, 0, sizeof(pthread_t));
    u_int j=0,i=0;
    for (i = 0; i < num_cpus; i++) {
        struct nm_desc in_nmd = *pa;
        in_nmd.self = &in_nmd;
        uint64_t innmd_flags = 0;

        if (in_nmd.req.nr_flags != NR_REG_ALL_NIC) {
            D("Ooops, main descriptor should be with NR_REG_ALL_NIC flag");
        }

        in_nmd.req.nr_flags = NR_REG_ONE_NIC;
        in_nmd.req.nr_ringid = i;

        /* Only touch one of the rings (rx is already ok) */
        //innmd_flags |= NETMAP_NO_TX_POLL;

        struct nm_desc* inone_nmd =
            nm_open(ifa, NULL, innmd_flags | NM_OPEN_IFNAME | NM_OPEN_NO_MMAP, &in_nmd);

        if (inone_nmd == NULL) {
            D("Can't open netmap descriptor for netmap per hardware queue thread");
            exit(1);
        }

        D("in My first ring is %d and last ring id is %d I'm thread %d",
                inone_nmd->first_rx_ring, inone_nmd->last_rx_ring, i);

        struct nm_desc out_nmd = *pb;
        out_nmd.self = &out_nmd;
        uint64_t outnmd_flags = 0;

        if (out_nmd.req.nr_flags != NR_REG_ALL_NIC) {
            D("Ooops, out descriptor should be with NR_REG_ALL_NIC flag");
        }

        out_nmd.req.nr_flags = NR_REG_ONE_NIC;
        out_nmd.req.nr_ringid = i;

        /* Only touch one of the rings (rx is already ok) */
        outnmd_flags = NM_OPEN_IFNAME | NM_OPEN_NO_MMAP;
        struct nm_desc* outone_nmd =
            nm_open(ifb, NULL, outnmd_flags,  &out_nmd);

        if (outone_nmd == NULL) {
            D("Can't open netmap descriptor for netmap per hardware queue thread");
            exit(1);
        }

        D("out My first ring is %d and last ring id is %d I'm thread %d",
                outone_nmd->first_rx_ring, outone_nmd->last_rx_ring, i);


        D("Start new netmap thread %d", i);

        thread_info *tinfo =malloc(sizeof(thread_info));
        tinfo->thread_id = i;
        tinfo->nm_receiver= inone_nmd;
        tinfo->nm_sender= outone_nmd;

        pthread_t tid;
        if (pthread_create(&tid,NULL,&thread_main,(void*)tinfo) != 0){
            fprintf(stderr,"thread create failed\n");
            exit(1);
        }

        thread_worker[i] = tid;

    }

    for(j=0;j<num_cpus;j++){
        pthread_join(thread_worker[j],NULL);
    }

    /* main loop */

    //	int n0=0; 
    //	int ret=0;
    //	long count=0;
    //
    //	while (!do_abort) {
    //
    //		pollfd[0].events = pollfd[1].events = 0;
    //		pollfd[0].revents = pollfd[1].revents = 0;
    //
    //		if (n0)
    //			pollfd[1].events |= POLLOUT;
    //		else
    //			pollfd[0].events |= POLLIN;
    //
    //		ret = poll(pollfd, 2, 2500);
    //		if (ret <= 0 || verbose)
    //		    D("poll %s [0] ev %x %x rx %d@%d tx %d,"
    //			     " [1] ev %x %x rx %d@%d tx %d",
    //				ret <= 0 ? "timeout" : "ok",
    //				pollfd[0].events,
    //				pollfd[0].revents,
    //				pkt_queued(pa, 0),
    //				NETMAP_RXRING(pa->nifp, pa->cur_rx_ring)->cur,
    //				pkt_queued(pa, 1),
    //				pollfd[1].events,
    //				pollfd[1].revents,
    //				pkt_queued(pb, 0),
    //				NETMAP_RXRING(pb->nifp, pb->cur_rx_ring)->cur,
    //				pkt_queued(pb, 1)
    //			);
    //
    //		if (ret < 0)
    //			continue;
    //
    //		if(pollfd[0].revents & POLLERR) {
    //			struct netmap_ring *rx = NETMAP_RXRING(pa->nifp, pa->cur_rx_ring);
    //			D("error on fd0, rx [%d,%d,%d)",
    //				rx->head, rx->cur, rx->tail);
    //			continue;
    //		}
    //		if (pollfd[1].revents & POLLERR) {
    //			struct netmap_ring *rx = NETMAP_RXRING(pb->nifp, pb->cur_rx_ring);
    //			D("error on fd1, rx [%d,%d,%d)",
    //				rx->head, rx->cur, rx->tail);
    //			continue;
    //		}
    //		if (pollfd[0].revents & POLLIN) {
    //                        D("enter fd 0 for receive %ld ", count);
    //	                n0=1; 
    //			continue;
    //		}
    //
    //		if (pollfd[1].revents & POLLOUT) {
    //		        count++;
    //                        D("enter fd 1 for receive %ld ", count);
    //			move(pa, pb, burst, 1);
    //	                n0=0; 
    //		}
    //	}
    //
    D("exiting");
    nm_close(pb);
    nm_close(pa);

    return (0);
}

