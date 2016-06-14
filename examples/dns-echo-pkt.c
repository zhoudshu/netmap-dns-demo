/*
 * (C) 2011-2014 Luigi Rizzo, Matteo Landi
 *
 * BSD license
 *
 * A netmap client to bridge two network interfaces
 * (or one interface and the host stack).
 *
 * $FreeBSD: head/tools/tools/netmap/bridge.c 228975 2011-12-30 00:04:11Z uqs $
 */

#include <stdio.h>
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

//zfar debug
#include <time.h> //time()

int verbose = 2;

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
	if (verbose > 1)
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
	echo_dns_query(buff, len);
	return 0;
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
 * ===  FUNCTION  ======================================================================
 *         Name:  dump_hex
 *  Description:  
 * =====================================================================================
 */

void dump_hex_file(char * str, int len)
{
    char buf[100];
    snprintf(buf, 100, "/tmp/hrs_packet_dump_%ld.hrs", time(NULL));
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

        fprintf(fp, "%08X\t", index);

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

        fprintf(fp, "%s\n", d);
        left_len -= 16;
    }

    fclose(fp);
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
	if (rxring->flags || txring->flags)
		D("%s rxflags %x txflags %x",
			msg, rxring->flags, txring->flags);
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
dump_hex_file(rxbuf, rs->len);
                int ret = is_dns_query(rxbuf, rs->len);
                if(ret){ 
		    j = nm_ring_next(rxring, j);
		    k = nm_ring_next(txring, k);
                    continue;
                }

      	        if (verbose > 1) D("echo: rx[%d] is DNS query", j);
	        dns_packet_process(rxbuf, rxring->slot[j].len);
	
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
		} else if (verbose > 1) {
			D("%s send len %d rx[%d] -> tx[%d]", msg, rs->len, j, k);
		}
		ts->len = rs->len;
		if (zerocopy) {
                        D("enter zerocopy");
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


static void
usage(void)
{
	fprintf(stderr,
	    "usage: dns-echo [-v] [-i ifa] [-i ifb] [-b burst] [-w wait_time] [iface]\n");
	exit(1);
}

/*
 * bridge [-v] if1 [if2]
 *
 * If only one name, or the two interfaces are the same,
 * bridges userland and the adapter. Otherwise bridge
 * two intefaces.
 */
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

	/* main loop */
	signal(SIGINT, sigint_h);
        int count = 0;
	while (!do_abort) {
		int n0, n1, ret;
		pollfd[0].events = pollfd[1].events = 0;
		pollfd[0].revents = pollfd[1].revents = 0;
		n0 = pkt_queued(pa, 0);
		n1 = pkt_queued(pb, 0);
#if defined(_WIN32) || defined(BUSYWAIT)
		if (n0){
			ioctl(pollfd[1].fd, NIOCTXSYNC, NULL);
			pollfd[1].revents = POLLOUT;
		}
		else {
			ioctl(pollfd[0].fd, NIOCRXSYNC, NULL);
		}
		if (n1){
			ioctl(pollfd[0].fd, NIOCTXSYNC, NULL);
			pollfd[0].revents = POLLOUT;
		}
		else {
			ioctl(pollfd[1].fd, NIOCRXSYNC, NULL);
		}
		ret = 1;
#else
                D("no n1 %d %d", n0, n1);
		if (n0)
			pollfd[1].events |= POLLOUT;
		else
			pollfd[0].events |= POLLIN;
		if (n1)
			pollfd[0].events |= POLLOUT;
		else
			pollfd[1].events |= POLLIN;
		ret = poll(pollfd, 2, 2500);
#endif //defined(_WIN32) || defined(BUSYWAIT)
		if (ret <= 0 || verbose)
		    D("poll %s [0] ev %x %x rx %d@%d tx %d,"
			     " [1] ev %x %x rx %d@%d tx %d",
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
		}
		if (pollfd[1].revents & POLLERR) {
			struct netmap_ring *rx = NETMAP_RXRING(pb->nifp, pb->cur_rx_ring);
			D("error on fd1, rx [%d,%d,%d)",
				rx->head, rx->cur, rx->tail);
		}
//		if (pollfd[0].revents & POLLOUT) {
//                    D("enter fd 0 for receive %d ", count);
//		
//                        count++;
//                        //D("enter fd 0 for receive %d ", count);
//                       	move(pb, pa, burst, 1);
//			// XXX we don't need the ioctl */
//			// ioctl(me[0].fd, NIOCT
//		}

   	      if (pollfd[0].revents & POLLOUT)
	      {
                D("enter fd 0 for receive %d ", count);
                u_int si, di;		
		si = pa->first_tx_ring;
		di = pb->first_rx_ring;
		struct netmap_ring *txring, *rxring;
		while(si <= pa->last_tx_ring && di <= pb->last_rx_ring)
		{
		    txring = NETMAP_TXRING(pa->nifp, si);
		    rxring = NETMAP_RXRING(pb->nifp, di);

		    if ( nm_ring_empty(rxring) )
		    {
			++si;
			continue;
		    }

		    if ( nm_ring_empty(txring) )
		    {
			++di;
			continue;
		    }

		    txring->head=txring->cur=txring->tail;
		    rxring->head=rxring->cur=rxring->tail;
		}

	        }

		if (pollfd[1].revents & POLLOUT) {
                        count++;
                        D("enter fd 1 for receive %d ", count);
			move(pa, pb, burst, 1);
			// XXX we don't need the ioctl */
			// ioctl(me[1].fd, NIOCTXSYNC, NULL);
		}
	}
	D("exiting");
	nm_close(pb);
	nm_close(pa);

	return (0);
}

