#include <stdio.h>
#include <pcap.h>
#include <net/if.h>
#include <stdlib.h>
#include <sys/types.h>          /* See NOTES */
#include <netinet/ip.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>


#define MY_DEST_MAC0	0x10
#define MY_DEST_MAC1	0xbf
#define MY_DEST_MAC2	0x48
#define MY_DEST_MAC3	0x29
#define MY_DEST_MAC4	0x16
#define MY_DEST_MAC5	0x6E

typedef struct ip_addr	{
	unsigned char one;
	unsigned char two;
	unsigned char three;
	unsigned char four;
}Ip_addr;

int rawFile;
int sockfd;
//structure pour découper l'adresse IP et mask
void affichage_ip(bpf_u_int32 net, bpf_u_int32 mask);
void callback(u_char *user,const struct pcap_pkthdr *h, const u_char *buff);
unsigned short in_cksum(unsigned short *addr, int len);
void fin_de_programme();

char *interface;

int main(int argc, char **argv)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32 net, mask;
	char *filtre = "ip";
	pcap_t *desc;

	//Installing a signal handler to close the rawFile on interrupt
	signal(SIGINT, fin_de_programme);


	// Find the default network interface
	interface = pcap_lookupdev(errbuf);
	if (interface == NULL)
	{
		fprintf(stderr, "Couldn't find default device : %s\n", errbuf);
		exit(-1);
	}
	printf("Interface : %s\n", interface);


	// Opening the interface
	if((desc=pcap_open_live(interface,1514,IFF_PROMISC,1000,errbuf))==NULL) {
		fprintf(stderr,"unable to open descriptor : %s\n",errbuf);
		exit(-1);
	}

	// Get the IP and Mask of the interface
	if(pcap_lookupnet(interface, &net, &mask, errbuf) == -1)
	{
		fprintf(stderr,"unable to lookup : %s\n", errbuf);
		return(-1);
	}

	// Display IP and mask
	affichage_ip(net, mask);

	struct bpf_program fp;

	//Compiling the filter string to a filter program.
	if(pcap_compile(desc, &fp,filtre,0x100,mask)==-1) {
		fprintf(stderr,"error compiling filter : %s\n",pcap_geterr(desc));
		exit(-1);
	}

	//Applying the filter to the sniffed interface
	if(pcap_setfilter(desc,&fp)<0) {
	   fprintf(stderr,"unable to apply filter : %s\n",pcap_geterr(desc));
	   exit(-1);
	}

	//Opening the rawFile to save each pack. Futher use : open it with wireshark
	if ((rawFile=open("./rawFile", O_CREAT|O_TRUNC|O_RDWR)) == -1){
		perror("open");
		exit(-1);
	}

	// Open output socket
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1) {
		perror("socket");
		exit(EXIT_FAILURE);
	}


	/*The socket is opened with IPPROTO_RAW.
	* On Linux, the kernel will automatily activate IP_HDRINCL to let use handle the IP Header
	* On FreeBSD, it's our job to do it
	*/
#ifdef __FreeBSD__
	int optval=1;
	setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(int));
#endif

	//Launch the packet capture with the handler callback
	unsigned char* buf=NULL;
	if(pcap_loop(desc,-1, callback, buf)<0) {
	   fprintf(stderr,"unable to initialize loop : %s\n",pcap_geterr(desc));
	   close(rawFile);
	   exit(-1);
	}
	return(0);
}

void affichage_ip(bpf_u_int32 net, bpf_u_int32 mask)
{
	Ip_addr *p_ip = (Ip_addr *)&net;
	Ip_addr *p_mask = (Ip_addr *)&mask;
	printf("ip : %d.%d.%d.%d\\", p_ip->one, p_ip->two, p_ip->three, p_ip->four);
	printf("%d.%d.%d.%d\n", p_mask->one, p_mask->two, p_mask->three, p_mask->four);
}


void callback(u_char *user, const struct pcap_pkthdr *h, const u_char *buff){
	struct ether_header *eth_h = (struct ether_header *) buff;
	struct iphdr *ip_h = NULL;
	struct sockaddr_ll socket_address;

	/*ifreq corresponding to the interface we are sniffing*/
	struct ifreq if_idx;
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, interface, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
		perror("SIOCGIFINDEX");

	struct ifreq if_mac;
	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, interface, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
		perror("SIOCGIFHWADDR");

	/*Ecriture dans le fichier raw*/
	if (write(rawFile, buff, h->caplen) < 0){
		perror("Write");
		exit(-1);
	}

	ip_h=(struct iphdr *)(buff+14);

//	struct sockaddr_in saddr, daddr;
//	saddr.sin_addr.s_addr=ip_h->saddr;
//	daddr.sin_addr.s_addr=ip_h->daddr;


    // Le strdup permet au ntoa de ne pas écraser la valeur précédente !!!!!!!!!!! :D
/*	char *source_ip=strdup(inet_ntoa(saddr.sin_addr));
	char *dest_ip=strdup(inet_ntoa(daddr.sin_addr));

	printf("Check : %d\n"
		   "Saddr : %s\n"
		   "Daddr : %s\n"
		   "Frag_off : %d\n"
		   "Id : %d\n"
		   "Ihl : %d\n"
		   "Protocol : %d\n"
		   "Tos : %d\n"
		   "Tot_len : %d\n"
		   "Ttl : %d\nversion: %d\n"
		   "\n\n\n",
		   ip->check,
		   source_ip,
		   dest_ip,
		   ip->frag_off,
		   ip->id,
		   ip->ihl,
		   ntohs(ip->tot_len),
		   ip->tos,
		   ip->tot_len,
		   ip->ttl,
		   ip->version
		   );

	free(source_ip);
	free(dest_ip);

	printf("Ack: \t%d\n"
		   "Ack_seq: \t%d\n"
		   "Check: \t%d\n"
		   "Dest: \t%d\n"
		   "Doff: \t%d\n"
		   "Fin: \t%d\n"
		   "Psh: \t%d\n"
		   "res1: \t%d\n"
		   "res2: \t%d\n"
		   "rst: \t%d\n"
		   "seq: \t%d\n"
		   "source: \t%d\n"
		   "syn: \t%d\n"
		   "th_ack: \t%d\n"
		   "th_dport: \t%d\n"
		   "th_flags: \t%d\n"
		   "th_off: \t%d\n"
		   "th_seq: \t%d\n"
		   "th_sport: \t%d\n"
		   "th_sum: \t%d\n"
		   "th_urp: \t%d\n"
		   "th_win: \t%d\n"
		   "th_x2: \t%d\n"
		   "urg: \t%d\n"
		   "urg_ptr: \t%d\n"
		   "window: \t\t%d\n",
		   tcp->ack,
		   tcp->ack_seq,
		   tcp->check,
		   tcp->dest,
		   tcp->doff,
		   tcp->fin,
		   tcp->psh,
		   tcp->res1,
		   tcp->res2,
		   tcp->rst,
		   tcp->seq,
		   tcp->source,
		   tcp->syn,
		   tcp->th_ack,
		   tcp->th_dport,
		   tcp->th_flags,
		   tcp->th_off,
		   tcp->th_seq,
		   tcp->th_sport,
		   tcp->th_sum,
		   tcp->th_urp,
		   tcp->th_win,
		   tcp->th_x2,
		   tcp->urg,
		   tcp->urg_ptr,
		   tcp->window
		   );
*/
	ip_h->tos=3;
	ip_h->check = in_cksum((unsigned short *)ip_h, sizeof(struct iphdr));

//	daddr.sin_family = AF_INET;

	/* Index of the network device */
	socket_address.sll_ifindex = if_idx.ifr_ifindex;
	/* Address length*/
	socket_address.sll_halen = ETH_ALEN;
	/* Destination MAC */
	socket_address.sll_addr[0] = eth_h->ether_shost[0];
	socket_address.sll_addr[1] = eth_h->ether_shost[1];
	socket_address.sll_addr[2] = eth_h->ether_shost[2];
	socket_address.sll_addr[3] = eth_h->ether_shost[3];
	socket_address.sll_addr[4] = eth_h->ether_shost[4];
	socket_address.sll_addr[5] = eth_h->ether_shost[5];

//	socket_address.sll_addr[0] = MY_DEST_MAC0;
//	socket_address.sll_addr[1] = MY_DEST_MAC1;
//	socket_address.sll_addr[2] = MY_DEST_MAC2;
//	socket_address.sll_addr[3] = MY_DEST_MAC3;
//	socket_address.sll_addr[4] = MY_DEST_MAC4;
//	socket_address.sll_addr[5] = MY_DEST_MAC5;

	int nbsend;
	// l'adresse mac sera présente car on utilise sendto avec une structure ip, le noyau suppose donc qu'il est censé gérer l'ethernet
//	printf("Tot len : %d\n", ntohs(ip->tot_len));
//	if( (nbsend=sendto(sockfd, buff+14, ntohs(ip->tot_len), 0, (struct sockaddr*)&daddr, sizeof(struct sockaddr_in))) < 0){
//		perror("Error on sendTo\n");
//	} else
//		printf("Envoyé %d\n", nbsend);

	// h->len
	if ( (nbsend=sendto(sockfd, buff, ntohs(ip_h->tot_len), 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll))) < 0)
		perror("Send failed\n");
	else
		printf("Envoyé %d\n", nbsend);
}

unsigned short in_cksum(unsigned short *addr, int len)
{
	register int sum = 0;
	u_short answer = 0;
	register u_short *w = addr;
	register int nleft = len;
	/*
	 * Our algorithm is simple, using a 32 bit accumulator (sum), we add
	 * sequential 16 bit words to it, and at the end, fold back all the
	 * carry bits from the top 16 bits into the lower 16 bits.
	 */
	while (nleft > 1)
	{
	  sum += *w++;
	  nleft -= 2;
	}
	/* mop up an odd byte, if necessary */
	if (nleft == 1)
	{
	  *(u_char *) (&answer) = *(u_char *) w;
	  sum += answer;
	}
	/* add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
	sum += (sum >> 16);             /* add carry */
	answer = ~sum;              /* truncate to 16 bits */
	return (answer);
}

void fin_de_programme(){
	printf("interruption du programme, fermeture du fichier de sortie\n");
	if(close(rawFile)!=0){
		perror("erreur à la fermeture du fichier rawFile\n");
		exit(EXIT_FAILURE);
		}
	else {
		exit(EXIT_SUCCESS);
	}
}
