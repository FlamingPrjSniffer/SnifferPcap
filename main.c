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
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>

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

int main(int argc, char **argv)
{
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32 net, mask;
	char *filtre = "icmp";
	pcap_t *desc;
	signal(SIGINT, fin_de_programme);
//    dev = "wlan0";
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL)
	{
		fprintf(stderr, "Couldn't find default device : %s\n", errbuf);
		exit(-1);
	}

	printf("Interface : %s\n", dev);


	if((desc=pcap_open_live(dev,1514,IFF_PROMISC,1000,errbuf))==NULL) {
		fprintf(stderr,"unable to open descriptor : %s\n",errbuf);
		exit(-1);
	}

	if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1) //récupere l'adresse IP et le Mask
	{
		fprintf(stderr,"unable to lookup : %s\n", errbuf);
		return(-1);
	}

	affichage_ip(net, mask);

	struct bpf_program fp;

	if(pcap_compile(desc, &fp,filtre,0x100,mask)==-1) {
		fprintf(stderr,"error compiling filter : %s\n",pcap_geterr(desc));
		exit(-1);
	}

	if(pcap_setfilter(desc,&fp)<0) {
	   fprintf(stderr,"unable to apply filter : %s\n",pcap_geterr(desc));
	   exit(-1);
	}

	if ((rawFile=open("./rawFile", O_CREAT|O_TRUNC|O_RDWR)) == -1){
		perror("open");
		exit(-1);
	}

	/* open ICMP socket */
	if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

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
	struct iphdr *ip = NULL;
	struct tcphdr *tcp = NULL;

	if (write(rawFile, buff, h->caplen) < 0){
		perror("Write");
		exit(-1);
	}

	ip=(struct iphdr *)(buff+14);
	tcp=(struct tcphdr *)(buff+34);
	struct sockaddr_in saddr, daddr;
    saddr.sin_addr.s_addr=ip->saddr;
    daddr.sin_addr.s_addr=ip->daddr;
//	Ip_addr *p_sip = (Ip_addr *)&ip->saddr;
//	Ip_addr *p_dip = (Ip_addr *)&ip->daddr;
	//system("clear");

    // Le strdup permet au ntoa de ne pas écraser la valeur précédente !!!!!!!!!!! :D
char *source_ip=strdup(inet_ntoa(saddr.sin_addr));
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
           ip->protocol,
		   ip->tos,
		   ip->tot_len,
		   ip->ttl,
		   ip->version
		   );

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


	ip->tos=3;
	ip->check = in_cksum((unsigned short *)ip, sizeof(struct iphdr));


	struct sockaddr_in connection;
	int optval=1;

//	The socket is opened with IPPROTO_RAW so normally the setsockopt isn't necessary
	 /* IP_HDRINCL must be set on the socket so that the kernel does not attempt
	 *  to automatically add a default ip header to the packet*/
	setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(int));

	connection.sin_family       = AF_INET;
	connection.sin_addr.s_addr  = ip->daddr;
	send(sockfd, buff, ip->tot_len, 0);




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
