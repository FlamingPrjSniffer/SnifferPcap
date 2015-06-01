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
#include <pthread.h>
#include <netdb.h>
#include <ifaddrs.h>

#define MY_DEST_MAC0	0x00
#define MY_DEST_MAC1	0x17
#define MY_DEST_MAC2	0xF2
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
int rawFile2;
int sockfd;

//structure pour découper l'adresse IP et mask
void affichage_ip(bpf_u_int32 net, bpf_u_int32 mask);
void callback(u_char *user,const struct pcap_pkthdr *h, const u_char *buff);
void* ThreadFunction(void* v);
uint32_t getIpFromName(char* ifaceName);

uint16_t ip_checksum(void* vdata, size_t length);
void fin_de_programme();

char *interface;
char *interface2;

pcap_t *fd_iface1;
pcap_t *fd_iface2;

void RouterMode(){
	char errbuf[PCAP_ERRBUF_SIZE];
	char errbuf2[PCAP_ERRBUF_SIZE];

	bpf_u_int32 net, mask;
	bpf_u_int32 net2, mask2;

	/* Our sniffer is working only with IP packet */
	char *filtre = "ip";
	char *filtre2 = "ip";

	/* Our sniffer is working on the two interfaces of the router and so it needs two threads */
	pthread_t thread1;

	//Installing a signal handler to close the rawFile on interrupt
	signal(SIGINT, fin_de_programme);


	// Find the default network interface
	interface = pcap_lookupdev(errbuf);
	printf("L'interface %s est-elle une des deux interface à sniffer ? [O/n]", interface);
	char choix;
	scanf("%*c%c%*c", &choix);
	if(choix != 'o' && choix != 'O' && choix != '0'){
//		free(interface);
		interface=(char*)malloc(sizeof(char)*12);
		if (interface == NULL){
			perror("Malloc error interface 1");
			exit(-1);
		}
		printf("Nom de l'interface 1 (hint enp4s0) : ");
		fgets(interface, 12, stdin);
	}


	interface2 = (char*)malloc(sizeof(char)*12);
	if (interface2 == NULL){
		perror("Malloc error interface 2");
		exit(-1);
	}
	printf("Nom de l'interface 2 (hint enp0s20u2) : \n");
	interface2=fgets(interface2, 12, stdin);
	interface2[strlen(interface2)-1]='\0';

	// Opening the interface
	if((fd_iface1=pcap_open_live(interface,1514,IFF_PROMISC,1000,errbuf))==NULL) {
		fprintf(stderr,"Interface %s: Unable1 to open descriptor : %s\n", interface, errbuf);
		exit(-1);
	}
	if((fd_iface2=pcap_open_live(interface2,1514,IFF_PROMISC,1000,errbuf2))==NULL) {
		fprintf(stderr,"Interface %s: Unable2 to open descriptor : %s\n", interface2, errbuf2);
		exit(-1);
	}

	// Get the IP and Mask of the interface
	if(pcap_lookupnet(interface, &net, &mask, errbuf) == -1)
	{
		fprintf(stderr,"unable to lookup : %s\n", errbuf);
		exit(-1);
	}

	if(pcap_lookupnet(interface2, &net2, &mask2, errbuf2) == -1)
	{
		fprintf(stderr,"unable to lookup : %s\n", errbuf);
		exit(-1);
	}

	// Display IP and mask
	affichage_ip(net, mask);
	affichage_ip(net2, mask2);

	struct bpf_program fp;
	struct bpf_program fp2;

	//Compiling the filter string to a filter program.
	if(pcap_compile(fd_iface1, &fp,filtre,0x100,mask)==-1) {
		fprintf(stderr,"error compiling filter : %s\n",pcap_geterr(fd_iface1));
		exit(-1);
	}
	if(pcap_compile(fd_iface2, &fp2,filtre2,0x100,mask2)==-1) {
		fprintf(stderr,"error compiling filter : %s\n",pcap_geterr(fd_iface2));
		exit(-1);
	}

	//Applying the filter to the sniffed interface
	if(pcap_setfilter(fd_iface1,&fp)<0) {
	   fprintf(stderr,"unable to apply filter : %s\n",pcap_geterr(fd_iface1));
	   exit(-1);
	}

	if(pcap_setfilter(fd_iface2,&fp2)<0) {
	   fprintf(stderr,"unable to apply filter : %s\n",pcap_geterr(fd_iface2));
	   exit(-1);
	}

	//Opening the rawFile to save each pack. Futher use : open it with wireshark
	if ((rawFile=open("./rawFile", O_CREAT|O_TRUNC|O_RDWR)) == -1){
		perror("open");
		exit(-1);
	}

	if ((rawFile2=open("./rawFile", O_CREAT|O_TRUNC|O_RDWR)) == -1){
		perror("open");
		exit(-1);
	}

	// Open output socket
	if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1) {
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

	pthread_create(&thread1, NULL, ThreadFunction, NULL);
	pthread_detach(thread1);
	//Launch the packet capture with the handler callback
	unsigned char* callbackArg;
	callbackArg=(unsigned char*)strdup("Thread enp4s0");
	if(pcap_loop(fd_iface1,-1, callback, callbackArg)<0) {
	   fprintf(stderr,"unable to initialize loop : %s\n",pcap_geterr(fd_iface1));
	   close(rawFile);
	   exit(-1);
	}
}

int main(int argc, char **argv)
{
	int typeDeReseau = 0;
	printf("Où se trouve le sniffer ?\n\t1) Sur le routeur\n\t2) En mode Bridge\nSaisir la réponse :");
	scanf("%d*c", &typeDeReseau);


	switch (typeDeReseau){
		case 1:
			RouterMode();
			break;
		default:
			printf("Pas encore implémenté\n");
			exit(-1);
	}

	return 0;
}

void* ThreadFunction(void* v){
	v=v;
	unsigned char* callbackArg;
	callbackArg=(unsigned char*)strdup("Thread enp0s20u2");
	if(pcap_loop(fd_iface2,-1, callback, callbackArg)<0) {
	   fprintf(stderr,"unable to initialize loop : %s\n",pcap_geterr(fd_iface1));
	   close(rawFile);
	   exit(-1);
	}
	printf("%s:%d\n", __FUNCTION__, __LINE__);
	pthread_exit(0);
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
	struct iphdr *ip_h = (struct iphdr *)(buff+14);

	/*Ecriture dans le fichier raw*/
	if (write(rawFile, buff, h->caplen) < 0){
		perror("Write");
		exit(-1);
	}

	/*Filtrage des paquets sortant d'une interface (paquet que l'on viens d'émettre
	 * Et filtrage des paquets dont notre ip est la destination (on ne traite que les paquets qui ne nous sont pas addressés
	 */
	if ( (
			eth_h->ether_shost[0] == 0xd8 &&
			eth_h->ether_shost[1] == 0x50 &&
			eth_h->ether_shost[2] == 0xe6 &&
			eth_h->ether_shost[3] == 0xee &&
			eth_h->ether_shost[4] == 0x61 &&
			eth_h->ether_shost[5] == 0xa9
		 )
		 ||
		 (
			 eth_h->ether_shost[0] == 0x00 &&
			 eth_h->ether_shost[1] == 0x50 &&
			 eth_h->ether_shost[2] == 0xb6 &&
			 eth_h->ether_shost[3] == 0x09 &&
			 eth_h->ether_shost[4] == 0xa5 &&
			 eth_h->ether_shost[5] == 0x35
		 )
		 ||
		 ip_h->daddr == inet_addr("192.168.0.42")
		 ||
		 ip_h->daddr == inet_addr("192.169.0.42")
	   )
	{
		return;
	}

	/* Modifying the TOS to 3*/
	ip_h->tos=3;
	ip_h->check = 0x00;
	ip_h->check = ip_checksum((void*)ip_h, sizeof(struct iphdr));

	/* Resend the packet */
	struct sockaddr_in daddr;
	daddr.sin_family = AF_INET;
	daddr.sin_addr.s_addr=ip_h->daddr;
	int nbsend;

	// Nul besoin de camoufler l'addresse mac.
	if( (nbsend=sendto(sockfd, buff+14, ntohs(ip_h->tot_len), 0, (struct sockaddr*)&daddr, sizeof(struct sockaddr_in))) < 0){
		perror("Error on sendTo");
		printf("Error on sendTo: %s\n", inet_ntoa(daddr.sin_addr));
	} else {
		printf("%s : Envoyé %d : %s\n", user, nbsend, inet_ntoa(daddr.sin_addr));
	}
}

void callbackBridge(u_char *user, const struct pcap_pkthdr *h, const u_char *buff){
	struct ether_header *eth_h = (struct ether_header *) buff;
	struct iphdr *ip_h = NULL;
	//struct sockaddr_ll socket_address;

	/*ifreq corresponding to the interface we are sniffing*/
//	struct ifreq if_idx;
//	memset(&if_idx, 0, sizeof(struct ifreq));
//	strncpy(if_idx.ifr_name, interface, IFNAMSIZ-1);
//	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
//		perror("SIOCGIFINDEX");

//	struct ifreq if_mac;
//	memset(&if_mac, 0, sizeof(struct ifreq));
//	strncpy(if_mac.ifr_name, interface, IFNAMSIZ-1);
//	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
//		perror("SIOCGIFHWADDR");

	/*Ecriture dans le fichier raw*/
	if (write(rawFile, buff, h->caplen) < 0){
		perror("Write");
		exit(-1);
	}

	ip_h=(struct iphdr *)(buff+14);

	if ( (
			eth_h->ether_shost[0] == 0xd8 &&
			eth_h->ether_shost[1] == 0x50 &&
			eth_h->ether_shost[2] == 0xe6 &&
			eth_h->ether_shost[3] == 0xee &&
			eth_h->ether_shost[4] == 0x61 &&
			eth_h->ether_shost[5] == 0xa9
		 )
		 ||
		 (
			 eth_h->ether_shost[0] == 0x00 &&
			 eth_h->ether_shost[1] == 0x50 &&
			 eth_h->ether_shost[2] == 0xb6 &&
			 eth_h->ether_shost[3] == 0x09 &&
			 eth_h->ether_shost[4] == 0xa5 &&
			 eth_h->ether_shost[5] == 0x35
		 )
		 ||
		 ip_h->daddr == inet_addr("192.168.0.42")
		 ||
		 ip_h->daddr == inet_addr("192.169.0.42")
	   )
	{
		return;
	}

	struct sockaddr_in saddr, daddr;


	// Le strdup permet au ntoa de ne pas écraser la valeur précédente ! :D
/*
	saddr.sin_addr.s_addr=ip_h->saddr;
	daddr.sin_addr.s_addr=ip_h->daddr;
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
//	ip_h->ttl+=1;
//	ip_h->check = ip_checksum((unsigned short *)ip_h, sizeof(struct iphdr));
	ip_h->check = 0x00;
	ip_h->check = ip_checksum((void*)ip_h, sizeof(struct iphdr));

	//daddr.sin_family = AF_INET;

	/* Index of the network device */
//	socket_address.sll_ifindex = if_idx.ifr_ifindex;
	/* Address length*/
//	socket_address.sll_halen = ETH_ALEN;
	/* Destination MAC */
//	socket_address.sll_addr[0] = eth_h->ether_shost[0];
//	socket_address.sll_addr[1] = eth_h->ether_shost[1];
//	socket_address.sll_addr[2] = eth_h->ether_shost[2];
//	socket_address.sll_addr[3] = eth_h->ether_shost[3];
//	socket_address.sll_addr[4] = eth_h->ether_shost[4];
//	socket_address.sll_addr[5] = eth_h->ether_shost[5];

//	eth_h->ether_shost[0] = MY_DEST_MAC0;
//	eth_h->ether_shost[1] = MY_DEST_MAC1;
//	eth_h->ether_shost[2] = MY_DEST_MAC2;
//	eth_h->ether_shost[3] = MY_DEST_MAC3;
//	eth_h->ether_shost[4] = MY_DEST_MAC4;
//	eth_h->ether_shost[5] = MY_DEST_MAC5;

//	socket_address.sll_addr[0] = MY_DEST_MAC0;
//	socket_address.sll_addr[1] = MY_DEST_MAC1;
//	socket_address.sll_addr[2] = MY_DEST_MAC2;
//	socket_address.sll_addr[3] = MY_DEST_MAC3;
//	socket_address.sll_addr[4] = MY_DEST_MAC4;
//	socket_address.sll_addr[5] = MY_DEST_MAC5;


	daddr.sin_family = AF_INET;
	daddr.sin_addr.s_addr=ip_h->daddr;
	printf("Ip dest : %s\n", inet_ntoa(daddr.sin_addr));
	int nbsend;
	// l'adresse mac sera présente car on utilise sendto avec une structure ip, le noyau suppose donc qu'il est censé gérer l'ethernet
	printf("Tot len : %d\n", ntohs(ip_h->tot_len));
	if( (nbsend=sendto(sockfd, buff+14, ntohs(ip_h->tot_len), 0, (struct sockaddr*)&daddr, sizeof(struct sockaddr_in))) < 0){
		perror("Error on sendTo");
		printf("Error on sendTo: %s\n", inet_ntoa(daddr.sin_addr));
	} else {
		printf("%s : Envoyé %d : %s\n", user, nbsend, inet_ntoa(daddr.sin_addr));
	}

//	//#todo ne plus modifier les addresses ethernet
//	if ( (nbsend=sendto(sockfd, buff, ntohs(ip_h->tot_len)+14, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll))) < 0)
//		perror("Send failed\n");
//	else
//		printf("%s : Envoyé %d\n", user, nbsend);
}

uint16_t ip_checksum(void* vdata, size_t length) {
	// Cast the data pointer to one that can be indexed.
	char* data=(char*)vdata;

	// Initialise the accumulator.
	uint32_t acc=0xffff;

	// Handle complete 16-bit blocks.
	for (size_t i=0;i+1<length;i+=2) {
		uint16_t word;
		memcpy(&word,data+i,2);
		acc+=ntohs(word);
		if (acc>0xffff) {
			acc-=0xffff;
		}
	}

	// Handle any partial block at the end of the data.
	if (length&1) {
		uint16_t word=0;
		memcpy(&word,data+length-1,1);
		acc+=ntohs(word);
		if (acc>0xffff) {
			acc-=0xffff;
		}
	}

	// Return the checksum in network byte order.
	return htons(~acc);
}



void fin_de_programme(){
	printf("interruption du programme, fermeture du fichier de sortie\n");
	if(close(rawFile)!=0 || close(rawFile2) !=0 ){
		perror("erreur à la fermeture du fichier rawFile1 ou rawFile2\n");
		exit(EXIT_FAILURE);
		}
	else {
		exit(EXIT_SUCCESS);
	}
}

uint32_t getIpFromName(char* ifaceName)
{
	struct ifaddrs *ifaddr, *ifa;
	int s;
	char host[NI_MAXHOST];

	if (getifaddrs(&ifaddr) == -1)
	{
		perror("getifaddrs");
		exit(EXIT_FAILURE);
	}

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
	{
		if (ifa->ifa_addr == NULL)
			continue;

		if ( (s=getnameinfo(ifa->ifa_addr,sizeof(struct sockaddr_in),host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST)) != 0) {
			printf("getnameinfo() failed: %s\n", gai_strerror(s));
			exit(EXIT_FAILURE);
		}

		if((strcmp(ifa->ifa_name,ifaceName)==0)&&(ifa->ifa_addr->sa_family==AF_INET))
		{
			printf("\tInterface : <%s>\n",ifa->ifa_name );
			printf("\t  Address : <%s>\n", host);
		}
	}
	freeifaddrs(ifaddr);
	return -1;
}
