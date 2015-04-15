#include <stdio.h>
#include <pcap.h>
#include <net/if.h>
#include <stdlib.h>
#include <sys/types.h>          /* See NOTES */
#include <netinet/ip.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

typedef struct ip_addr	{
unsigned char one;
unsigned char two;
unsigned char three;
unsigned char four;
}Ip_addr;


//structure pour découper l'adresse IP et mask
void affichage_ip(bpf_u_int32 net, bpf_u_int32 mask);
void callback(u_char *user,const struct pcap_pkthdr *h, const u_char *buff);

int main(int argc, char **argv)
{
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 net, mask;
	char *filtre = "";
	pcap_t *desc;

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

	unsigned char* buf=NULL;
	if(pcap_loop(desc,-1, callback, buf)<0) {
	   fprintf(stderr,"unable to initialize loop : %s\n",pcap_geterr(desc));
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
//	struct tcphdr *tcp = NULL;

	ip=(struct iphdr *)buff;
	struct sockaddr_in saddr, daddr;
	saddr.sin_addr.s_addr=ip->saddr;
//	daddr.sin_addr.s_addr=ip->daddr;
//	Ip_addr *p_sip = (Ip_addr *)&ip->saddr;
	Ip_addr *p_dip = (Ip_addr *)&ip->daddr;
	//system("clear");
	printf("Check : %d\nDaddr : %d.%d.%d.%d\nFrag_off : %d\nId : %d\nIhl : %d\nProtocol : %d\nSaddr : %s\nTos : %d\nTot_len : %d\nTtl : %d\nversion: %d\n\n", ip->check, p_dip->one, p_dip->two, p_dip->three, p_dip->four, ip->frag_off, ip->id, ip->ihl, ip->protocol, inet_ntoa(daddr.sin_addr), ip->tos, ip->tot_len, ip->ttl, ip->version);
}
