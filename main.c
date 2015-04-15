#include <stdio.h>
#include <pcap.h>
#include <net/if.h>

typedef struct ip_addr	{
unsigned char one;
unsigned char two;
unsigned char three;
unsigned char four;
}Ip_addr;
//structure pour découper l'adresse IP et mask
void affichage_ip(bpf_u_int32 net, bpf_u_int32 mask);

int main(int argc, char **argv)
{
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 net, mask;
    char *filtre = "src port 80";

    dev = "wlan0";
/*	dev = pcap_lookupdev(errbuf);
    if (dev == NULL)
    {
        fprintf(stderr, "Couldn't find default device : %s\n", errbuf);
        exit(-1);
    }
*/
    printf("Interface : %s\n", dev);

    pcap_t *desc = pcap_open_live(dev, 1514, IFF_PROMISC, 1000, errbuf); // Récupère le descripeur

    if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1) //récupere l'adresse IP et le Mask
    {
        fprintf(stderr,"unable to lookup : %s\n", errbuf);
        return(-1);
    }

    affichage_ip(net, mask);

    struct bpf_program fp;
    pcap_compile(desc, &fp, "src port 80", 0x100, mask);

    return(0);
}

void affichage_ip(bpf_u_int32 net, bpf_u_int32 mask)
{
        Ip_addr *p_ip = (Ip_addr *)&net;
        Ip_addr *p_mask = (Ip_addr *)&mask;
        printf("ip : %d.%d.%d.%d\\", p_ip->one, p_ip->two, p_ip->three, p_ip->four);
        printf("%d.%d.%d.%d\n", p_mask->one, p_mask->two, p_mask->three, p_mask->four);
}


