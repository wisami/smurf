#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h>
#include <time.h>
#include <sys/types.h>
#include <pcap/pcap.h>
#include "smurf.h"

unsigned long long num_cap_packets = 0;		//для подсчёта количества захваченных пакетов

void init_list_options_default(struct list_options *lopt)
{
	lopt->Aflag = false;

	lopt->iflag = false;
	lopt->ivalue = NULL;

	lopt->cflag = false;
	lopt->cvalue = 0;
}

void print_list_devices(void)
{
	int i = 1;
	char ebuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32 flag = 0;
	pcap_if_t *list_dev = NULL, *dev = NULL;

	if(pcap_findalldevs(&list_dev, ebuf) == PCAP_ERROR)
		print_error(ebuf);

	dev = list_dev;

	while(dev) {
		printf("%2d. %s", i++, dev->name);
		if(dev->description)
			printf(" (%s)", dev->description);

		flag = dev->flags & (PCAP_IF_UP | PCAP_IF_RUNNING | PCAP_IF_LOOPBACK);

		switch(flag) {
			case (PCAP_IF_UP | PCAP_IF_RUNNING | PCAP_IF_LOOPBACK):
			printf(" [Up, Running, Loopback]\n");
			break;

			case (PCAP_IF_UP | PCAP_IF_RUNNING):
			printf(" [Up, Running]\n");
			break;

			case PCAP_IF_UP:
			printf(" [Up]\n");
			break;

			default:
			printf(" [none]\n");
		}

		dev = dev->next;
	}

	printf("\n");

	pcap_freealldevs(list_dev);
}

void print_network_address(struct list_options *lopt)
{
	char ebuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *list_dev = NULL;
	char *dev_name = NULL;
	bpf_u_int32 net = 0, mask = 0;

	if(lopt->iflag) {
		dev_name = lopt->ivalue;
	}
	else {
		if(pcap_findalldevs(&list_dev, ebuf) == PCAP_ERROR)
			print_error(ebuf);

		dev_name = list_dev->name;
	}

	if(pcap_lookupnet(dev_name, &net, &mask, ebuf) == PCAP_ERROR)
		print_error(ebuf);

	printf("Сетевой интерфейс: %s\n", dev_name);
	printf("Сетевой адрес -- %u.%u.%u.%u\n", ((net << 24) >> 24), ((net << 16) >> 24), ((net << 8) >> 24), (net >> 24));
	printf("Маска сети -- %u.%u.%u.%u\n", ((mask << 24) >> 24), ((mask << 16) >> 24), ((mask << 8) >> 24), (mask >> 24));
	printf("\n");

	pcap_freealldevs(list_dev);
}

void print_error(char *strerr)
{
	fprintf(stderr, "Ошибка: %s\n", strerr);
	exit(EXIT_FAILURE);
}

void to_sniff(struct list_options *lopt)
{
	char ebuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle = NULL;
	pcap_if_t *list_dev = NULL;
	char *dev_name;
	int count_packet = -1;

	if(lopt->iflag) {
		dev_name = lopt->ivalue;
	}
	else {
		if(pcap_findalldevs(&list_dev, ebuf) == PCAP_ERROR)
			print_error(ebuf);

		dev_name = list_dev->name;
	}

	if((handle = pcap_open_live(dev_name, SNAP_LEN, 1, 1000, ebuf)) == NULL)
		print_error(ebuf);

	if(pcap_datalink(handle) != DLT_EN10MB) {
		if(pcap_set_datalink(handle, DLT_EN10MB) == PCAP_ERROR) {
			fprintf(stderr, "%s\n", pcap_geterr(handle));
			fprintf(stderr, "Заголовки канального уровня предоставляемые устройством \"%s\" \
не поддерживаются\n", dev_name);
			pcap_freealldevs(list_dev);
			exit(EXIT_FAILURE);
		}
	}

	printf("Тип заголока канального уровня: DLT_EN10MB (ethernet).\n");
	printf("Длина пакета для захвата: %d.\n", SNAP_LEN);
	printf("Сетевой интерфейс: %s\n\n", dev_name);
	pcap_freealldevs(list_dev);

	if(lopt->cflag)
		count_packet = lopt->cvalue;

	if(pcap_loop(handle, count_packet, got_packet, (u_char *) lopt) == PCAP_ERROR)
		print_error("Ошибка: pcap_loop\n");
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	num_cap_packets++;

	const struct header_ethernet *ethernet;

	ethernet = (struct header_ethernet *) (packet);

	switch(ntohs(ethernet->ether_type)) {
		case ETHERTYPE_IPv4:
		print_time(&(header->ts));
		print_ip(packet, (struct list_options *) args);
		break;

		case ETHERTYPE_ARP:
		print_time(&(header->ts));
		print_arp((const struct header_arp *) (packet + SIZE_ETHERNET));
		break;

		default:
		printf("ETHER_TYPE: Protocol unknown. ether_type = 0x%X\n", ntohs(ethernet->ether_type));
	}

}

void print_time(const struct timeval *pt)
{
	const int size_time_str = 9;
	char time_str[size_time_str];

	strftime(time_str, size_time_str, "%H:%M:%S", localtime(&(pt->tv_sec)));
	printf("%s.%ld ", time_str, pt->tv_usec);

}

void print_ip(const u_char *packet, struct list_options *lopt)
{
	const struct header_ip *ip;
	const struct header_tcp *tcp;
	const struct header_udp *udp;

	int size_ip = 0;
	int size_tcp = 0;
	int size_udp = 0;
	uint16_t length = 0;

	ip = (const struct header_ip *) (packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip) * 4;

	if(size_ip < 20) {
		printf("* Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	if(ip->ip_p == IP_TCP) {
		tcp = (const struct header_tcp *) (packet + SIZE_ETHERNET + size_ip);
		size_tcp = TH_OFF(tcp) * 4;

		if(!(size_tcp < 20)) {
			printf("IP ");
			printf("%s:%u", inet_ntoa(ip->ip_src), ntohs(tcp->th_sport));
			printf(" > ");
			printf("%s:%u ", inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport));

			length = ntohs(ip->ip_len) - (size_ip + size_tcp);
			print_tcp(tcp, length, lopt);
			return;
		}
	}

	if(ip->ip_p == IP_UDP) {
		udp = (const struct header_udp *) (packet + SIZE_ETHERNET + size_ip);

			printf("IP ");
			printf("%s:%u", inet_ntoa(ip->ip_src), ntohs(udp->uh_sport));
			printf(" > ");
			printf("%s:%u ", inet_ntoa(ip->ip_dst), ntohs(udp->uh_dport));
			print_udp(udp, lopt);
	}
}

void print_tcp(const struct header_tcp *tcp, uint16_t length, struct list_options *lopt)
{
	printf("Flags ");
	switch(tcp->th_flags) {
		case TH_ACK:
		printf("[.], ");
		break;

		case TH_SYN:
		printf("[S], ");
		break;

		case TH_PUSH:
		printf("[P], ");
		break;

		case (TH_PUSH | TH_ACK):
		printf("[P.], ");
		break;

		case TH_FIN:
		printf("[F], ");
		break;

		case (TH_FIN | TH_ACK):
		printf("[F.], ");
		break;

		case TH_RST:
		printf("[R], ");
		break;

		case (TH_RST | TH_ACK):
		printf("[R.], ");
		break;

		case (TH_ACK | TH_SYN):
		printf("[S.], ");
		break;

		case (TH_URG):
		printf("[U], ");
		break;

		case (TH_ECE):
		printf("[E], ");
		break;

		case (TH_CWR):
		printf("[C], ");
		break;

		case (TH_ACK | TH_FIN | TH_PUSH):
		printf("[FP.], ");
		break;

		case (TH_SYN | TH_RST | TH_URG | TH_ECE):
		printf("[SRUE], ");
		break;

		case (TH_ECE | TH_CWR):
		printf("[EC], ");
		break;

		default:
		printf("Flag unknown %d, ", tcp->th_flags);
		break;
	}

	if(length > 0 || tcp->th_flags & (TH_SYN | TH_FIN | TH_RST)) {
    	printf("seq %u", ntohl(tcp->th_seq));
		if(length > 0) {
        	printf(":%u, ", ntohl(tcp->th_seq) + length);
        }
        else
        	printf(", ");
    }

	if(tcp->th_flags & TH_ACK) {
		printf("ask %u, ", htonl(tcp->th_ack));
	}

	printf("win %hu, ", ntohs(tcp->th_win));

	if(tcp->th_flags & TH_URG) {
		printf("urg %u, ", ntohs(tcp->th_urp));
	}

	printf("length %d\n", length);

	if(lopt->Aflag && length > 0) {
		print_ascii((const char *) (tcp + 1), length);
	}
}

void print_udp(const struct header_udp *udp, struct list_options *lopt)
{
	printf("Check sum %hu, length %hu\n", ntohs(udp->uh_sum), UDP_LENGHT(udp));

	if(lopt->Aflag && UDP_LENGHT(udp) > 0) {
		print_ascii((const char *) (udp + 1), UDP_LENGHT(udp));
	}
}

void print_arp(const struct header_arp *ap)
{
	const uint8_t *ar_tpa = ar_tpa(ap);
	const uint8_t *ar_spa = ar_spa(ap);
	const uint8_t *ar_sha = ar_sha(ap);

	printf("ARP, ");

	switch(ntohs(ap->ar_op)) {
		case ARPOP_REQUEST:
		printf("Request who-has %u.%u.%u.%u ", *(ar_tpa + 0), *(ar_tpa + 1), *(ar_tpa + 2), *(ar_tpa + 3));
		printf("tell %u.%u.%u.%u, ", *(ar_spa + 0), *(ar_spa + 1), *(ar_spa + 2), *(ar_spa + 3));
		printf("length %ld\n", ARP_LENGHT(ap));
		break;

		case ARPOP_REPLY:
		printf("Reply %u.%u.%u.%u is-at, ", *(ar_spa + 0), *(ar_spa + 1), *(ar_spa + 2), *(ar_spa + 3));
		printf("%x:%x:%x:%x:%x:%x, ", *(ar_sha + 0), *(ar_sha + 1), *(ar_sha + 2), *(ar_sha + 3), *(ar_sha + 4), *(ar_sha + 5));
		printf("length %ld\n", ARP_LENGHT(ap));
		break;
	}
}

void print_ascii(const char *p, uint32_t n)
{
	for(uint32_t i = 0; i < n; i++, p++) {
		if(isprint(*p) || *p == '\n') 
			printf("%c", *p);
		else
			printf(".");

	}

	printf("\n\n");
}

void print_usage(void)
{
	printf("Usage: smurf [-AaDh] [-i interface] [-c count]\n");
	printf("-A (--ascii): вывод содержимого пакета в кодировки ASCII\n");
	printf("-D (--devices): вывести список доступных сетевых устройств\n");
	printf("-a (--addr): отобразить сетевой адрес и маску подсети для первого сетевого интерфеса в списке. \
Для выбора сетевого интерфейса возпользуйтесь опцией -i\n");
	printf("-i (--interface): указать необходимый сетевой интерфейс для работы\n");
	printf("-c (--count): указать количество захватываемых пакетов\n");
	printf("-h (--help): вызов справки\n");
	
	printf("\n");
}

void print_num_packets(void)
{
	printf("\n\nЗахвачено пакетов: %llu\n", num_cap_packets);
}

void exit_smurf(int num)
{
	print_num_packets();
	exit(EXIT_SUCCESS);
}