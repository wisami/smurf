#ifndef SMURF_H_
#define SMURF_H_

#include <stdbool.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <pcap/pcap.h>

struct list_options {
	bool Aflag;		//ascii

	bool hflag;		//help

	bool Dflag;		//devices

	bool aflag;		//address

	bool iflag;		//interface
	char *ivalue;

	bool cflag;		//count
	int cvalue;
};


#define SNAP_LEN 1518		//максимальное число байт для захвата пакета
#define SIZE_ETHERNET 14	//длина загаловка Ethernet 14 байт
#define ETHER_ADDR_LEN	6	//Адреса Ethernet 6 байтов

struct header_ethernet {
	uint8_t ether_dhost[ETHER_ADDR_LEN];		//адрес хоста назначения
	uint8_t ether_shost[ETHER_ADDR_LEN];		//адрес хоста источника
	#define ETHERTYPE_IPv4 0x0800
	#define ETHERTYPE_ARP  0x0806
	uint16_t ether_type;						//IP? ARP? RARP? и т.д
};

struct header_ip {
	uint8_t ip_vhl;							//версия << 4 | длина заголовка >> 2
	uint8_t ip_tos;							//тип сервиса
	uint16_t ip_len;						//общая длина
	uint16_t ip_id;							//идентификация
	uint16_t ip_off;						//поле смещения фрагмента
	#define IP_RF 0x8000					//флаг зарезервированного фрагмента
	#define IP_DF 0x4000					//не фрагментировать флаг
	#define IP_MF 0x2000					//флаг больше фрагментов
	#define IP_OFFMASK 0x1fff				//маска для фрагментации битов
	uint8_t ip_ttl;							//время жизни
	uint8_t ip_p;							//протокол
	#define IP_TCP 6
	#define IP_UDP 17
	uint16_t ip_sum;						//контрольная сумма
	struct in_addr ip_src, ip_dst;			//адрес источника и адресата
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

struct header_tcp {
	uint16_t th_sport;			//исходный порт
	uint16_t th_dport;			//порт назначения
	uint32_t th_seq;			//порядковый номер
	uint32_t th_ack;			//номер подтверждения
	uint8_t th_offx2;			//смещение данных, rsvd
	#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	uint8_t th_flags;
	#define TH_FIN  0x01
	#define TH_SYN  0x02
	#define TH_RST  0x04
	#define TH_PUSH 0x08
	#define TH_ACK  0x10
	#define TH_URG  0x20
	#define TH_ECE  0x40
	#define TH_CWR  0x80
	#define TH_FLAGS (TH_FIN | TH_SYN | TH_RST | TH_ACK | TH_URG | TH_ECE | TH_CWR)
	uint16_t th_win;				//window 
	uint16_t th_sum;				//checksum
	uint16_t th_urp;				//urgent pointer
};

struct header_arp {
        uint16_t ar_hrd;			//пространство аппаратных адресов (например, Ethernet, Packet Radio Net и др.)
        uint16_t ar_pro;			//пространство протокольных адресов. Для Ethernet это набор значений поля ether_typ.
        uint8_t  ar_hln;			//размер каждого аппаратного адреса в байтах
        uint8_t  ar_pln;			//размер каждого протокольного адреса в байтах
        #define ARPOP_REQUEST	1
		#define ARPOP_REPLY		2
        uint16_t ar_op;				//код операции
		#define ar_sha(ap)	(((const uint8_t *) ((ap)+1)) +  0)											//аппартаный адрес отправителя пакета (n берется из поля ar_hln).
		#define ar_spa(ap)	(((const uint8_t *) ((ap)+1)) + ((ap)->ar_hln))								//протокольный адрес отправителя пакета (m берется из поля ar_pln).
		#define ar_tha(ap)	(((const uint8_t *) ((ap)+1)) + ((ap)->ar_hln) + ((ap)->ar_pln))			//аппаратный адрес получателя, если он известен (n берется из поля ar_hln).
		#define ar_tpa(ap)	(((const uint8_t *) ((ap)+1)) + 2 * ((ap)->ar_hln) + ((ap)->ar_pln))		//протокольный адрес получателя (m берется из поля ar_pln).
		#define ARP_LENGHT(ap) (sizeof(ap) + 2 * ((ap)->ar_hln) + 2 * ((ap)->ar_pln))
};

struct header_udp{
	#define LEN_UHDR 8
	uint16_t uh_sport;
	uint16_t uh_dport;
	uint16_t uh_len;
	#define UDP_LENGHT(up) (ntohs(up->uh_len) - LEN_UHDR)  
	uint16_t uh_sum;
};

void init_list_options_default(struct list_options *);
void print_list_devices(void);
void print_network_address(struct list_options *);
void print_error(char *);
void to_sniff(struct list_options *);
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void print_usage(void);
void print_num_packets(void);
void exit_smurf(int num);
void print_ip(const uint8_t *packet, struct list_options *);
void print_tcp(const struct header_tcp *tcp, uint16_t, struct list_options *);
void print_udp(const struct header_udp *udp, struct list_options *);
void print_arp(const struct header_arp *);
void print_time(const struct timeval *);
void print_ascii(const char *, uint32_t);

#endif