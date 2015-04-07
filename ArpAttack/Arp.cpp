#include "Arp.h"

Arp::Arp() {
	ethernet_arp = new ether_arp();
	ether_header = new Ether();
	memset(ethernet_arp, 0, sizeof(*ethernet_arp));
	ether_header->setType(htons(0x0806));
	ethernet_arp->ea_hdr.ar_hrd = htons(0x01);	// Ether type
	ethernet_arp->ea_hdr.ar_pro = htons(0x0800);	// IP protocol
	ethernet_arp->ea_hdr.ar_hln = 0x06;	// hardware address length
	ethernet_arp->ea_hdr.ar_pln = 0x04;	// protocol address length
}

Arp::~Arp() {
	delete ethernet_arp;
	ethernet_arp = NULL;
	delete ether_header;
	ether_header = NULL;
}

void Arp::send_packet(pcap_t* dev) {
	u_char* send = new u_char[sizeof(ethhdr)+sizeof(ether_arp)];
	memcpy(send, ether_header->ether, sizeof(ethhdr));
	memcpy(send+sizeof(ethhdr), ethernet_arp, sizeof(ether_arp));
	int ret = pcap_sendpacket(dev, send, sizeof(ethhdr)+sizeof(ether_arp));
	assert (0 == ret);
}