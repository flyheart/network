// Arp.h

#ifndef ARP_H
#define ARP_H

#include <cstring>
#include <netinet/if_ether.h>
#include <pcap.h>
#include "Ether.h"


class Arp {
public:
	Ether* ether_header;
	ether_arp* ethernet_arp;
public:
	Arp();
	~Arp();

//////////////////////////////////////////////////////// ARP header


	void setArpHdr(const u_short hrd) {
		ethernet_arp->ea_hdr.ar_hrd = hrd;
	}
	const u_short getArpHdr() { return ethernet_arp->ea_hdr.ar_hrd; }

	void setArpPro(const u_short pro) {
		ethernet_arp->ea_hdr.ar_pro = pro;
	}
	const u_short getArpPro() { ethernet_arp->ea_hdr.ar_pro; }

	void setArpHln(const u_char hln) {
		ethernet_arp->ea_hdr.ar_hln = hln;
	}
	const u_char getArpHln() { return ethernet_arp->ea_hdr.ar_hln; }

	void setArpPln(const u_char pln) {
		ethernet_arp->ea_hdr.ar_pln = pln;
	}
	const u_char getArpPln() { return ethernet_arp->ea_hdr.ar_pln; }

	void setArpOP(const u_short op) {
		ethernet_arp->ea_hdr.ar_op = op;
	}
	const u_short getArpOp() { return ethernet_arp->ea_hdr.ar_op; }


////////////////////////////////////////////////////////////////////// ARP data
 
	void setArpSha(const u_char* mac) {
		for (int i = 0; i < ETH_ALEN; ++i) {
			ethernet_arp->arp_sha[i] = mac[i];
		}
		ether_header->setSrcMac(mac); // they are the same
	}
	const u_char* getArpSha() { return ethernet_arp->arp_sha; }

	void setArpSpa(u_int8_t* ip) { 
		for (int i = 0; i < 4; ++i)
			ethernet_arp->arp_spa[i] = ip[i];
	}
	const u_int8_t* getArpSpa() { return ethernet_arp->arp_spa; }

	void setArpTha(const u_char* mac) {
		for (int i = 0; i < ETH_ALEN; ++i) {
			ethernet_arp->arp_tha[i] = mac[i];
		}
		ether_header->setDstMac(mac);	// they are the same
	}
	const u_char* getArpTha() { return ethernet_arp->arp_tha; }

	void setArpTpa(u_int8_t* ip) { 
		for (int i = 0; i < 4; ++i)
			ethernet_arp->arp_tpa[i] = ip[i]; 
	}
	const u_int8_t* getArpTpa() { return ethernet_arp->arp_tpa; }

	void send_packet(pcap_t* dev);


};

#endif // ARP_H