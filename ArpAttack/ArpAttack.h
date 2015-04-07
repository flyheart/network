// arpAttack.h
#ifndef ARPATTACK_H
#define ARPATTACK_h

#include <pcap.h>
#include "Ether.h"
#include "Arp.h"

class ArpAttack {
protected:
	pcap_t* dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	const u_char* mac;
public:
	/**
	 * devstr, the interface to attack
	 * _IP, the IP address to attack, if equals NULL, means any IP.
	 * _mac, the physices to fake
	 */
	ArpAttack(const char* devstr, const u_char* _mac) {
		dev = pcap_open_live(devstr, 65535, 1, 0, errbuf);
		Arp* a = new Arp();
		assert (NULL != dev);

		mac = _mac;
	}
	~ArpAttack() {
		pcap_close(dev);
	}

	friend void analysis_packet(u_char* args, const struct pcap_pkthdr* header, 
		const u_char* packet);

	void run();
};


#endif // ARPATTACK_H