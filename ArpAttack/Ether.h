// Ether.h

#ifndef ETHER_H
#define ETHER_H

#include <cassert>
#include <cstring>
// #include </usr/include/linux/if_ether.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>


class Ether {
public:
	ethhdr* ether;
public:
	Ether();
	~Ether();

	void setDstMac(const u_char* mac) {
		for (int i = 0; i < ETH_ALEN; ++i) {
			ether->h_dest[i] = mac[i];
		}
	}
	const u_char* getDstMac() { 
		return ether->h_dest;
	}

	void setSrcMac(const u_char* mac) {
		for (int i = 0; i < ETH_ALEN; ++i) {
			ether->h_source[i] = mac[i];
		}
	}
	const u_char* getSrcMac() {
		return ether->h_source;
	}

	void setType(const u_short type) {
		ether->h_proto = type;
	}
	const u_short getType() {
		return ether->h_proto;
	}
};

#endif // ETHER_H