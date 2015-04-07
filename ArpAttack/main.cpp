#include <iostream>
#include "ArpAttack.h"
using namespace std;

int main(void) {
	char* dev, errbuf[PCAP_ERRBUF_SIZE];
	unsigned char mac[ETH_ALEN] = {0x66, 0xfb, 0x79, 0x86, 0x19, 0xef};
	dev = pcap_lookupdev(errbuf);
	if (NULL == dev)
		cout << errbuf << endl;
	ArpAttack aa(dev, mac);
	aa.run();

	return 0;
}