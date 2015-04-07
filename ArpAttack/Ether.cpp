// Ether.cpp

#include "Ether.h"

Ether::Ether() {
	ether = new ethhdr();
	memset(ether, 0, sizeof(*ether));
	assert(NULL != ether);
}
Ether::~Ether() {
	delete ether;
	ether = NULL;
}
