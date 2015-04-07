test : Ether.o Arp.o ArpAttack.o main.o
	g++ -o test Ether.o Arp.o ArpAttack.o main.o -lpcap

Ether.o : Ether.cpp Ether.h
	g++ -c Ether.cpp

Arp.o : Arp.cpp Arp.h
	g++ -c Arp.cpp

ArpAttack.o: ArpAttack.cpp ArpAttack.h
	g++ -c ArpAttack.cpp

main.o : main.cpp
	g++ -c main.cpp

clean:
	rm *.o test