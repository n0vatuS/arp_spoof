all: arp_spoof

arp_spoof: main.o module.o
	g++ -std=c++11 -Wall -g -o arp_spoof main.o module.o -lpcap

main.o: main.cpp
	g++ -Wall -g -c -o main.o main.cpp

module.o: module.cpp module.h
	g++ -Wall -g -c -o module.o module.cpp

clean: 
	rm -f *.o
	rm -f arp_spoof
