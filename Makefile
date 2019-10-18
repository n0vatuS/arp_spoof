all: send_arp

send_arp: main.o module.o pcap.o gmemfunc.cpp gmemhook.cpp gmemmgr.cpp
	clang++ -std=c++14 -Wall -g -o send_arp main.o module.o pcap.o gmemfunc.cpp gmemhook.cpp gmemmgr.cpp -ldl -lpcap

main.o: main.cpp
	g++ -Wall -g -c -o main.o main.cpp

module.o: module.cpp module.h
	g++ -Wall -g -c -o module.o module.cpp

pcap.o: pcap.cpp pcap.h
	g++ -Wall -g -c -o pcap.o pcap.cpp
clean: 
	rm -f *.o
	rm send_arp
