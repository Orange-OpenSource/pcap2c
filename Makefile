all: pcap2c

INCLUDES= 

pcap2c: pcap2cpp.o
	gcc -std=c++11 -g pcap2cpp.o -o pcap2c -lpcap -lstdc++

pcap2cpp.o: pcap2cpp.cpp
	gcc -std=c++11 -g pcap2cpp.cpp $(INCLUDES) -c -o pcap2cpp.o

clean:
	rm -f pcap2c pcap2cpp.o
