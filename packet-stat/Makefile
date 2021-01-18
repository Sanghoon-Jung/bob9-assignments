LDLIBS=-lpcap -lnet -lglog
CXXFLAGS=-g -std=c++2a

all: pcap-stat

pcap-stat: *.cpp
	$(LINK.cpp) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f pcap-stat *.o
