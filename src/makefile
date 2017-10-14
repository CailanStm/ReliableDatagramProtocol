HEADERS = helpers.h rdp_packets.h
SHARED_SOURCE = helpers.c rdp_packets.c

all: rdpr rdps

rdpr: rdpr.c $(SHARED_SOURCE) $(HEADERS)
	gcc -o $@ $^
	
rdps: rdps.c $(SHARED_SOURCE) $(HEADERS)
	gcc -o $@ $^
	
.PHONY: clean

clean:
	rm -f rdpr