# For multiple programs using a single source file each,
# we can just define 'progs' and create custom targets.
PROGS	=	pkt-gen bridge vale-ctl pkt-gen-b bridge-b dns-echo dns-echo-pkt dns-resp
#PROGS += pingd
PROGS	+= testlock test_select testmmap vale-ctl
MORE_PROGS = kern_test

CLEANFILES = $(PROGS) *.o
NO_MAN=
CFLAGS = -O0 -pipe -g
CFLAGS += -Werror -Wall -Wunused-function
CFLAGS += -I ../sys # -I/home/luigi/FreeBSD/head/sys -I../sys
CFLAGS += -Wextra
.ifdef WITH_PCAP
LDFLAGS += -lpcap
.else
CFLAGS += -DNO_PCAP
.endif

LDFLAGS += -lpthread
LDFLAGS += -lrt	# needed on linux, does not harm on BSD
#SRCS = pkt-gen.c

all: $(PROGS)

kern_test: testmod/kern_test.c

pkt-gen: pkt-gen.o
	$(CC) $(CFLAGS) -o pkt-gen pkt-gen.o $(LDFLAGS)

dns-echo-pkt: dns-echo-pkt.o
	$(CC) $(CFLAGS) -o dns-echo-pkt dns-echo-pkt.o $(LDFLAGS)

dns-echo: dns-echo.o
	$(CC) $(CFLAGS) -o dns-echo dns-echo.o $(LDFLAGS)

dns-resp: dns-resp.o
	$(CC) $(CFLAGS) -o dns-resp dns-resp.o $(LDFLAGS)

pkt-gen-b: pkt-gen-b.o
	$(CC) $(CFLAGS) -o pkt-gen-b pkt-gen-b.o $(LDFLAGS)

pkt-gen-b.o: pkt-gen.c
	$(CC) $(CFLAGS) -DBUSYWAIT -c pkt-gen.c -o pkt-gen-b.o

bridge: bridge.o
	$(CC) $(CFLAGS) -o bridge bridge.o
	
bridge-b: bridge-b.o
	$(CC) $(CFLAGS) -o bridge-b bridge-b.o

bridge-b.o: bridge.c
	$(CC) $(CFLAGS) -DBUSYWAIT -c bridge.c -o bridge-b.o	

vale-ctl: vale-ctl.o
	$(CC) $(CFLAGS) -o vale-ctl vale-ctl.o

clean:
	-@rm -rf $(CLEANFILES)

testlock: testlock.c
	$(CC) $(CFLAGS) -o testlock testlock.c -lpthread $(LDFLAGS)
