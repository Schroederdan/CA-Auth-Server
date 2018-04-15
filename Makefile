LDFLAGS=-O0 -lcrypto -g -ggdb -Wall -pedantic

all: cert ca.pem server

cert: server.o
	$(CC) -o $@ $(LDFLAGS) $^

ca.pem:
ifneq (,$(wildcard ca.pem))
		$(error ca.pem already exists! Issue make clean to remove it!)
endif
ifneq (,$(wildcard ca.key))
		$(error ca.key already exists! Issue make clean to remove it!)
endif

