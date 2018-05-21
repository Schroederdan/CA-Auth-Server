LDFLAGS=-O0 -lcrypto -g -ggdb -Wall -pedantic
CFLAGS=-std=c11 -O0 -g -ggdb -Wall -pedantic

all: cert ca.pem

cert: main.o
	gcc -o $@ $^ $(LDFLAGS)

%.o: %.c
	gcc -c -o  $@ $< $(CFLAGS)

clean:
	rm -f cert *.o
	@echo "CA Certs not removed. Run caclean to remove these."

caclean:
	rm -f ca.key ca.pem
	@echo "All CA certs removed."

ca.pem:
ifneq (,$(wildcard ca.pem))
		$(error ca.pem already exists! Issue make clean to remove it!)
endif
ifneq (,$(wildcard ca.key))
		$(error ca.key already exists! Issue make clean to remove it!)
endif
	openssl req -config openssl.conf -x509 -sha256 -nodes -extensions v3_ca -days 3650 -subj '/CN=OpenSSL CA/O=Example Company/C=SE' -newkey rsa:4096 -keyout ca.key -out ca.pem
