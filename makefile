CC = gcc
CFLAGS = -Wall -O3
INCLUDES = -I/usr/local/include/jerasure -I/usr/local/include/gf_complete
LIBS = -L/usr/local/lib -lJerasure -lgf_complete -lcrypto

all: benchmark

benchmark: benchmark.c
	$(CC) $(CFLAGS) $(INCLUDES) -o benchmark benchmark.c $(LIBS)

clean:
	rm -f benchmark
	rm -rf /tmp/node_*