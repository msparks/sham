all: sham

sham: sham.c
	gcc -funroll-loops -O3 -o sham -lcrypto sham.c

shamprofile: sham.c
	gcc -g -pg -O0 -o sham -lcrypto sham.c

clean:
	rm -f sham
