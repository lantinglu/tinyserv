LAB3_FLAGS=-D$$(./get_lab3.sh port) -D$$(./get_lab3.sh secret)
FLAGS=-O0 -std=gnu18 -g 

all: tinyserv

%.o : %.c
	gcc ${LAB3_FLAGS} ${FLAGS} -o $@ -c $<

tinyserv: tinyserv.o socket_stuff.o hmac.o lab3_management.o error.o sha1.o strnstr.o
	gcc ${FLAGS} -o $@ $^

clean:
	rm tinyserv *.o
