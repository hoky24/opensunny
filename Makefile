CFLAGS      +=-ggdb -Wall -pedantic -std=gnu99
LDFLAGS     += -lbluetooth

all: opensunny

OBJS=iniparser.o dictionary.o logging.o in_bluetooth.o in_smadata2plus.o utils.o opensunny.o

opensunny: ${OBJS}
	${CC} ${CFLAGS} -o opensunny ${OBJS} ${LDFLAGS}

%.o: %.c ${HEADER}
	$(CC) ${CFLAGS} ${INCLUDES} -c -o $@ $<
	
clean:
	rm -f opensunny *.o

all: opensunny

