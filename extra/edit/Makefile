PREFIX ?= /usr/local
BINDIR ?= ${PREFIX}/bin
MANDIR ?= ${PREFIX}/man

CFLAGS += -std=c11 -Wall -Wextra -Wpedantic
LDADD.libtls = -ltls

-include config.mk

LDLIBS = ${LDADD.libtls}
OBJS = edit.o xdg.o

all: pounce-edit

pounce-edit: ${OBJS}
	${CC} ${LDFLAGS} ${OBJS} ${LDLIBS} -o $@

clean:
	rm -f ${OBJS} pounce-edit

install: pounce-edit pounce-edit.1
	install -d ${DESTDIR}${BINDIR} ${DESTDIR}${MANDIR}/man1
	install pounce-edit ${DESTDIR}${BINDIR}
	install -m 644 pounce-edit.1 ${DESTDIR}${MANDIR}/man1

uninstall:
	rm -f ${DESTDIR}${BINDIR}/pounce-edit
	rm -f ${DESTDIR}${MANDIR}/man1/pounce-edit.1
