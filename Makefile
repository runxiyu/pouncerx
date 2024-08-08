PREFIX ?= /usr/local
BINDIR ?= ${PREFIX}/bin
MANDIR ?= ${PREFIX}/man

CFLAGS += -std=c11 -Wall -Wextra -Wpedantic
LDADD.crypt = -lcrypt
LDADD.libcurl = -lcurl
LDADD.libtls = -ltls
LDADD.sqlite3 = -lsqlite3

BINS = calico pounce
MANS = ${BINS:=.1}

include config.mk

LDLIBS.calico =
LDLIBS.pounce = ${LDADD.crypt} ${LDADD.libtls}
LDLIBS.pounce-notify = ${LDADD.libtls}
LDLIBS.pounce-palaver = ${LDADD.libcurl} ${LDADD.libtls} ${LDADD.sqlite3}

OBJS.calico += dispatch.o

OBJS.pounce += bounce.o
OBJS.pounce += client.o
OBJS.pounce += config.o
OBJS.pounce += local.o
OBJS.pounce += ring.o
OBJS.pounce += server.o
OBJS.pounce += state.o
OBJS.pounce += xdg.o

OBJS.pounce-notify = notify.o
OBJS.pounce-palaver = palaver.o xdg.o

OBJS += ${OBJS.calico}
OBJS += ${OBJS.pounce}
OBJS += ${OBJS.pounce-notify}
OBJS += ${OBJS.pounce-palaver}

dev: tags all

all: ${BINS}

calico: ${OBJS.calico}
pounce: ${OBJS.pounce}
pounce-notify: ${OBJS.pounce-notify}
pounce-palaver: ${OBJS.pounce-palaver}

${BINS}:
	${CC} ${LDFLAGS} ${OBJS.$@} ${LDLIBS.$@} -o $@

${OBJS.pounce}: bounce.h

tags: *.[ch]
	ctags -w *.[ch]

clean:
	rm -f ${BINS} ${OBJS} tags

install: ${BINS} ${MANS}
	install -d ${DESTDIR}${BINDIR} ${DESTDIR}${MANDIR}/man1
	install ${BINS} ${DESTDIR}${BINDIR}
	install -m 644 ${MANS} ${DESTDIR}${MANDIR}/man1

uninstall:
	rm -f ${BINS:%=${DESTDIR}${BINDIR}/%}
	rm -f ${MANS:%=${DESTDIR}${MANDIR}/man1/%}

localhost.pem: pounce
	./pounce -g $@
