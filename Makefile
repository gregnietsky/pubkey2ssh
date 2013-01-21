PREFIX=/usr
BINDIR=$(PREFIX)/bin

CC=gcc
INSTALL=ginstall

PROGNAME=pubkey2ssh
LIBS=-lcrypto


all:	$(PROGNAME)
distclean:	clean

clean:
	rm $(PROGNAME)

install: all
	$(INSTALL) -D $(PROGNAME) $(DESTDIR)$(BINDIR)/$(PROGNAME)

$(PROGNAME):
	$(CC) $(PROGNAME).c -o $(PROGNAME) $(LIBS)
