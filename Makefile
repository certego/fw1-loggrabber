# Change the following variables according to your system environment
GCC_PREFIX = /usr
CC_CMD = gcc
LD_CMD = gcc
CC = $(GCC_PREFIX)/bin/$(CC_CMD)
LD = $(GCC_PREFIX)/bin/$(LD_CMD)
PKG_DIR = ../OPSEC_SDK_6_0.linux30
INSTALL_PREFIX = /usr/local/fw1-loggrabber

EXE_NAME = fw1-loggrabber
OBJ_FILES = thread.o queue.o fw1-loggrabber.o

SYSCONFDIR=${INSTALL_PREFIX}/etc
BINDIR=${INSTALL_PREFIX}/bin
MANDIR=${INSTALL_PREFIX}/man
TEMPDIR=/tmp

LIB_DIR = $(PKG_DIR)/lib/release.static
STATIC_LIBS = \
	-lopsec \
	-lsicauth -lsic \
	-lcp_policy \
	-lskey \
	-lndb \
	-lckpssl -lcpcert \
	-lcpcryptutil -lcpprng \
	-lcpbcrypt -lcpca \
	-lasn1cpp \
	-lcpopenssl \
	-lAppUtils -lEventUtils \
	-lEncode -lComUtils \
	-lResolve -lDataStruct \
	-lOS \
	-lcpprod50 

LIBS = -lpthread -lresolv -ldl -lnsl -lelf -lstdc++
CFLAGS += -m32 -g -Wall -fpic -I$(PKG_DIR)/include -DLINUX -DUNIXOS=1 -DDEBUG $(ODBC_CFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $*.c

$(EXE_NAME): $(OBJ_FILES)
	$(LD) $(CFLAGS) -L$(LIB_DIR) -o $@ $(OBJ_FILES) $(STATIC_LIBS) $(LIBS)

install:
	@echo
	@echo "Installing FW1-Loggrabber to ${INSTALL_PREFIX}:"
	@echo
	install -v -d -o root -g root -m 755 ${BINDIR}
	install -v -d -o root -g root -m 755 ${SYSCONFDIR}
	install -v -d -o root -g root -m 755 ${MANDIR}/man1
	install -v -o root -g root -m 755 -p fw1-loggrabber ${BINDIR}/fw1-loggrabber 
	install -v -o root -g root -m 644 -p fw1-loggrabber.conf ${SYSCONFDIR}/fw1-loggrabber.conf 
	install -v -o root -g root -m 644 -p lea.conf ${SYSCONFDIR}/lea.conf 
	install -v -o root -g root -m 644 -p fw1-loggrabber.1 ${MANDIR}/man1/fw1-loggrabber.1
	@echo
	@echo "Installation complete! Please declare the following environment variables in your shell configuration file:"
	@echo
	@echo "  LOGGRABBER_CONFIG_PATH=${SYSCONFDIR}"
	@echo "  export LOGGRABBER_CONFIG_PATH"
	@echo "  LOGGRABBER_TEMP_PATH=${TEMPDIR}"
	@echo "  export LOGGRABBER_TEMP_PATH"
	@echo

clean:
	rm -f *.o $(EXE_NAME)
