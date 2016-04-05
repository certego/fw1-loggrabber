GCC_PREFIX = /usr
CC_CMD = gcc
LD_CMD = gcc
CC = $(GCC_PREFIX)/bin/$(CC_CMD)
LD = $(GCC_PREFIX)/bin/$(LD_CMD)

EXE_NAME = fw1-loggrabber
OBJ_FILES = thread.o queue.o fw1-loggrabber.o

CFLAGS += -m32 -g -Wall -fpic -DLINUX -DUNIXOS=1 -DDEBUG
SYSTEM_LIBS = -lpthread -lresolv -ldl -lnsl -lelf -lstdc++ -lz

OPSEC_PKG_DIR = OPSEC_SDK/pkg_rel
OPSEC_INC_DIR = $(OPSEC_PKG_DIR)/include
OPSEC_LIB_DIR = $(OPSEC_PKG_DIR)/lib/release.dynamic
OPSEC_LIBS = \
	-lopsec \
	-lcpprod50 \
	-lsicauth \
	-lskey \
	-lfwsetdb \
	-lndb \
	-lsic \
	-lcp_policy \
	-lcpca \
	-lckpssl \
	-lcpcert \
	-lcpcryptutil \
	-lEncode \
	-lcpprng \
	-lProdUtils \
	-lcpbcrypt \
	-lcpopenssl \
	-lAppUtils \
	-lComUtils \
	-lResolve \
	-lEventUtils \
	-lDataStruct \
	-lOS

INSTALL_PREFIX = /usr/local/fw1-loggrabber
SYSCONFDIR=${INSTALL_PREFIX}/etc
BINDIR=${INSTALL_PREFIX}/bin
MANDIR=${INSTALL_PREFIX}/man
TEMPDIR=/tmp

%.o: %.c
	$(CC) $(CFLAGS) -I$(OPSEC_INC_DIR) -c -o $@ $*.c

$(EXE_NAME): $(OBJ_FILES)
	$(LD) $(CFLAGS) -L$(OPSEC_LIB_DIR) -o $@ $(OBJ_FILES) $(OPSEC_LIBS) $(SYSTEM_LIBS)

install:
	@echo
	@echo "Installing FW1-Loggrabber to ${INSTALL_PREFIX}:"
	@echo
	install -v -d -o root -g root -m 755 ${BINDIR}
	install -v -d -o root -g root -m 755 ${SYSCONFDIR}
	install -v -d -o root -g root -m 755 ${MANDIR}/man1
	install -v -o root -g root -m 755 -p fw1-loggrabber ${BINDIR}/fw1-loggrabber
	install -v -o root -g root -m 644 -p fw1-loggrabber.conf ${SYSCONFDIR}/fw1-loggrabber.conf-sample
	install -v -o root -g root -m 644 -p lea.conf ${SYSCONFDIR}/lea.conf-sample
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
