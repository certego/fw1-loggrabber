GCC_PREFIX = /usr
CC_CMD = gcc
LD_CMD = gcc
CC = $(GCC_PREFIX)/bin/$(CC_CMD)
LD = $(GCC_PREFIX)/bin/$(LD_CMD)

EXE_NAME = fw1-loggrabber
OBJ_FILES = thread.o queue.o fw1-cursor.o fw1-loggrabber.o

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

INSTALL_DIR = /usr/local/fw1-loggrabber
INSTALL_BIN_DIR=${INSTALL_DIR}/bin
INSTALL_ETC_DIR=${INSTALL_DIR}/etc
INSTALL_LIB_DIR=${INSTALL_DIR}/lib
TEMP_DIR=/tmp

%.o: %.c
	$(CC) $(CFLAGS) -I$(OPSEC_INC_DIR) -c -o $@ $*.c

$(EXE_NAME): $(OBJ_FILES)
	$(LD) $(CFLAGS) -L$(OPSEC_LIB_DIR) -o $@ $(OBJ_FILES) $(OPSEC_LIBS) $(SYSTEM_LIBS)

install:
	@echo
	@echo "Installing FW1-Loggrabber to ${INSTALL_DIR}:"
	@echo
	@install -v -o root -g root -m 755 -d ${INSTALL_BIN_DIR}
	@install -v -o root -g root -m 755 -d ${INSTALL_ETC_DIR}
	@install -v -o root -g root -m 755 -d ${INSTALL_LIB_DIR}
	@install -v -o root -g root -m 755 -p fw1-loggrabber ${INSTALL_BIN_DIR}/fw1-loggrabber
	@install -v -o root -g root -m 644 -p fw1-loggrabber.conf ${INSTALL_ETC_DIR}/fw1-loggrabber.conf-sample
	@install -v -o root -g root -m 644 -p lea.conf ${INSTALL_ETC_DIR}/lea.conf-sample
	@install -v -o root -g root -m 644 -t ${INSTALL_LIB_DIR} ${OPSEC_LIB_DIR}/*.so
ifeq ($(shell test -d /etc/ld.so.conf.d && echo -n yes),yes)
	@echo
	@echo "** ldconfig detected, adding ${INSTALL_LIB_DIR}."
	@install -v -o root -g root -m 644 -p install/ldconfig/fw1-loggrabber.conf /etc/ld.so.conf.d/fw1-loggrabber.conf
	rm /etc/ld.so.cache
	ldconfig
	@echo
endif
ifeq ($(shell test -d /etc/systemd/system && echo -n yes),yes)
	@install -v -o root -g root -m 644 -p install/systemd/fw1-loggrabber.service /etc/systemd/system/fw1-loggrabber.service
	systemctl daemon-reload
	systemctl enable fw1-loggrabber
	@echo
	@echo
	@echo "Installation complete! After configuration files are set you may start the service with the following command;"
	@echo
	@echo "  systemctl start fw1-loggrabber"
else
	@echo
	@echo
	@echo "Installation complete! Please declare the following environment variables in your shell configuration file:"
	@echo
	@echo "  LOGGRABBER_CONFIG_PATH=${INSTALL_ETC_DIR}"
	@echo "  export LOGGRABBER_CONFIG_PATH"
	@echo "  LOGGRABBER_TEMP_PATH=${TEMP_DIR}"
	@echo "  export LOGGRABBER_TEMP_PATH"
endif
ifneq ($(shell test -d /etc/ld.so.conf.d && echo -n yes),yes)
	@echo "  LD_LIBRARY_PATH=\$$LD_LIBRARY_PATH:${INSTALL_LIB_DIR}"
	@echo "  export LD_LIBRARY_PATH"
endif
	@echo
	@echo

clean:
	rm -f *.o $(EXE_NAME)
