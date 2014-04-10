#!/bin/sh

PREFIX=/usr/local/fw1-loggrabber
SYSCONFDIR=${PREFIX}/etc
BINDIR=${PREFIX}/bin
MANDIR=${PREFIX}/man
DOCDIR=${PREFIX}/share/fw1-loggrabber
TEMPDIR=/tmp

INSTALLBINARY=install
ECHOBINARY=echo

OS=`uname`

${ECHOBINARY}
${ECHOBINARY} "Installing FW1-Loggrabber to ${PREFIX}"
${ECHOBINARY}

if [ "$OS" = "SunOS" ]
then
	${INSTALLBINARY} -d -u root -g root -m 755 ${BINDIR}
	${INSTALLBINARY} -d -u root -g root -m 755 ${SYSCONFDIR}
	${INSTALLBINARY} -d -u root -g root -m 755 ${MANDIR}/man1
	${INSTALLBINARY} -d -u root -g root -m 755 ${DOCDIR}
	${INSTALLBINARY} -f ${BINDIR} -u root -g root -m 755 fw1-loggrabber
	${INSTALLBINARY} -f ${SYSCONFDIR} -u root -g root -m 644 fw1-loggrabber.conf
	${INSTALLBINARY} -f ${SYSCONFDIR} -u root -g root -m 644 lea.conf
	${INSTALLBINARY} -f ${MANDIR}/man1 -u root -g root -m 644 fw1-loggrabber.1
	${INSTALLBINARY} -f ${DOCDIR} -u root -g root -m 644 CHANGES
fi

if [ "$OS" = "Linux" ]
then
	${INSTALLBINARY} -v -d -o root -g root -m 755 ${BINDIR}
	${INSTALLBINARY} -v -d -o root -g root -m 755 ${SYSCONFDIR}
	${INSTALLBINARY} -v -d -o root -g root -m 755 ${MANDIR}/man1
	${INSTALLBINARY} -v -d -o root -g root -m 755 ${DOCDIR}
	${INSTALLBINARY} -v -o root -g root -m 755 -p fw1-loggrabber ${BINDIR}/fw1-loggrabber 
	${INSTALLBINARY} -v -o root -g root -m 644 -p fw1-loggrabber.conf ${SYSCONFDIR}/fw1-loggrabber.conf 
	${INSTALLBINARY} -v -o root -g root -m 644 -p lea.conf ${SYSCONFDIR}/lea.conf 
	${INSTALLBINARY} -v -o root -g root -m 644 -p fw1-loggrabber.1 ${MANDIR}/man1/fw1-loggrabber.1
	${INSTALLBINARY} -v -o root -g root -m 644 -p CHANGES ${DOCDIR}/CHANGES
fi

${ECHOBINARY}
${ECHOBINARY} "Installation complete. Please declare the following environment"
${ECHOBINARY} "variables in your shell configuration file:"
${ECHOBINARY} "  LOGGRABBER_CONFIG_PATH=${SYSCONFDIR}"
${ECHOBINARY} "  export LOGGRABBER_CONFIG_PATH"
${ECHOBINARY} "  LOGGRABBER_TEMP_PATH=${TEMPDIR}"
${ECHOBINARY} "  export LOGGRABBER_TEMP_PATH"
${ECHOBINARY}
