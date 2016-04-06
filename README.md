# FW1-LogGrabber

FW1-Loggrabber is a command-line tool to grab logfiles from remote Checkpoint devices using OPSEC LEA (Log Export API).

## Installation

Building FW1-LogGrabber is supported for the Linux platform only, and has been tested with:
* Gentoo ~amd64, GNU GCC 5.3.0

FW1-LogGrabber uses API-functions from Checkpoint's [OPSEC SDK 6.0 for Linux 50](http://supportcontent.checkpoint.com/file_download?id=48148). You must take care of downloading the Checkpoint OPSEC SDK and extracting it inside the ``OPSEC_SDK`` folder.

If you are using Ubuntu, install required libraries with ``sudo apt-get install gcc-multilib g++-multilib libelf-dev:i386``. You might also need to tweak some ``Makefile`` variables (e.g. ``CC``, ``LD`` and ``OPSEC_PKG_DIR``) according to your environment.

Then run ``make`` to build and ``sudo make install`` to install into default location ``/usr/local/fw1-loggrabber`` (defined by ``INSTALL_DIR`` variable). Since the binary is dynamically linked, please add ``/usr/local/fw1-loggrabber/lib`` to your ``LD_LIBRARY_PATH``.

## Documentation

Documentation is available both as a [wiki page](https://github.com/certego/fw1-loggrabber/wiki/FW1-LOGGRABBER) and as a [man page](https://raw.githubusercontent.com/certego/fw1-loggrabber/master/fw1-loggrabber.1).

## License

This program is released under the GNU General Public License version 2 (GPLv2).

## Authors

Copyright (c) 2003-2005 Torsten Fellhauer, Xiaodong Lin

Copyright (c) 2014-2016 CERTEGO s.r.l.

All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

## Changelog

* 2.0 - retrieval of all fields (2014/04/14)
    * all fields are retrieved, hardcoded header list is not needed anymore
    * INSTALL.sh script moved to "make install"
    * removed output of field headers (kept "key=value" only)
    * removed datetime format parsing (kept Checkpoint format only)
    * dropped all ODBC- and database-related code
    * building on WIN32 or SOLARIS is no longer supported

* 1.11 - some new features (2005/01/02)
    * separated connection configuration into lea.conf
    * looking for config files in cwd or absolute dir
    * implemented configurable syslog facility
    * implemented authenticated connections to FW-1 4.1
    * implemented failover/reconnect for LEA connections
    * implemented configurable field printorder
    * replaced MySQL support by ODBC support
    * implemented creation of database tables
    * support for MySQL, PostgreSQL, Oracle, DB2 and MSSQL Server
    * added additional filter for "orig"
    * added additional filter values for "action"
    * added INSTALL script to Unix/Linux-distribution
    * created INSTALLER for W32-distribution
    * replace newline character in resource field by (+)

* 1.10 - some new features (2004/09/10)
    * implemented filter rules for audit logs
    * enhanced filter rules (more arguments, negation)
    * implemented option to display all currently supported fields
    * implemented option to process all available logfiles
    * rewrite of documentation (man-page)
    * added the possibility to process all available logfiles
    * disabled connection timeout
    * implemented additional output methods (file, syslog)

* 1.9.2 - bugfixes and some new features (2004/07/07)
    * implemented some so far unsupported fields
    * implemented opsec debug informations
    * fixed some bugs in MySQL support
    * implemented authentication type to use different authentication mechanismns (no documented so far, will be documented in man-page which comes with next major release.)
    * implemented opsec error handling

* 1.9.1 - couple of new features (2004/02/15)
    * usage of configfile for all available options
    * implemented option to use user-defined field separator
    * implemented option to show fieldnames in every logentry or once at the beginning of the output
    * rewrite of log output functions
    * implemented experimental MySQL support
    * Filter option to filter on date/time
    * configurable dateformat
    * Implementation of simple filter rules for audit-logs (starttime, endtime and action)

* 1.8 - bugfixes and some new features (2003/07/04)
    * bugfix in argument processing
    * bugfixes in logentry output
    * implemented --fields option to print out only certain fields
    * implemented OPSEC event handlers for debugging purposes
    * improved argument processing
    * Improved filter processing ('-' for ranges, e.g. rule=1-9)

* 1.7.2 - bugfixes and minor improvements (2003/06/19)
    * bugfix in Makefiles
    * bugfix in argument processing 
    * bugfix in ipaddress presentation of W32 version
    * implemented online-mode for audit-logs

* 1.7.1 - WIN32 build
    * some minor modifications for WIN32

* 1.7 - bugfixes (2003/06/11)
    * bugfixes
    * improved filter parser

* 1.6 - bugfixes (2003/06/09)
    * error handling
    * code improvement

* 1.5 - added new feature (2003/05/27)
    * implemented online mode

* 1.4 - added new feature (2003/05/23)
    * implemented filter rules
 
* 1.3 - added new feature (2003/04/22)
    * implemented access to CP FW-1 4.1 (2000)

* 1.2 - added new feature (2003/04/17)
    * implemented authenticated and encrypted (3DES) Connections using Certificates

* 1.1 - Bugfix (2003/04/16)
    * when using --noresolve, IP-addresses were printed differently under Linux and Solaris

* 1.0 - Initial Version (2003/03/30)
    * get all available FW1-Logfiles
    * get data of one or more FW1-Logfiles

