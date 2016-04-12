# FW1-LogGrabber

FW1-Loggrabber is a command-line tool to grab logfiles from remote Checkpoint devices using OPSEC LEA (Log Export API).

## Installation

Building FW1-LogGrabber is supported for the Linux platform only, and has been tested with:
* Gentoo ~amd64, GNU GCC 5.3.0

FW1-LogGrabber uses API-functions from Checkpoint's [OPSEC SDK 6.0 for Linux 50](http://supportcontent.checkpoint.com/file_download?id=48148). You must take care of downloading the Checkpoint OPSEC SDK and extracting it inside the ``OPSEC_SDK`` folder.

If you are using Ubuntu, install required libraries with ``sudo apt-get install gcc-multilib g++-multilib libelf-dev:i386``. You might also need to tweak some ``Makefile`` variables (e.g. ``CC``, ``LD`` and ``OPSEC_PKG_DIR``) according to your environment.

Then run ``make`` to build and ``sudo make install`` to install into default location ``/usr/local/fw1-loggrabber`` (defined by ``INSTALL_DIR`` variable). Since the binary is dynamically linked, please add ``/usr/local/fw1-loggrabber/lib`` to your ``LD_LIBRARY_PATH``.

## Documentation

Documentation is available as a [GitHub wiki page](https://github.com/certego/fw1-loggrabber/wiki/FW1-LOGGRABBER).

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

