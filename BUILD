***********************************************************************
FW1-LOGGRABBER

Author:           Torsten Fellhauer <torsten@fellhauer-web.de>
current Version:  1.10
***********************************************************************

Copyright (c) 2004 Torsten Fellhauer, Xiaodong Lin 
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:
1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
SUCH DAMAGE.
***********************************************************************

PREREQUISITES FOR BUILDING FW1-LOGGRABBER
=========================================
FW1-LOGGRABBER uses API-functions from Checkpoints'
OPSEC SDK. In order to be able to build applications 
which are using this SDK, a very special build environ-
ment has to be used. Currently building FW1-LOGGRABBER is
supported only for Solaris SPARC platform and the Linux
platform.
* Linux
  - Red Hat 6.2
  - gcc 2.95.1
  - Checkpoint OPSEC SDK NG-FP3 for Linux 2.2
  - for experimental MySQL-Support MySQL-Client-Libraries
    and ZLib-Libraries are required
* Solaris SPARC
  - Solaris 8
  - gcc 2.95.2
  - Checkpoint OPSEC SDK NG-FP3 for Solaris SPARC
* Windows
  - Windows NT/2000
  - MS Visual Studio 6.0 SP5
  - Checkpoint OPSEC SDK NG-FP3 for Windows NT/2000


HOW TO BUILD FW1-LOGGRABBER
===========================
a) Set up the Build Environment for Linux

- Install a machine with Red Hat 6.2
- Download Checkpoints Opsec SDK (NG) for Linux
- Untar the Opsec SDK and move the Directory to
  e.g. /opt/CPsdk-NG
- Compile and install gcc 2.95.1 (install-prefix
  e.g. /opt/CPsdk-NG/gcc)
- Untar fw1-loggrabber
- Copy Makefile.linux to Makefile
- Edit the Makefile and change the variables CC, 
  LD and PKG_DIR according to your environment
- uncomment MySQL lines in makefile to enable
  experimental MySQL-Support
- Edit the Makefile and change the MYSQL_LIBS 
  variable according to your environment
- make

b) Set up the Build Environment for Solaris

- Install a machine with Solaris 8
- Download Checkpoints Opsec SDK (NG) for Solaris gcc
- Untar the Opsec SDK and move the Directory to
  e.g. /opt/CPsdk-NG
- Compile and install gcc 2.95.2 (install-prefix
  e.g. /opt/CPsdk-NG/gcc)
- Untar fw1-loggrabber
- Copy Makefile.solaris to Makefile
- Edit the Makefile and change the variables CC, 
  LD and PKG_DIR according to your environment
- make

b) Set up the Build Environment for Windows

- Use a Windows NT or Windows 2000 Workstation
- Download Checkpoints Opsec SDK (NG) for Windows NT/2000
- Unpack the Opsec SDK and move the Directory to
  e.g. C:\Opsec-SDK
- Install Microsoft Visual Studio 6.0 SP5
- Untar fw1-loggrabber
- Use Visual C++ Project File (fw1-loggrabber.dsp)
  for preferences
- build

