This is only needed for the Windows build. For Linux leave this directory as is.
For Windows, downlaod and extract the latest pthreads-win32 libraries here, get it from https://sourceware.org/pthreads-win32/
The 2.2 build was done using pthreads-w32-2-9-1-release
Download from here: ftp://sourceware.org/pub/pthreads-win32/pthreads-w32-2-9-1-release.zip and extract the content sin this directory
The directory structure would then look like this:
fw1-loggrabber\PTHREADS_SDK
fw1-loggrabber\PTHREADS_SDK\.gitignore
fw1-loggrabber\PTHREADS_SDK
fw1-loggrabber\PTHREADS_SDK\Pre-built.2
fw1-loggrabber\PTHREADS_SDK\pthreads.2
fw1-loggrabber\PTHREADS_SDK\QueueUserAPCEx