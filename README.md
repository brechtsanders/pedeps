pedeps
======

Cross-platform C library to read data from PE/PE+ files (the format of Windows .exe and .dll files).

Description
-----------

The pedeps C library provides functions to retrieve data from Windows .exe and .dll files.

These files are in either PE (Windows 32-bit) or PE+ (Windows 64-bit) format, which are extensions of the COFF format.

Currently the library allows iterating through:
- exported symbols
- imported symbols from dependency .dll files

Goal
----
The library was written with the following goals in mind:
- written in standard C, but allows being used by C++
- hiding the complexity of the file format
- portable across different platforms (Windows, macOS, *nix)
- no dependencies

Libraries
---------

The following libraries are provided:
- `-lpedeps` - requires `\#include <pedeps.h>` (and optionally `\#include <pestructs.h>`)

Command line utilities
----------------------
Some command line utilities are included:
- `listpedeps` - show information and list imported and exported symbols
- `copypedeps` - copy file(s) to a folder along with all dependency files

Dependencies
------------
The library has no depencancies.

The utilities have the following dependency:
- [libavl](http://packages.debian.org/search?keywords=libavl-dev) (only for copypedeps)

Building from source
--------------------
### Requirements:
- a C compiler like gcc or clang, on Windows MinGW and MinGW-w64 are supported
- a Linux/Unix shell environment (like bash, which is also present on macOS), on Windows MSYS is supported
- the make command

### Building
- To build run: `make`
- To install run: `make install`
- To install to a specific folder run: `make install PREFIX=/usr/local`

### Microsoft Visual C++
- Building from source using MSVC is not supported. However, binary downloads are available for Windows (both 32-bit and 64-bit). They include a .def file that can be used to generate the .lib file with the following commands (run from a prompt inside the lib folder of the extracted binary package):
  + for Windows 32-bit: `lib /def:pedeps.def /out:pedeps.lib /machine:X86`
  + for Windows 64-bit: `lib /def:pedeps.def /out:pedeps.lib /machine:X64`

License
-------
pedeps is released under the terms of the MIT License (MIT), see LICENSE.txt.

This means you are free to use pedeps in any of your projects, from open source to commercial.
