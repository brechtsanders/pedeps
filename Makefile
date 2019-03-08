ifeq ($(OS),)
OS = $(shell uname -s)
endif
PREFIX = /usr/local
CC   = gcc
CPP  = g++
AR   = ar
LIBPREFIX = lib
LIBEXT = .a
ifeq ($(OS),Windows_NT)
BINEXT = .exe
SOEXT = .dll
else ifeq ($(OS),Darwin)
BINEXT =
SOEXT = .dylib
else
BINEXT =
SOEXT = .so
endif
INCS = -Ilib
CFLAGS = $(INCS) -Os
CPPFLAGS = $(INCS) -Os
STATIC_CFLAGS = -DBUILD_PEDEPS_STATIC
SHARED_CFLAGS = -DBUILD_PEDEPS_DLL
LIBS =
LDFLAGS =
ifeq ($(OS),Darwin)
STRIPFLAG =
else
STRIPFLAG = -s
endif
MKDIR = mkdir -p
RM = rm -f
RMDIR = rm -rf
CP = cp -f
CPDIR = cp -rf
DOXYGEN := $(shell which doxygen)

libpedeps_OBJ = lib/pedeps.o lib/pestructs.o
libpedeps_LDFLAGS = 
libpedeps_SHARED_LDFLAGS =
ifneq ($(OS),Windows_NT)
SHARED_CFLAGS += -fPIC
endif
ifeq ($(OS),Windows_NT)
libpedeps_SHARED_LDFLAGS += -Wl,--out-implib,$@$(LIBEXT)
endif
ifeq ($(OS),Darwin)
OS_LINK_FLAGS = -dynamiclib -o $@
else
OS_LINK_FLAGS = -shared -Wl,-soname,$@ $(STRIPFLAG)
endif

UTILS_BIN = src/listpedeps$(BINEXT)

COMMON_PACKAGE_FILES = README.md LICENSE Changelog.txt
SOURCE_PACKAGE_FILES = $(COMMON_PACKAGE_FILES) Makefile doc/Doxyfile lib/*.h lib/*.c src/*.c build/*.workspace build/*.cbp

default: all

all: static-lib shared-lib utils

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS) 

%.static.o: %.c
	$(CC) -c -o $@ $< $(STATIC_CFLAGS) $(CFLAGS) 

%.shared.o: %.c
	$(CC) -c -o $@ $< $(SHARED_CFLAGS) $(CFLAGS)

static-lib: $(LIBPREFIX)pedeps$(LIBEXT)

shared-lib: $(LIBPREFIX)pedeps$(SOEXT)

$(LIBPREFIX)pedeps$(LIBEXT): $(libpedeps_OBJ:%.o=%.static.o)
	$(AR) cru $@ $^

$(LIBPREFIX)pedeps$(SOEXT): $(libpedeps_OBJ:%.o=%.shared.o)
	$(CC) -o $@ $(OS_LINK_FLAGS) $^ $(libpedeps_SHARED_LDFLAGS) $(libpedeps_LDFLAGS) $(LDFLAGS) $(LIBS)

utils: $(UTILS_BIN)

src/listpedeps$(BINEXT): src/listpedeps.static.o $(LIBPREFIX)pedeps$(LIBEXT)
	$(CC) -o $@ $(@:%$(BINEXT)=%.static.o) $(LIBPREFIX)pedeps$(LIBEXT) $(libpedeps_LDFLAGS) $(LDFLAGS)

.PHONY: doc
doc:
ifdef DOXYGEN
	$(DOXYGEN) doc/Doxyfile
endif

install: all doc
	$(MKDIR) $(PREFIX)/include $(PREFIX)/lib $(PREFIX)/bin
	$(CP) include/*.h $(PREFIX)/include/
	$(CP) *$(LIBEXT) $(PREFIX)/lib/
ifeq ($(OS),Windows_NT)
	$(CP) *$(SOEXT) $(PREFIX)/bin/
else
	$(CP) *$(SOEXT) $(PREFIX)/lib/
endif
ifdef DOXYGEN
	$(CPDIR) doc/man $(PREFIX)/
endif

#.PHONY: version
version:
	sed -ne "s/^#define\s*PEDEPS_VERSION_[A-Z]*\s*\([0-9]*\)\s*$$/\1./p" lib/pedeps_version.h | tr -d "\n" | sed -e "s/\.$$//" > version

.PHONY: package
package: version
	tar cfJ libpedeps-$(shell cat version).tar.xz --transform="s?^?libpedeps-$(shell cat version)/?" $(SOURCE_PACKAGE_FILES)

.PHONY: package
binarypackage: version
	$(MAKE) PREFIX=binarypackage_temp install
	tar cfJ "libpedeps-$(shell cat version)-$(OS).tar.xz" --transform="s?^binarypackage_temp/??" $(COMMON_PACKAGE_FILES) binarypackage_temp/*
	rm -rf binarypackage_temp

.PHONY: clean
clean:
	$(RM) lib/*.o src/*.o *$(LIBEXT) *$(SOEXT) $(UTILS_BIN) version libpedeps-*.tar.xz doc/doxygen_sqlite3.db
	$(RMDIR) doc/html doc/man

