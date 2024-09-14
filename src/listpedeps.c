/*****************************************************************************
Copyright (C)  2019  Brecht Sanders  All Rights Reserved
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*****************************************************************************/

#include "pestructs.h"
#include "pedeps.h"
#include "pedeps_version.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>

#define APPLICATION_NAME "listpedeps"

struct progdata_struct
{
  int showinfo;
  int showimports;
  int showexports;
  int details;
  char* lastmodule;
};

int listimports (const char* modulename, const char* functionname, void* callbackdata)
{
  struct progdata_struct* progdata = (struct progdata_struct*)callbackdata;
  if (progdata->details) {
    printf("%s: %s\n", modulename, functionname);
  } else {
    if (!progdata->lastmodule || strcmp(modulename, progdata->lastmodule) != 0) {
      if (progdata->lastmodule)
        free(progdata->lastmodule);
      progdata->lastmodule = strdup(modulename);
      printf("%s\n", modulename);
    }
  }
  return 0;
}

int listexports (const char* modulename, const char* functionname, uint16_t ordinal, int isdata, char* functionforwardername, void* callbackdata)
{
  printf("%s: %s @ %" PRIu16 "%s%s%s\n", modulename, functionname, ordinal, (isdata ? " DATA": ""), (functionforwardername ? "; forwarder: " : ""), (functionforwardername ? functionforwardername : ""));
  return 0;
}

void show_help ()
{
  printf(
    "Usage: " APPLICATION_NAME " [-h|-?] [-v] [-n] [-i] [-s] [-x] srcfile [...]\n"
    "Parameters:\n"
    "  -h -?       \tdisplay command line help and exit\n"
    "  -v          \tdisplay version and exit\n"
    "  -n          \tdon't show file info\n"
    "  -i          \tlist imports\n"
    "  -s          \tshort import list without symbols\n"
    "  -x          \tlist exports\n"
    "Description:\n"
    "Lists dependencies of .exe and .dll files.\n"
    "Version: " PEDEPS_VERSION_STRING " (library version: %s)\n"
    "", pedeps_get_version_string()
  );
}

int main (int argc, char* argv[])
{
  int i;
  pefile_handle pehandle;
  struct progdata_struct progdata = {
    .showinfo = 1,
    .showimports = 0,
    .showexports = 0,
    .details = 1,
    .lastmodule = NULL
  };
  int status = 0;

  //check command line arguments
  if (argc <= 1) {
    fprintf(stderr, "Error: no filename given\n");
    show_help();
    return 1;
  }
  if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "-?") == 0 || strcmp(argv[1], "--help") == 0) {
    show_help();
    return 0;
  }
  if (strcmp(argv[1], "-v") == 0 || strcmp(argv[1], "--version") == 0) {
    printf(APPLICATION_NAME " " PEDEPS_VERSION_STRING "\n");
    return 0;
  }

  //create PE object
  if ((pehandle = pefile_create()) == NULL) {
    fprintf(stderr, "Error creating object\n");
    return 2;
  }

  for (i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-n") == 0 || strcmp(argv[i], "--noinfo") == 0) {
      progdata.showinfo = 0;
    } else if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--imports") == 0) {
      progdata.showimports = 1;
    } else if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--short") == 0) {
      progdata.showimports = 1;
      progdata.details = 0;
    } else if (strcmp(argv[i], "-x") == 0 || strcmp(argv[i], "--exports") == 0) {
      progdata.showimports = 1;
    } else {
      printf("[%s]\n", argv[i]);
      //open PE file
      if ((status = pefile_open_file(pehandle, argv[i])) != 0) {
        fprintf(stderr, "Error opening PE file %s: %s\n", argv[i], pefile_status_message(status));
        return 3;
      }
      if (progdata.showinfo) {
        //display information
        uint16_t mach = pefile_get_machine(pehandle);
        int bits = pe_get_machine_bits(mach);
        printf("architecture: %s\n", pe_get_arch_name(mach));
        printf("machine name: %s\n", pe_get_machine_name(mach));
        printf("machine bits: %i-bit\n", bits);
        printf("subsystem:    %s\n", pe_get_subsystem_name(pefile_get_subsystem(pehandle)));
        printf("DLL:          %s\n", (pefile_is_dll(pehandle) ? "yes" : "no"));
        printf("stripped:     %s\n", (pefile_is_stripped(pehandle) ? "yes" : "no"));
        printf("file version: %" PRIu16 ".%" PRIu16 "\n", pefile_get_file_version_major(pehandle), pefile_get_file_version_minor(pehandle));
        printf("minimum OS:   Windows version %" PRIu16 ".%" PRIu16 "\n", pefile_get_min_os_major(pehandle), pefile_get_min_os_minor(pehandle));
        //printf("image base address:  0x%0*" PRIx64 "\n", bits / 4, pefile_get_image_base_address(pehandle));
        printf("image base address:  0x%" PRIx64 "\n", pefile_get_image_base_address(pehandle));
      }
      //list imports
      if (progdata.showimports) {
        printf("IMPORTS\n");
        status = pefile_list_imports(pehandle, listimports, &progdata);
      }
      //list exports
      if (progdata.showexports) {
        printf("EXPORTS\n");
        status = pefile_list_exports(pehandle, listexports, &progdata);
      }
      //close PE file
      pefile_close(pehandle);
      //clean up
      if (progdata.lastmodule) {
        free(progdata.lastmodule);
        progdata.lastmodule = NULL;
      }
    }
  }
  //destroy PE object
  pefile_destroy(pehandle);
  return status;
}

