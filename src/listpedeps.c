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
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>

struct progdata_struct
{
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

int main (int argc, char* argv[])
{
  int i;
  int status;
  pefile_handle pehandle;
  struct progdata_struct progdata = {1, NULL};

  //show version number
  printf("pedeps library version: %s\n", pedeps_get_version_string());

  //determine filename
  if (argc <= 1) {
    fprintf(stderr, "Error: no filename given\n");
    return 1;
  }

  //create PE object
  if ((pehandle = pefile_create()) == NULL) {
    fprintf(stderr, "Error creating object\n");
    return 2;
  }

  for (i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-s") == 0) {
      progdata.details = 0;
    } else {
      printf("[%s]\n", argv[i]);
      //open PE file
      if ((status = pefile_open_file(pehandle, argv[i])) != 0) {
        fprintf(stderr, "Error opening PE file %s: %s\n", argv[i], pefile_status_message(status));
        return 3;
      }
      //display information
      printf("architecture: %s\n", pe_get_arch_name(pefile_get_machine(pehandle)));
      printf("machine name: %s\n", pe_get_machine_name(pefile_get_machine(pehandle)));
      printf("subsystem:    %s\n", pe_get_subsystem_name(pefile_get_subsystem(pehandle)));
      printf("minimum Windows version: %" PRIu16 ".%" PRIu16 "\n", pefile_get_min_os_major(pehandle), pefile_get_min_os_minor(pehandle));
      //analyze file
      printf("IMPORTS\n");
      status = pefile_list_imports(pehandle, listimports, &progdata);
      printf("EXPORTS\n");
      status = pefile_list_exports(pehandle, listexports, &progdata);
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

