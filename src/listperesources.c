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

/*
int save_data (void* buf, size_t buflen, void* callbackdata)
{
  fwrite(buf, 1, buflen, (FILE*)callbackdata);
  return 0;
}
*/

int list_resourcegroups (struct pefile_resource_directory_struct* info, void* callbackdata)
{
  if (info->isnamed) {
    wprintf(L"[\"%s\"]\n", info->name);
  } else {
    printf("[%s|%lu]\n", pe_get_resourceid_name(info->id), (unsigned long)info->id);
  }
  return PE_CB_RETURN_CONTINUE;
}

int list_resources (pefile_handle pe_file, struct pefile_resource_directory_struct* info, uint32_t fileposition, uint32_t datalen, uint32_t codepage, void* callbackdata)
{
  if (info->isnamed) {
    wprintf(L"- \"%s\"\n", info->name);
  } else {
    printf("- ID: %lu\n", (unsigned long)info->id);
  }
  if (info && info->parent && !info->parent->isnamed && info->parent->id == PE_RESOURCE_TYPE_HTML) {
    void* data;
    printf("Contents:\n");
    if ((data = read_data_at(pe_file, fileposition, NULL, datalen)) != NULL) {
      printf("%*s\n.\n", (int)datalen, (char*)data);
      free(data);
    }
  }
/*
  if (info && info->parent && !info->parent->isnamed && info->parent->id == PE_RESOURCE_TYPE_HTML) {
    FILE* dst;
    wchar_t* filename = NULL;
    size_t filenamelen = 0;
    if (info->isnamed) {
      filenamelen = _snwprintf(NULL, 0, L"%s.html", info->name);
      if ((filename = (wchar_t*)(malloc((filenamelen + 1) * sizeof(wchar_t)))) != NULL)
        filenamelen = _snwprintf(filename, filenamelen + 1, L"%s.html", info->name);
    } else {
      filenamelen = _snwprintf(NULL, 0, L"ID_%" PRIu32 ".html", info->id);
      if ((filename = (wchar_t*)(malloc((filenamelen + 1) * sizeof(wchar_t)))) != NULL)
        filenamelen = _snwprintf(filename, filenamelen + 1, L"ID_%" PRIu32 ".html", info->id);
    }
    wprintf(L"Saving to file: %s\n", filename);
    if ((dst = _wfopen(filename, L"wb")) != NULL) {
      pefile_read(pe_file, fileposition, datalen, NULL, 0, save_data, (void*)dst);
      fclose(dst);
    }
    free(filename);
  }
*/
/*
  if (info && info->parent && !info->parent->isnamed && info->parent->id == PE_RESOURCE_TYPE_VERSION) {
    uint32_t i;
    uint8_t* data;
    if ((data = (uint8_t*)read_data_at(pe_file, fileposition, NULL, datalen)) != NULL) {
      for (i = 0; i < datalen; i++) {
        printf("%02X  ", (int)data[i]);
      }
      printf("\n");
      free(data);
    }
    wprintf(L"%*s\n", (int)datalen / sizeof(wchar_t), (wchar_t*)data);
    /////See also: https://docs.microsoft.com/en-us/windows/win32/menurc/string-str?redirectedfrom=MSDN
  }
*/
  return PE_CB_RETURN_CONTINUE;
}

int main (int argc, char* argv[])
{
  int i;
  pefile_handle pehandle;
  int status = 0;

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
    printf("[%s]\n", argv[i]);
    //open PE file
    if ((status = pefile_open_file(pehandle, argv[i])) != 0) {
      fprintf(stderr, "Error opening PE file %s: %s\n", argv[i], pefile_status_message(status));
      return 3;
    }
    //display information
    pefile_list_resources(pehandle, list_resourcegroups, list_resources, NULL);
    //close PE file
    pefile_close(pehandle);
  }
  //destroy PE object
  pefile_destroy(pehandle);
  return status;
}

