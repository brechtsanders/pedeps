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

int save_data (void* buf, size_t buflen, void* callbackdata)
{
  fwrite(buf, 1, buflen, (FILE*)callbackdata);
  return 0;
}

/*
struct pefile_list_version_struct {

  void* callbackdata;
};
*/

int pefile_list_version_info_group (struct pefile_resource_directory_struct* info, void* callbackdata)
{
/**/
  if (info->isnamed) {
    wprintf(L"[\"%s\"]\n", info->name);
  } else {
    printf("[%s|%lu]\n", pe_get_resourceid_name(info->id), (unsigned long)info->id);
  }
/**/
  return (info->id == PE_RESOURCE_TYPE_VERSION ? PE_CB_RETURN_CONTINUE : PE_CB_RETURN_SKIP);
}

int pefile_list_version_info (pefile_handle pe_file, struct pefile_resource_directory_struct* info, uint32_t fileposition, uint32_t datalen, uint32_t codepage, void* callbackdata)
{
  int versioninfofound = 0;
  if (info && info->parent && !info->parent->isnamed && info->parent->id == PE_RESOURCE_TYPE_VERSION) {
    struct peheader_versioninfo* versioninfo;
    if ((versioninfo = (struct peheader_versioninfo*)read_data_at(pe_file, fileposition, NULL, datalen)) != NULL) {
//http://systemmanager.ru/windowsce3_0_documentationarchive.en/html/_wcesdk_win32_vs_versioninfo_str.htm
//http://systemmanager.ru/windowsce3_0_documentationarchive.en/html/_wcesdk_win32_vs_fixedfileinfo_str.htm
      if (wcsncmp(versioninfo->szKey, L"VS_VERSION_INFO", 15) == 0) {
        struct peheader_fileinfo_entry* fileinfochild;
        struct peheader_fixedfileinfo* fileinfo = NULL;
        if (versioninfo->wValueLength >= 0) {
          fileinfo = &(versioninfo->Padding1);
          while (fileinfo->dwSignature != 0xFEEF04BD) {
            if ((uint8_t*)fileinfo + sizeof(struct peheader_fixedfileinfo) >= (uint8_t*)versioninfo + versioninfo->wLength) {
              fileinfo = NULL;
              break;
            }
            fileinfo = (struct peheader_versioninfo*)((uint8_t*)fileinfo + 1);
          }
        }
        if (fileinfo) {
          versioninfofound = 1;
          printf("Structure version %lu.%lu\n", (unsigned long)fileinfo->dwStrucVersionHi, (unsigned long)fileinfo->dwStrucVersionLo);
          printf("File version %u.%u.%u.%u\n", (unsigned)fileinfo->dwFileVersion1, (unsigned)fileinfo->dwFileVersion2, (unsigned)fileinfo->dwFileVersion3, (unsigned)fileinfo->dwFileVersion4);
          printf("Product version %u.%u.%u.%u\n", (unsigned)fileinfo->dwProductVersion1, (unsigned)fileinfo->dwProductVersion2, (unsigned)fileinfo->dwProductVersion3, (unsigned)fileinfo->dwProductVersion4);
          printf("File type: %s\n", pe_version_fileinfo_get_type_name(fileinfo->dwFileType));
          printf("File subtype: %s\n", pe_version_fileinfo_get_subtype_name(fileinfo->dwFileType, fileinfo->dwFileSubtype));
          printf("Debugging information: %s\n", (fileinfo->dwFileFlags & PE_VERSION_FILEINFO_FLAG_DEBUG ? "Yes" : "No"));
          //skip padding
          fileinfochild = (struct peheader_fileinfo_entry*)((uint8_t*)fileinfo + versioninfo->wValueLength);
          if (fileinfochild->wLength == 0)
            fileinfochild = (struct peheader_fileinfo_entry*)((uint8_t*)fileinfochild + 2);
          while (fileinfochild->wLength > 0 && (uint8_t*)fileinfochild + fileinfochild->wLength < (uint8_t*)versioninfo + versioninfo->wLength) {
            if (fileinfochild->wType = PE_VERSION_FILEINFO_STRING_TYPE_TEXT) {
              printf("Text version resource\n");
            } else if (fileinfochild->wType = PE_VERSION_FILEINFO_STRING_TYPE_BINARY) {
              printf("Binary version resource\n");
            } else {
              printf("Invalid version resource type\n");
            }
            wprintf(L"-> %s\n", fileinfochild->szKey);/////
            if (wcsncmp(fileinfochild->szKey, L"StringFileInfo", 14) == 0) {
              struct peheader_fileinfo_entry* strtable;
              struct peheader_fileinfo_entry* str;
              strtable = (struct peheader_fileinfo_entry*)(fileinfochild->szKey + 14);
              while ((uint8_t*)strtable + strtable->wLength < (uint8_t*)versioninfo + versioninfo->wLength) {
                //skip padding
                if (strtable->wLength == 0)
                  strtable = (struct peheader_fileinfo_entry*)((uint8_t*)strtable + 2);
                //check data type
                if (strtable->wType = PE_VERSION_FILEINFO_STRING_TYPE_TEXT) {
                  printf("Text string table\n");
                } else if (strtable->wType = PE_VERSION_FILEINFO_STRING_TYPE_BINARY) {
                  printf("Binary string table\n");
                } else {
                  printf("Invalid string table type\n");
                }
                //show table name (= 8-digit hexadecimal language / code page information)
                wprintf(L"- %s\n", strtable->szKey);
                str = (struct peheader_fileinfo_entry*)((uint8_t*)strtable->szKey + 8 * 2);
                if (str->wLength == 0)
                  str = (struct peheader_fileinfo_entry*)((uint8_t*)str + 2);
                while (str->wLength > 0 && (uint8_t*)str + str->wLength < (uint8_t*)strtable + strtable->wLength) {
                  wprintf(L"  - %s = \"%s\"\n", str->szKey, (wchar_t*)((uint8_t*)str + str->wLength) - str->wValueLength);
                  str = (struct peheader_fileinfo_entry*)((uint8_t*)str + str->wLength);
                }
                strtable = (struct peheader_fileinfo_entry*)((uint8_t*)strtable + strtable->wLength);
              }
            } else if (wcsncmp(fileinfochild->szKey, L"VarFileInfo", 11) == 0) {
              struct peheader_fileinfo_entry* strtable;
              struct peheader_fileinfo_entry* str;
              strtable = (struct peheader_fileinfo_entry*)(fileinfochild->szKey + 14);
              while ((uint8_t*)strtable + strtable->wLength < (uint8_t*)versioninfo + versioninfo->wLength) {
                //skip padding
                if (strtable->wLength == 0)
                  strtable = (struct peheader_fileinfo_entry*)((uint8_t*)strtable + 2);
                //check data type
                if (strtable->wType = PE_VERSION_FILEINFO_STRING_TYPE_TEXT) {
                  printf("Text string table\n");
                } else if (strtable->wType = PE_VERSION_FILEINFO_STRING_TYPE_BINARY) {
                  printf("Binary string table\n");
                } else {
                  printf("Invalid string table type\n");
                }
                //show table name (= 8-digit hexadecimal language / code page information)
                wprintf(L"- %s\n", strtable->szKey);

                strtable = (struct peheader_fileinfo_entry*)((uint8_t*)strtable + strtable->wLength);
              }
            }
            fileinfochild = (struct peheader_fileinfo_entry*)((uint8_t*)fileinfochild + fileinfochild->wLength);
          }
        }
      }
      free(versioninfo);
    }
/*
    wprintf(L"%*s\n", (int)datalen / sizeof(wchar_t), (wchar_t*)data);
    /////See also: https://docs.microsoft.com/en-us/windows/win32/menurc/string-str?redirectedfrom=MSDN
*/
  }
  return (versioninfofound ? PE_CB_RETURN_ABORT : PE_CB_RETURN_CONTINUE);
}

int list_resourcegroups (struct pefile_resource_directory_struct* info, void* callbackdata)
{
  if (info->isnamed) {
    wprintf(L"[\"%s\"]\n", info->name);
  } else {
    printf("[%s|%lu]\n", pe_get_resourceid_name(info->id), (unsigned long)info->id);
  }
//if (info->id == 2) return PE_CB_RETURN_LAST;/////
  return PE_CB_RETURN_CONTINUE;
}

int list_resources (pefile_handle pe_file, struct pefile_resource_directory_struct* info, uint32_t fileposition, uint32_t datalen, uint32_t codepage, void* callbackdata)
{
  if (info->isnamed) {
    wprintf(L"- \"%s\"\n", info->name);
  } else {
    printf("- ID: %lu\n", (unsigned long)info->id);
  }

  if (info->parent && info->parent->isnamed && (wcscmp(info->parent->name, L"PNG") == 0 || wcscmp(info->parent->name, L"AVI") == 0)) {
    FILE* dst;
    wchar_t* filename = NULL;
    size_t filenamelen = 0;
    if (info->isnamed) {
      filenamelen = _snwprintf(NULL, 0, L"%s.%s", info->name, info->parent->name);
      if ((filename = (wchar_t*)(malloc((filenamelen + 1) * sizeof(wchar_t)))) != NULL)
        filenamelen = _snwprintf(filename, filenamelen + 1, L"%s.%s", info->name, info->parent->name);
    } else {
      filenamelen = _snwprintf(NULL, 0, L"ID_%" PRIu32 ".%s", info->id, info->parent->name);
      if ((filename = (wchar_t*)(malloc((filenamelen + 1) * sizeof(wchar_t)))) != NULL)
        filenamelen = _snwprintf(filename, filenamelen + 1, L"ID_%" PRIu32 ".%s", info->id, info->parent->name);
    }
    wprintf(L"Saving to file: %s\n", filename);
    if ((dst = _wfopen(filename, L"wb")) != NULL) {
      pefile_read(pe_file, fileposition, datalen, NULL, 0, save_data, (void*)dst);
      fclose(dst);
    }
    free(filename);
  } else

  if (info && info->parent && !info->parent->isnamed && info->parent->id == PE_RESOURCE_TYPE_HTML) {
    void* data;
    printf("Contents:\n");
    if ((data = read_data_at(pe_file, fileposition, NULL, datalen)) != NULL) {
      printf("%*s\n.\n", (int)datalen, (char*)data);
      free(data);
    }
  }
//return PE_CB_RETURN_ABORT;/////
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
    //display version information
    pefile_list_resources(pehandle, pefile_list_version_info_group, pefile_list_version_info, NULL);
    //list resource information
    //pefile_list_resources(pehandle, list_resourcegroups, list_resources, NULL);
    //close PE file
    pefile_close(pehandle);
  }
  //destroy PE object
  pefile_destroy(pehandle);
  return status;
}

