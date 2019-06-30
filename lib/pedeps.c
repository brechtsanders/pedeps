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

#include "pedeps_version.h"
#include "pedeps.h"
#include "pestructs.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>

#define READ_STRING_STEP 32

DLL_EXPORT_PEDEPS void pedeps_get_version (int* pmajor, int* pminor, int* pmicro)
{
  if (pmajor)
    *pmajor = PEDEPS_VERSION_MAJOR;
  if (pminor)
    *pminor = PEDEPS_VERSION_MINOR;
  if (pmicro)
    *pmicro = PEDEPS_VERSION_MICRO;
}

DLL_EXPORT_PEDEPS const char* pedeps_get_version_string ()
{
  return PEDEPS_VERSION_STRING;
}

////////////////////////////////////////////////////////////////////////

struct pefile_struct {
  PEio_read_fn read_fn;
  PEio_tell_fn tell_fn;
  PEio_seek_fn seek_fn;
  PEio_close_fn close_fn;
  void* iohandle;
  struct PEheader_DOS dosheader;
  struct PEheader_PE peheader;
  struct PEheader_COFF coffheader;
  union PEheader_optional* optionalheader;
  struct PEheader_data_directory* datadir;
  struct PEheader_optional_commonext* pecommonext;
  struct peheader_imagesection* sections;
};

////////////////////////////////////////////////////////////////////////

static inline struct peheader_imagesection* find_section (pefile_handle pehandle, uint32_t rva)
{
  return PE_find_rva_section(pehandle->sections, pehandle->coffheader.NumberOfSections, rva);
}

void* read_data_at (pefile_handle pehandle, uint32_t offset, void* buf, size_t buflen)
{
  uint64_t origfilepos;
  void* data;
  //allocate buffer dynamically if NULL pointer was given
  if (!buf) {
    if ((data = malloc(buflen)) == NULL)
      return NULL;
  } else {
    data = buf;
  }
  //remember original file position
  origfilepos = (pehandle->tell_fn)(pehandle->iohandle);
  //read data at position
  if ((pehandle->seek_fn)(pehandle->iohandle, offset) != 0 || (pehandle->read_fn)(pehandle->iohandle, data, buflen) < buflen) {
    if (!buf)
      free(data);
    data = NULL;
  }
  //restore original file position
  (pehandle->seek_fn)(pehandle->iohandle, origfilepos);
  return data;
}

char* read_string_at (pefile_handle pehandle, uint32_t offset)
{
  uint64_t origfilepos;
  char* data = NULL;
  size_t dataallocated = 0;
  size_t datalen = 0;
  //remember original file position
  origfilepos = (pehandle->tell_fn)(pehandle->iohandle);
  //read data at position
  if ((pehandle->seek_fn)(pehandle->iohandle, offset) == 0 && (data = (char*)malloc(dataallocated = READ_STRING_STEP)) != NULL) {
    size_t i;
    size_t len;
    //read next block
    while ((len = (pehandle->read_fn)(pehandle->iohandle, data + datalen, READ_STRING_STEP)) > 0) {
      //done if terminating zero was found
      for (i = datalen; i < datalen + len; i++) {
        if (!data[i])
          break;
      }
      datalen += len;
      if (i < datalen)
        break;
      //allocate more data
      if ((data = (char*)realloc(data, dataallocated += READ_STRING_STEP)) == NULL) {
        free(data);
        data = NULL;
        break;
      }
    }
  }
  //restore original file position
  (pehandle->seek_fn)(pehandle->iohandle, origfilepos);
  return data;
}

int pefile_process_import_section (pefile_handle pehandle, struct peheader_imagesection* section, uint32_t fileposition, uint32_t sectionlength, PEfile_list_imports_fn callbackfn, void* callbackdata)
{
  //process import directory
  struct peheader_imageimportdirectory imgimpdir;
  char* modulename;
  uint32_t importlookupvalue;
  int importlookupbyname;
  int done;
  uint64_t oldpos = (pehandle->tell_fn)(pehandle->iohandle);
  uint32_t pos = fileposition;
  int result = 0;
  //iterate trough import directory
  while (pos + sizeof(imgimpdir) <= fileposition + sectionlength && read_data_at(pehandle, pos, &imgimpdir, sizeof(imgimpdir)) && !(imgimpdir.ImportLookupTable == 0 && imgimpdir.TimeDateStamp == 0 && imgimpdir.ForwarderChain == 0 && imgimpdir.Name == 0 && imgimpdir.ImportAddressTable == 0)) {
    //get module name
    modulename = read_string_at(pehandle, imgimpdir.Name - section->VirtualAddress + section->PointerToRawData);
    //position at import lookup table
    (pehandle->seek_fn)(pehandle->iohandle, imgimpdir.ImportLookupTable - section->VirtualAddress + section->PointerToRawData);
    importlookupvalue = 0;
    importlookupbyname = 0;
    done = 0;
    //iterate through import lookup table
    while (result == 0 && !done) {
      switch (pehandle->optionalheader->common.Signature) {
        case PE_SIGNATURE_PE32:
          {
            uint32_t importlookupentry;
            if ((pehandle->read_fn)(pehandle->iohandle, &importlookupentry, sizeof(importlookupentry)) == sizeof(importlookupentry)) {
              if (importlookupentry == 0) {
                done++;
              } else {
                importlookupbyname = ((importlookupentry & 0x80000000) == 0);
                importlookupvalue = importlookupentry & (importlookupbyname ? 0x7FFFFFFF : 0x0000FFFF);
              }
            }
          }
          break;
        case PE_SIGNATURE_PE64:
          {
            uint64_t importlookupentry;
            if ((pehandle->read_fn)(pehandle->iohandle, &importlookupentry, sizeof(importlookupentry)) == sizeof(importlookupentry)) {
              if (importlookupentry == 0) {
                done++;
              } else {
                importlookupbyname = ((importlookupentry & 0x8000000000000000) == 0);
                importlookupvalue = importlookupentry & (importlookupbyname ? 0x000000007FFFFFFF : 0x000000000000FFFF);
              }
            }
          }
          break;
      }
      if (!done) {
        if (importlookupbyname) {
          char* functionname;
          if ((functionname = read_string_at(pehandle, importlookupvalue + 2 - section->VirtualAddress + section->PointerToRawData)) != NULL) {
            result = (*callbackfn)(modulename, functionname, callbackdata);
            free(functionname);
          }
        } else {
          char ordinal[7];
          snprintf(ordinal, sizeof(ordinal), "@%" PRIu16, (uint16_t)importlookupvalue);
          result = (*callbackfn)(modulename, ordinal, callbackdata);
        }
      }
    }
/*
    if (imgimpdir.ForwarderChain)
      printf("ForwarderChain: 0x%08" PRIX32 "\n", imgimpdir.ForwarderChain);/////
*/
    if (modulename)
      free(modulename);
    //move to position of next import directory
    pos += sizeof(imgimpdir);
  }
  (pehandle->seek_fn)(pehandle->iohandle, oldpos);
  return result;
}

int pefile_process_export_section (pefile_handle pehandle, struct peheader_imagesection* section, uint32_t fileposition, uint32_t sectionlength, PEfile_list_exports_fn callbackfn, void* callbackdata)
{
  struct peheader_imageexportdirectory imgexpdir;
  char* modulename;
  char* functionname;
  int isdata;
  char* functionforwardername;
  uint32_t i;
  uint32_t* functionaddr;
  uint32_t* functionnamerva;
  uint16_t* functionnameordinal;
  struct peheader_imagesection* s;
  int result = 0;
  //read export directory
  if (read_data_at(pehandle, fileposition, &imgexpdir, (sectionlength < sizeof(imgexpdir) ? sectionlength : sizeof(imgexpdir))) == NULL)
    return 1;
  //process export directory
  modulename = read_string_at(pehandle, imgexpdir.Name - section->VirtualAddress + section->PointerToRawData);
  //read Export Address Table (EAT)
  if (imgexpdir.AddressOfFunctions && (functionaddr = read_data_at(pehandle, imgexpdir.AddressOfFunctions - section->VirtualAddress + section->PointerToRawData, NULL, sizeof(uint32_t) * imgexpdir.NumberOfFunctions)) != NULL) {
    if (imgexpdir.NumberOfNames == 0) {
      for (i = 0; i < imgexpdir.NumberOfFunctions; i++) {
        isdata = 0;
        if ((s = find_section(pehandle, functionaddr[i])) == NULL || (s /*&& s != section*/ && (s->Characteristics & PE_IMGSECTION_TYPE_CODE) == 0))
          isdata = 1;
        else
          isdata = 0;
        result = (*callbackfn)(modulename, NULL, i + imgexpdir.Base, isdata, NULL, callbackdata);
      }
    } else {
      //read Export Ordinal Table (EOT)
      functionnameordinal = read_data_at(pehandle, imgexpdir.AddressOfNameOrdinals - section->VirtualAddress + section->PointerToRawData, NULL, sizeof(uint16_t) * imgexpdir.NumberOfNames);
      //read Export Name Table (ENT)
      if ((functionnamerva = read_data_at(pehandle, imgexpdir.AddressOfNames - section->VirtualAddress + section->PointerToRawData, NULL, sizeof(uint32_t) * imgexpdir.NumberOfNames)) != NULL) {
        for (i = 0; result == 0 && i < imgexpdir.NumberOfNames; i++) {
          if ((functionname = read_string_at(pehandle, functionnamerva[i] - section->VirtualAddress + section->PointerToRawData)) != NULL) {
            //forwarded function if address points within export section
            //if (functionaddr[functionnameordinal[i]] >= section->VirtualAddress && functionaddr[functionnameordinal[i]] < section->VirtualAddress + section->SizeOfRawData)
            if (functionaddr[functionnameordinal[i]] >= section->VirtualAddress && functionaddr[functionnameordinal[i]] < section->VirtualAddress + sectionlength)
              functionforwardername = read_string_at(pehandle, functionaddr[functionnameordinal[i]] - section->VirtualAddress + section->PointerToRawData);
            else
              functionforwardername = NULL;
            //data entry if function points outside known sections or within non-code section
            if ((s = find_section(pehandle, functionaddr[functionnameordinal[i]])) == NULL || (s /*&& s != section*/ && (s->Characteristics & PE_IMGSECTION_TYPE_CODE) == 0))
              isdata = 1;
            else
              isdata = 0;
            //run callback function, except if function pointer points to current section but outside specified sectionlength
            if (!(functionaddr[functionnameordinal[i]] >= section->VirtualAddress + sectionlength && functionaddr[functionnameordinal[i]] < section->VirtualAddress + section->SizeOfRawData))
              result = (*callbackfn)(modulename, functionname, (functionnameordinal && functionnameordinal[i] <= imgexpdir.NumberOfFunctions ? functionnameordinal[i] + imgexpdir.Base : 0), isdata, functionforwardername, callbackdata);
            if (functionforwardername)
              free(functionforwardername);
            free(functionname);
          }
        }
        free(functionnamerva);
      }
      if (functionnameordinal)
        free(functionnameordinal);
    }
    free(functionaddr);
  }
  free(modulename);
  return result;
}

////////////////////////////////////////////////////////////////////////

DLL_EXPORT_PEDEPS const char* pefile_status_message (int statuscode)
{
  switch (statuscode) {
    case PE_RESULT_SUCCESS:
      return "success";
    case PE_RESULT_OPEN_ERROR:
      return "file open error";
    case PE_RESULT_READ_ERROR:
      return "file read error";
    case PE_RESULT_SEEK_ERROR:
      return "file seek error";
    case PE_RESULT_OUT_OF_MEMORY:
      return "memory allocation error";
    case PE_RESULT_NOT_PE:
      return "not a PE file";
    case PE_RESULT_NOT_PE_LE:
      return "wrong endianness";
    case PE_RESULT_WRONG_IMAGE:
      return "wrong image type";
    default:
      return "(unknown status code)";
  }
}

DLL_EXPORT_PEDEPS pefile_handle pefile_create ()
{
  pefile_handle pe_file;
  if ((pe_file = (struct pefile_struct*)malloc(sizeof(struct pefile_struct))) != NULL) {
    pe_file->read_fn = NULL;
    pe_file->tell_fn = NULL;
    pe_file->seek_fn = NULL;
    pe_file->close_fn = NULL;
    pe_file->iohandle = NULL;
    pe_file->optionalheader = NULL;
    pe_file->datadir = NULL;
    pe_file->pecommonext = NULL;
    pe_file->sections = NULL;
  }
  return pe_file;
}

DLL_EXPORT_PEDEPS int pefile_open_custom (pefile_handle pe_file, void* iohandle, PEio_read_fn read_fn, PEio_tell_fn tell_fn, PEio_seek_fn seek_fn, PEio_close_fn close_fn)
{
  pe_file->read_fn = read_fn;
  pe_file->tell_fn = tell_fn;
  pe_file->seek_fn = seek_fn;
  pe_file->iohandle = iohandle;
  //read DOS header
  if ((pe_file->seek_fn)(pe_file->iohandle, 0) != 0)
    return PE_RESULT_SEEK_ERROR;
  if ((pe_file->read_fn)(pe_file->iohandle, &(pe_file->dosheader), sizeof(struct PEheader_DOS)) != sizeof(struct PEheader_DOS))
    return PE_RESULT_READ_ERROR;
  //check for MZ in the beginning of the file
  if (pe_file->dosheader.e_magic != 0x5A4D)
    return PE_RESULT_NOT_PE;
  //read PE header
  if ((pe_file->seek_fn)(pe_file->iohandle, pe_file->dosheader.e_lfanew) != 0)
    return PE_RESULT_SEEK_ERROR;
  if ((pe_file->read_fn)(pe_file->iohandle, &(pe_file->peheader), sizeof(struct PEheader_PE)) != sizeof(struct PEheader_PE))
    return PE_RESULT_READ_ERROR;
  //check for little endian PE signature
  if (pe_file->peheader.signature != 0x00004550)
    return PE_RESULT_NOT_PE_LE;
  //read COFF header
  if ((pe_file->read_fn)(pe_file->iohandle, &(pe_file->coffheader), sizeof(struct PEheader_COFF)) != sizeof(struct PEheader_COFF))
    return PE_RESULT_READ_ERROR;
  //read optional header
  if (pe_file->coffheader.SizeOfOptionalHeader == 0) {
    pe_file->optionalheader = NULL;
  } else {
    if ((pe_file->optionalheader = malloc(pe_file->coffheader.SizeOfOptionalHeader)) == NULL)
      return PE_RESULT_OUT_OF_MEMORY;
    if ((pe_file->read_fn)(pe_file->iohandle, pe_file->optionalheader, pe_file->coffheader.SizeOfOptionalHeader) != pe_file->coffheader.SizeOfOptionalHeader) {
      free(pe_file->optionalheader);
      pe_file->optionalheader = NULL;
      return PE_RESULT_READ_ERROR;
    }
  }
  //check image signature (267 for 32 bit Windows, 523 for 64 bit Windows, and 263 for a ROM image)
  switch (pe_file->optionalheader->common.Signature) {
    case PE_SIGNATURE_PE32:
      pe_file->pecommonext = &(pe_file->optionalheader->opt32.commonext);
      pe_file->datadir = &(pe_file->optionalheader->opt32.firstdatadir);
      break;
    case PE_SIGNATURE_PE64:
      pe_file->pecommonext = &(pe_file->optionalheader->opt64.commonext);
      pe_file->datadir = &(pe_file->optionalheader->opt64.firstdatadir);
      break;
/*
    case 0x0107:
      imagetype = "ROM";
      break;
    default:
      imagetype = "unknown";
      break;
*/
    default:
      free(pe_file->optionalheader);
      pe_file->optionalheader = NULL;
      return PE_RESULT_WRONG_IMAGE;
  }
  //read all sections
  if ((pe_file->sections = malloc(sizeof(struct peheader_imagesection) * pe_file->coffheader.NumberOfSections)) == NULL) {
    free(pe_file->optionalheader);
    pe_file->optionalheader = NULL;
    return PE_RESULT_OUT_OF_MEMORY;
  }
  if ((pe_file->read_fn)(pe_file->iohandle, pe_file->sections, sizeof(struct peheader_imagesection) * pe_file->coffheader.NumberOfSections) != sizeof(struct peheader_imagesection) * pe_file->coffheader.NumberOfSections) {
    free(pe_file->optionalheader);
    pe_file->optionalheader = NULL;
    free(pe_file->sections);
    pe_file->sections = NULL;
    return PE_RESULT_READ_ERROR;
  }
  return 0;
}

uint64_t PEio_fread (void* iohandle, void* buf, uint64_t buflen)
{
  if (!iohandle)
    return 0;
  return (uint64_t)fread(buf, 1, buflen, (FILE*)iohandle);
}

uint64_t PEio_ftell (void* iohandle)
{
#if defined(_WIN32) && !defined(__MINGW64_VERSION_MAJOR)
  return (uint64_t)ftell((FILE*)iohandle);
#else
  return (uint64_t)ftello((FILE*)iohandle);
#endif
}

int PEio_fseek (void* iohandle, uint64_t pos)
{
#if defined(_WIN32) && !defined(__MINGW64_VERSION_MAJOR)
  return fseek((FILE*)iohandle, (long)pos, SEEK_SET);
#else
  return fseeko((FILE*)iohandle, (off_t)pos, SEEK_SET);
#endif
}

void PEio_fclose (void* iohandle)
{
  fclose((FILE*)iohandle);
}

DLL_EXPORT_PEDEPS int pefile_open_file (pefile_handle pe_file, const char* filename)
{
  FILE* filehandle;
  if ((filehandle = fopen(filename, "rb")) == NULL) {
    return 1;
  }
  return pefile_open_custom(pe_file, filehandle, &PEio_fread, &PEio_ftell, &PEio_fseek, &PEio_fclose);
}

DLL_EXPORT_PEDEPS void pefile_close (pefile_handle pe_file)
{
  if (pe_file->close_fn) {
    (pe_file->close_fn)(pe_file->iohandle);
  }
  pe_file->read_fn = NULL;
  pe_file->tell_fn = NULL;
  pe_file->seek_fn = NULL;
  pe_file->close_fn = NULL;
  pe_file->iohandle = NULL;
  if (pe_file->optionalheader) {
    free(pe_file->optionalheader);
    pe_file->optionalheader = NULL;
  }
  pe_file->datadir = NULL;
  pe_file->pecommonext = NULL;
  if (pe_file->sections) {
    free(pe_file->sections);
    pe_file->sections = NULL;
  }
}

DLL_EXPORT_PEDEPS void pefile_destroy (pefile_handle pe_file)
{
  pefile_close(pe_file);
  free(pe_file);
}

DLL_EXPORT_PEDEPS uint16_t pefile_get_signature (pefile_handle pe_file)
{
  return (pe_file && pe_file->optionalheader ? pe_file->optionalheader->common.Signature : 0);
}

DLL_EXPORT_PEDEPS uint16_t pefile_get_machine (pefile_handle pe_file)
{
  return (pe_file ? pe_file->coffheader.Machine : 0);
}

DLL_EXPORT_PEDEPS uint16_t pefile_get_subsystem (pefile_handle pe_file)
{
  return (pe_file && pe_file->pecommonext ? pe_file->pecommonext->Subsystem : 0);
}

DLL_EXPORT_PEDEPS uint16_t pefile_get_min_os_major (pefile_handle pe_file)
{
  return (pe_file && pe_file->pecommonext ? pe_file->pecommonext->MajorSubsystemVersion : 0);
}

DLL_EXPORT_PEDEPS uint16_t pefile_get_min_os_minor (pefile_handle pe_file)
{
  return (pe_file && pe_file->pecommonext ? pe_file->pecommonext->MinorSubsystemVersion : 0);
}

const char import_section_name[8] = {'.', 'i', 'd', 'a', 't', 'a', 0, 0};

DLL_EXPORT_PEDEPS int pefile_list_imports (pefile_handle pehandle, PEfile_list_imports_fn callbackfn, void* callbackdata)
{
  uint32_t datadirentries = 0;
  switch (pehandle->optionalheader->common.Signature) {
    case PE_SIGNATURE_PE32:
      datadirentries = pehandle->optionalheader->opt32.NumberOfRvaAndSizes;
      break;
    case PE_SIGNATURE_PE64:
      datadirentries = pehandle->optionalheader->opt64.NumberOfRvaAndSizes;
      break;
    default:
      return PE_RESULT_WRONG_IMAGE;
  }

  //process import directory specified in data directory
  uint32_t processedimpdir = 0;
  {
    if (PE_DATA_DIR_IDX_IMPORT < datadirentries && pehandle->datadir[PE_DATA_DIR_IDX_IMPORT].VirtualAddress) {
      struct peheader_imagesection* rvasection;
      if ((rvasection = find_section(pehandle, pehandle->datadir[PE_DATA_DIR_IDX_IMPORT].VirtualAddress)) != NULL) {
        pefile_process_import_section(pehandle, rvasection, pehandle->datadir[PE_DATA_DIR_IDX_IMPORT].VirtualAddress - rvasection->VirtualAddress + rvasection->PointerToRawData, pehandle->datadir[PE_DATA_DIR_IDX_IMPORT].Size, callbackfn, callbackdata);
        processedimpdir = rvasection->PointerToRawData;
      }
    }
  }

  //process each section
  uint16_t currentsection;
  struct peheader_imagesection* section;
  for (currentsection = 0; currentsection < pehandle->coffheader.NumberOfSections; currentsection++) {
    section = &(pehandle->sections[currentsection]);
    if (section->PointerToRawData && section->SizeOfRawData >= sizeof(struct peheader_imageimportdirectory) && memcmp(section->Name, import_section_name, 8) == 0) {
      if (section->PointerToRawData != processedimpdir && section->SizeOfRawData >= sizeof(struct peheader_imageimportdirectory)) {
/////TO DO: test this scenario (additional .idata sections)
/////TO DO: correct addressing
/*
        if (pefile_process_import_section(pehandle, section, section->PointerToRawData, section->SizeOfRawData, callbackfn, callbackdata) != 0)
          break;
*/
      }
    }
  }
  return 0;
}

const char export_section_name[8] = {'.', 'e', 'd', 'a', 't', 'a', 0, 0};

DLL_EXPORT_PEDEPS int pefile_list_exports (pefile_handle pehandle, PEfile_list_exports_fn callbackfn, void* callbackdata)
{
  uint32_t datadirentries = 0;
  switch (pehandle->optionalheader->common.Signature) {
    case PE_SIGNATURE_PE32:
      datadirentries = pehandle->optionalheader->opt32.NumberOfRvaAndSizes;
      break;
    case PE_SIGNATURE_PE64:
      datadirentries = pehandle->optionalheader->opt64.NumberOfRvaAndSizes;
      break;
    default:
      return PE_RESULT_WRONG_IMAGE;
  }

  //process export directory specified in data directory
  uint32_t processedexpdir = 0;
  {
    if (PE_DATA_DIR_IDX_EXPORT < datadirentries && pehandle->datadir[PE_DATA_DIR_IDX_EXPORT].VirtualAddress) {
      struct peheader_imagesection* rvasection;
      if ((rvasection = find_section(pehandle, pehandle->datadir[PE_DATA_DIR_IDX_EXPORT].VirtualAddress)) != NULL) {
        pefile_process_export_section(pehandle, rvasection, pehandle->datadir[PE_DATA_DIR_IDX_EXPORT].VirtualAddress - rvasection->VirtualAddress + rvasection->PointerToRawData, pehandle->datadir[PE_DATA_DIR_IDX_IMPORT].Size, callbackfn, callbackdata);
        processedexpdir = pehandle->datadir[PE_DATA_DIR_IDX_EXPORT].VirtualAddress - rvasection->VirtualAddress + rvasection->PointerToRawData;
      }
    }
  }

  //process each section
  uint16_t currentsection;
  struct peheader_imagesection* section;
  for (currentsection = 0; currentsection < pehandle->coffheader.NumberOfSections; currentsection++) {
    section = &(pehandle->sections[currentsection]);
    if (section->PointerToRawData && section->SizeOfRawData >= sizeof(struct peheader_imageexportdirectory) && memcmp(section->Name, export_section_name, 8) == 0) {
      //process export directory
      if (section->PointerToRawData != processedexpdir && section->SizeOfRawData >= sizeof(struct peheader_imageexportdirectory)) {
        pefile_process_export_section(pehandle, section, section->PointerToRawData, section->SizeOfRawData, callbackfn, callbackdata);
      }
    }
  }
  return 0;
}
