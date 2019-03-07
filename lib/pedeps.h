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

/**
 * @file pedeps.h
 * @brief pedeps library header file with main functions
 * @author Brecht Sanders
 *
 * This header file defines the functions needed to process PE(+) files
 */

#ifndef INCLUDED_PE_IO_H
#define INCLUDED_PE_IO_H

#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint64_t (*PEio_read_fn) (void* handle, void* buf, uint64_t buflen);
typedef uint64_t (*PEio_tell_fn) (void* handle);
typedef int (*PEio_seek_fn) (void* handle, uint64_t pos);
typedef void (*PEio_close_fn) (void* handle);

uint64_t PEio_fread (void* handle, void* buf, uint64_t buflen);
uint64_t PEio_ftell (void* handle);
int PEio_fseek (void* handle, uint64_t pos);
void PEio_fclose (void* handle);

typedef struct pefile_struct* pefile_handle;

#define PE_RESULT_SUCCESS       0
#define PE_RESULT_OPEN_ERROR    1
#define PE_RESULT_READ_ERROR    2
#define PE_RESULT_SEEK_ERROR    3
#define PE_RESULT_OUT_OF_MEMORY 4
#define PE_RESULT_NOT_PE        5
#define PE_RESULT_NOT_PE_LE     6
#define PE_RESULT_WRONG_IMAGE   7

const char* pefile_status_message (int statuscode);

pefile_handle pefile_create ();
int pefile_open_custom (pefile_handle pe_file, void* iohandle, PEio_read_fn read_fn, PEio_tell_fn tell_fn, PEio_seek_fn seek_fn, PEio_close_fn close_fn);
int pefile_open_file (pefile_handle pe_file, const char* filename);
void pefile_close (pefile_handle pe_file);
void pefile_destroy (pefile_handle pe_file);

#define PE_SIGNATURE_PE32       0x010B
#define PE_SIGNATURE_PE64       0x020B

uint16_t pefile_get_signature (pefile_handle pe_file);

#define PE_MACHINE_X86          0x014C
#define PE_MACHINE_X64          0x8664
#define PE_MACHINE_IA64         0x8664

uint16_t pefile_get_machine (pefile_handle pe_file);

#define PE_SUBSYSTEM_WIN_GUI            2
#define PE_SUBSYSTEM_WIN_CONSOLE        3

uint16_t pefile_get_subsystem (pefile_handle pe_file);
uint16_t pefile_get_min_os_major (pefile_handle pe_file);
uint16_t pefile_get_min_os_minor (pefile_handle pe_file);

typedef int (*PEfile_list_imports_fn) (const char* modulename, const char* functionname, void* callbackdata);

int pefile_list_imports (pefile_handle pehandle, PEfile_list_imports_fn callbackfn, void* callbackdata);

typedef int (*PEfile_list_exports_fn) (const char* modulename, const char* functionname, uint16_t ordinal, int isdata, char* functionforwardername, void* callbackdata);

int pefile_list_exports (pefile_handle pehandle, PEfile_list_exports_fn callbackfn, void* callbackdata);

#ifdef __cplusplus
}
#endif

#endif
