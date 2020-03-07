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

/*! \cond PRIVATE */
#if !defined(DLL_EXPORT_PEDEPS)
# if defined(_WIN32) && defined(BUILD_PEDEPS_DLL)
#  define DLL_EXPORT_PEDEPS __declspec(dllexport)
# elif defined(_WIN32) && !defined(STATIC) && !defined(BUILD_PEDEPS_STATIC) && !defined(BUILD_PEDEPS)
#  define DLL_EXPORT_PEDEPS __declspec(dllimport)
# else
#  define DLL_EXPORT_PEDEPS
# endif
#endif
/*! \endcond */

#ifdef __cplusplus
extern "C" {
#endif

/*! \brief get pedeps library version string
 * \param  pmajor        pointer to integer that will receive major version number
 * \param  pminor        pointer to integer that will receive minor version number
 * \param  pmicro        pointer to integer that will receive micro version number
 * \sa     pedeps_get_version_string()
 */
DLL_EXPORT_PEDEPS void pedeps_get_version (int* pmajor, int* pminor, int* pmicro);

/*! \brief get pedeps library version string
 * \return version string
 * \sa     pedeps_get_version()
 */
DLL_EXPORT_PEDEPS const char* pedeps_get_version_string ();

/*! \brief handle type used by pedeps library
 * \sa     pefile_create()
 * \sa     pefile_open_custom()
 * \sa     pefile_open_file()
 * \sa     pefile_close()
 * \sa     pefile_destroy()
 */
typedef struct pefile_struct* pefile_handle;

/*! \brief status result codes used by pedeps library
 * \sa     pefile_status_message()
 * \sa     pefile_open_custom()
 * \sa     pefile_open_file()
 * \sa     pefile_close()
 * \sa     pefile_destroy()
 * \sa     pefile_list_imports()
 * \sa     pefile_list_exports()
 * \name   PE_RESULT_*
 * \{
 */
#define PE_RESULT_SUCCESS       0       /**< success */
#define PE_RESULT_OPEN_ERROR    1       /**< error opening file */
#define PE_RESULT_READ_ERROR    2       /**< error reading file */
#define PE_RESULT_SEEK_ERROR    3       /**< error positiong withing file */
#define PE_RESULT_OUT_OF_MEMORY 4       /**< error allocating memory */
#define PE_RESULT_NOT_PE        5       /**< not a PE file */
#define PE_RESULT_NOT_PE_LE     6       /**< not a little endian PE file */
#define PE_RESULT_WRONG_IMAGE   7       /**< invalid file image type */
/*! @} */

/*! \brief get text message describing the status code
 * \param  statuscode            status code
 * \return text message describing the status code
 * \sa     PE_RESULT_*
 */
DLL_EXPORT_PEDEPS const char* pefile_status_message (int statuscode);

/*! \brief create handle for use with the pedeps library
 * \return handle
 * \sa     pefile_handle
 * \sa     pefile_open_custom()
 * \sa     pefile_open_file()
 * \sa     pefile_close()
 * \sa     pefile_destroy()
 * \sa     pefile_list_imports()
 * \sa     pefile_list_exports()
 */
DLL_EXPORT_PEDEPS pefile_handle pefile_create ();

/*! \brief function type used by pefile_open_custom() for reading data from file
 * \param  iohandle              I/O handle data passed to pefile_open_custom()
 * \param  buf                   buffer where data will be read to
 * \param  buflen                size of \b buf
 * \return number of bytes read
 * \sa     pefile_open_custom()
 * \sa     pefile_create()
 * \sa     PEio_tell_fn
 * \sa     PEio_seek_fn
 * \sa     PEio_close_fn
 */
typedef uint64_t (*PEio_read_fn) (void* iohandle, void* buf, uint64_t buflen);

/*! \brief function type used by pefile_open_custom() for determining file position
 * \param  iohandle              I/O handle data passed to pefile_open_custom()
 * \return file position
 * \sa     pefile_open_custom()
 * \sa     PEio_read_fn
 * \sa     PEio_seek_fn
 * \sa     PEio_close_fn
 */
typedef uint64_t (*PEio_tell_fn) (void* iohandle);

/*! \brief function type used by pefile_open_custom() for positioning within file
 * \param  iohandle              I/O handle data passed to pefile_open_custom()
 * \param  pos                   file position
 * \return 0 on success
 * \sa     pefile_open_custom()
 * \sa     PEio_read_fn
 * \sa     PEio_tell_fn
 * \sa     PEio_close_fn
 */
typedef int (*PEio_seek_fn) (void* iohandle, uint64_t pos);

/*! \brief function type used by pefile_open_custom() for closing file
 * \param  iohandle              I/O handle data passed to pefile_open_custom()
 * \sa     pefile_open_custom()
 * \sa     PEio_read_fn
 * \sa     PEio_tell_fn
 * \sa     PEio_seek_fn
 */
typedef void (*PEio_close_fn) (void* iohandle);

/*! \brief function type used by pefile_open_custom() for positioning within file
 * \param  pe_file               handle as returned by pefile_create()
 * \param  iohandle              I/O handle data to be passed passed to the custom functions
 * \param  read_fn               custom function for reading data from file
 * \param  tell_fn               custom function for determining file position
 * \param  seek_fn               custom function for positioning within file
 * \param  close_fn              custom function for closing file (NULL to leave open)
 * \return 0 on success or one of the PE_RESULT_* status result codes
 * \sa     pefile_create()
 * \sa     pefile_open_file()
 * \sa     PEio_read_fn
 * \sa     PEio_tell_fn
 * \sa     PEio_seek_fn
 * \sa     PEio_close_fn
 * \sa     PE_RESULT_*
 */
DLL_EXPORT_PEDEPS int pefile_open_custom (pefile_handle pe_file, void* iohandle, PEio_read_fn read_fn, PEio_tell_fn tell_fn, PEio_seek_fn seek_fn, PEio_close_fn close_fn);

/*! \brief function type used by pefile_open_custom() for positioning within file
 * \param  pe_file               handle as returned by pefile_create()
 * \param  filename              path of file to open
 * \return 0 on success or one of the PE_RESULT_* status result codes
 * \sa     pefile_create()
 * \sa     pefile_open_custom()
 * \sa     PE_RESULT_*
 */
DLL_EXPORT_PEDEPS int pefile_open_file (pefile_handle pe_file, const char* filename);

/*! \brief close open file
 * \param  pe_file               handle as returned by pefile_create()
 * \sa     pefile_open_custom()
 * \sa     pefile_open_file()
 * \sa     pefile_destroy()
 */
DLL_EXPORT_PEDEPS void pefile_close (pefile_handle pe_file);

/*! \brief clean up handle and associated data
 * \param  pe_file               handle as returned by pefile_create()
 * \sa     pefile_create()
 * \sa     pefile_destroy()
 */
DLL_EXPORT_PEDEPS void pefile_destroy (pefile_handle pe_file);

/*! \brief PE file format identifiers as returned by pefile_get_signature()
 * \sa     pefile_get_signature()
 * \name   PE_SIGNATURE_*
 * \{
 */
/*! \brief Windows 32-bit PE file */
#define PE_SIGNATURE_PE32       0x010B
/*! \brief Windows 64-bit PE+ file */
#define PE_SIGNATURE_PE64       0x020B
/*! @} */

/*! \brief get PE file format identifier
 * \param  pe_file               handle as returned by pefile_create()
 * \return file format identifier
 * \sa     pefile_create()
 * \sa     PE_SIGNATURE_*
 */
DLL_EXPORT_PEDEPS uint16_t pefile_get_signature (pefile_handle pe_file);

/*! \brief machine architecture identifiers as returned by pefile_get_machine()
 * \sa     pefile_get_machine()
 * \name   PE_MACHINE_*
 * \{
 */
#define PE_MACHINE_X86          0x014C          /**< Windows x86 (32-bit) */
#define PE_MACHINE_X64          0x8664          /**< Windows AMD64 (64-bit) */
#define PE_MACHINE_IA64         0x8664          /**< Windows Itanium */
/*! @} */

/*! \brief get machine architecture identifier
 * \param  pe_file               handle as returned by pefile_create()
 * \return machine architecture identifier
 * \sa     pefile_create()
 * \sa     PE_MACHINE_*
 */
DLL_EXPORT_PEDEPS uint16_t pefile_get_machine (pefile_handle pe_file);

/*! \brief OS subsystem identifiers as returned by pefile_get_subsystem()
 * \sa     pefile_get_subsystem()
 * \name   PE_SUBSYSTEM_*
 * \{
 */
#define PE_SUBSYSTEM_WIN_GUI            2       /**< Windows GUI application */
#define PE_SUBSYSTEM_WIN_CONSOLE        3       /**< Windows console application */
/*! @} */

/*! \brief get OS subsystem identifier
 * \param  pe_file               handle as returned by pefile_create()
 * \return OS subsystem identifier
 * \sa     pefile_create()
 * \sa     PE_SUBSYSTEM_*
 */
DLL_EXPORT_PEDEPS uint16_t pefile_get_subsystem (pefile_handle pe_file);

/*! \brief get major version number of minimum spported OS version
 * \param  pe_file               handle as returned by pefile_create()
 * \return major version number of minimum spported OS version
 * \sa     pefile_get_min_os_minor()
 * \sa     pefile_create()
 */
DLL_EXPORT_PEDEPS uint16_t pefile_get_min_os_major (pefile_handle pe_file);

/*! \brief get minor version number of minimum spported OS version
 * \param  pe_file               handle as returned by pefile_create()
 * \return minor version number of minimum spported OS version
 * \sa     pefile_get_min_os_major()
 * \sa     pefile_create()
 */
DLL_EXPORT_PEDEPS uint16_t pefile_get_min_os_minor (pefile_handle pe_file);

/*! \brief get major file version number
 * \param  pe_file               handle as returned by pefile_create()
 * \return major version number of file version
 * \sa     pefile_get_file_version_minor()
 * \sa     pefile_create()
 */
DLL_EXPORT_PEDEPS uint16_t pefile_get_file_version_major (pefile_handle pe_file);

/*! \brief get minjor file version number
 * \param  pe_file               handle as returned by pefile_create()
 * \return minor version number of file version
 * \sa     pefile_get_file_version_major()
 * \sa     pefile_create()
 */
DLL_EXPORT_PEDEPS uint16_t pefile_get_file_version_minor (pefile_handle pe_file);

/*! \brief determine if file is a DLL
 * \param  pe_file               handle as returned by pefile_create()
 * \return non-zero if file is a DLL file, otherwise zero (EXE file)
 * \sa     pefile_create()
 */
DLL_EXPORT_PEDEPS int pefile_is_dll (pefile_handle pe_file);

/*! \brief determine if debugging information was stripped
 * \param  pe_file               handle as returned by pefile_create()
 * \return non-zero if debugging information was stripped, otherwise zero
 * \sa     pefile_create()
 */
DLL_EXPORT_PEDEPS int pefile_is_stripped (pefile_handle pe_file);

/*! \brief callback function called by pefile_list_imports() for each imported symbol
 * \param  modulename            name of module file where symbol is imported from
 * \param  functionname          name of imported symbol
 * \param  callbackdata          callback data passed via pefile_list_imports()
 * \return 0 to continue processing, non-zero to abort
 * \sa     pefile_list_imports()
 */
typedef int (*PEfile_list_imports_fn) (const char* modulename, const char* functionname, void* callbackdata);

/*! \brief iterate through all imported symbols
 * \param  pe_file               handle as returned by pefile_create()
 * \param  callbackfn            callback function called for each imported symbol
 * \param  callbackdata          callback data passed to \b callbackfn
 * \return 0 on success or one of the PE_RESULT_* status result codes
 * \sa     pefile_create()
 * \sa     PEfile_list_imports_fn
 */
DLL_EXPORT_PEDEPS int pefile_list_imports (pefile_handle pe_file, PEfile_list_imports_fn callbackfn, void* callbackdata);

/*! \brief callback function called by PEfile_list_exports_fn() for each exported symbol
 * \param  modulename            name of module file (should match the file being processed)
 * \param  functionname          name of exported symbol
 * \param  ordinal               ordinal number of exported symbol
 * \param  isdata                0 for function, non-zero for data variable
 * \param  functionforwardername name of forwarder function (notation: module.function) or NULL of not forwarded
 * \param  callbackdata          callback data passed via pefile_list_exports()
 * \return 0 to continue processing, non-zero to abort
 * \sa     pefile_list_exports()
 * \sa     pefile_create()
 */
typedef int (*PEfile_list_exports_fn) (const char* modulename, const char* functionname, uint16_t ordinal, int isdata, char* functionforwardername, void* callbackdata);

/*! \brief iterate through all exported symbols
 * \param  pe_file               handle as returned by pefile_create()
 * \param  callbackfn            callback function called for each exported symbol
 * \param  callbackdata          callback data passed to \b callbackfn
 * \return 0 on success or one of the PE_RESULT_* status result codes
 * \sa     pefile_create()
 * \sa     PEfile_list_exports_fn
 */
DLL_EXPORT_PEDEPS int pefile_list_exports (pefile_handle pe_file, PEfile_list_exports_fn callbackfn, void* callbackdata);

#ifdef __cplusplus
}
#endif

#endif
