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
 * @file pestructs.h
 * @brief pedeps library header file with PE(+) data structures
 * @author Brecht Sanders
 *
 * This header file defines the structures needed by the pedeps library
 */

#ifndef INCLUDED_PE_STRUCTURES_H
#define INCLUDED_PE_STRUCTURES_H

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

/*! \brief DOS header
*/
struct PEheader_DOS {
  uint16_t e_magic;             /**< Magic number */
  uint16_t e_cblp;              /**< Bytes on last page of file */
  uint16_t e_cp;                /**< Pages in file */
  uint16_t e_crlc;              /**< Relocations */
  uint16_t e_cparhdr;           /**< Size of header in paragraphs */
  uint16_t e_minalloc;          /**< Minimum extra paragraphs needed */
  uint16_t e_maxalloc;          /**< Maximum extra paragraphs needed */
  uint16_t e_ss;                /**< Initial (relative) SS value */
  uint16_t e_sp;                /**< Initial SP value */
  uint16_t e_csum;              /**< Checksum */
  uint16_t e_ip;                /**< Initial IP value */
  uint16_t e_cs;                /**< Initial (relative) CS value */
  uint16_t e_lfarlc;            /**< File address of relocation table */
  uint16_t e_ovno;              /**< Overlay number */
  uint16_t e_res[4];            /**< Reserved words */
  uint16_t e_oemid;             /**< OEM identifier (for e_oeminfo) */
  uint16_t e_oeminfo;           /**< OEM information; e_oemid specific */
  uint16_t e_res2[10];          /**< Reserved words */
  uint32_t e_lfanew;            /**< File address of new exe header */
};

/*! \brief PE header
 * \sa     PE_SIGNATURE_*
 */
struct PEheader_PE {
  uint32_t signature;           /**< PE file signature */
};

/*! \brief COFF header
 * \sa     PE_CHARACTERISTIC_*
*/
struct PEheader_COFF {
  uint16_t Machine;                 /**< The number that identifies the type of target machine. */
  uint16_t NumberOfSections;        /**< The number of sections. This indicates the size of the section table, which immediately follows the headers. */
  uint32_t TimeDateStamp;           /**< The low 32 bits of the number of seconds since 00:00 January 1, 1970 (a C run-time time_t value), that indicates when the file was created. */
  uint32_t PointerToSymbolTable;    /**< The file offset of the COFF symbol table, or zero if no COFF symbol table is present. This value should be zero for an image because COFF debugging information is deprecated. */
  uint32_t NumberOfSymbols;         /**< The number of entries in the symbol table. This data can be used to locate the string table, which immediately follows the symbol table. This value should be zero for an image because COFF debugging information is deprecated. */
  uint16_t SizeOfOptionalHeader;    /**< The size of the optional header, which is required for executable files but not for object files. This value should be zero for an object file. */
  uint16_t Characteristics;         /**< The flags that indicate the attributes of the file. */
};

/*! \brief PE/COFF header charachteristics masks
 * \sa     PEheader_COFF
 * \name   PE_CHARACTERISTIC_*
 * \{
 */
#define PE_CHARACTERISTIC_IMAGE_FILE_RELOCS_STRIPPED		      0x0001	/**< Relocation information was stripped from the file. The file must be loaded at its preferred base address. If the base address is not available, the loader reports an error. */
#define PE_CHARACTERISTIC_IMAGE_FILE_EXECUTABLE_IMAGE	      	0x0002	/**< The file is executable (there are no unresolved external references). */
#define PE_CHARACTERISTIC_IMAGE_FILE_LINE_NUMS_STRIPPED   		0x0004	/**< COFF line numbers were stripped from the file. */
#define PE_CHARACTERISTIC_IMAGE_FILE_LOCAL_SYMS_STRIPPED	    0x0008	/**< COFF symbol table entries were stripped from file. */
#define PE_CHARACTERISTIC_IMAGE_FILE_AGGRESIVE_WS_TRIM    		0x0010	/**< Aggressively trim the working set. This value is obsolete. */
#define PE_CHARACTERISTIC_IMAGE_FILE_LARGE_ADDRESS_AWARE    	0x0020	/**< The application can handle addresses larger than 2 GB. */
#define PE_CHARACTERISTIC_IMAGE_FILE_BYTES_REVERSED_LO	    	0x0080	/**< The bytes of the word are reversed. This flag is obsolete. */
#define PE_CHARACTERISTIC_IMAGE_FILE_32BIT_MACHINE		        0x0100	/**< The computer supports 32-bit words. */
#define PE_CHARACTERISTIC_IMAGE_FILE_DEBUG_STRIPPED		        0x0200	/**< Debugging information was removed and stored separately in another file. */
#define PE_CHARACTERISTIC_IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP	0x0400	/**< If the image is on removable media, copy it to and run it from the swap file. */
#define PE_CHARACTERISTIC_IMAGE_FILE_NET_RUN_FROM_SWAP		    0x0800	/**< If the image is on the network, copy it to and run it from the swap file. */
#define PE_CHARACTERISTIC_IMAGE_FILE_SYSTEM			              0x1000	/**< The image is a system file. */
#define PE_CHARACTERISTIC_IMAGE_FILE_DLL			                0x2000	/**< The image is a DLL file. While it is an executable file, it cannot be run directly. */
#define PE_CHARACTERISTIC_IMAGE_FILE_UP_SYSTEM_ONLY		        0x4000	/**< The file should be run only on a uniprocessor computer. */
#define PE_CHARACTERISTIC_IMAGE_FILE_BYTES_REVERSED_HI		    0x8000	/**< The bytes of the word are reversed. This flag is obsolete. */
/*! @} */

/*! \brief common section in the beginning of the optional header
*/
struct PEheader_optional_common {
  uint16_t Signature;                 /**< The unsigned integer that identifies the state of the image file. Decimal number 267 for 32 bit, 523 for 64 bit, and 263 for a ROM image. */
  uint8_t MajorLinkerVersion;         /**< The linker major version number. */
  uint8_t MinorLinkerVersion;         /**< The linker minor version number. */
  uint32_t SizeOfCode;                /**< The size of the code (text) section, or the sum of all code sections if there are multiple sections. */
  uint32_t SizeOfInitializedData;     /**< The size of the initialized data section, or the sum of all such sections if there are multiple data sections */
  uint32_t SizeOfUninitializedData;   /**< The size of the uninitialized data section (BSS), or the sum of all such sections if there are multiple BSS sections. */
  uint32_t AddressOfEntryPoint;       /**< The RVA of the code entry point. The address of the entry point relative to the image base when the executable file is loaded into memory. For program images, this is the starting address. For device drivers, this is the address of the initialization function. An entry point is optional for DLLs. When no entry point is present, this field must be zero. */
  uint32_t BaseOfCode;                /**< The address that is relative to the image base of the beginning-of-code section when it is loaded into memory. */
};

/*! \brief data directory
 * \sa     PE_DATA_DIR_IDX_*
*/
struct PEheader_data_directory {
  uint32_t VirtualAddress;            /**< RVA of the table. The RVA is the address of the table relative to the base address of the image when the table is loaded. */
  uint32_t Size;                      /**< Size in bytes. */
};

/*! \brief data directory indices
 * \sa     PEheader_data_directory
 * \name   PE_DATA_DIR_IDX_*
 * \{
 */
#define PE_DATA_DIR_IDX_EXPORT          0     /**< export directory */
#define PE_DATA_DIR_IDX_IMPORT          1     /**< import directory */
#define PE_DATA_DIR_IDX_RESOURCE        2     /**< resource directory */
#define PE_DATA_DIR_IDX_EXCEPTION       3     /**< exception directory */
#define PE_DATA_DIR_IDX_SECURITY        4     /**< security directory */
#define PE_DATA_DIR_IDX_BASERELOC       5     /**< base relocation table */
#define PE_DATA_DIR_IDX_DEBUG           6     /**< debug directory */
#define PE_DATA_DIR_IDX_ARCHITECTURE    7     /**< architecture specific data */
#define PE_DATA_DIR_IDX_GLOBALPTR       8     /**< RVA of GP */
#define PE_DATA_DIR_IDX_TLS             9     /**< TLS directory */
#define PE_DATA_DIR_IDX_LOAD_CONFIG    10     /**< load configuration directory */
#define PE_DATA_DIR_IDX_BOUND_IMPORT   11     /**< bound import directory in headers */
#define PE_DATA_DIR_IDX_IAT            12     /**< import address table */
#define PE_DATA_DIR_IDX_DELAY_IMPORT   13     /**< delay load import descriptors */
#define PE_DATA_DIR_IDX_COM_DESCRIPTOR 14     /**< COM runtime descriptor */
#define PE_DATA_DIR_IDX_RESERVED       15     /**< reserved for future use */
#define PE_DATA_DIR_IDX_COUNT          16     /**< number of indeces defined */
/*! @} */

/*! \brief common section within the optional header
 * \sa     PE_DLLCHARACTERISTICS_*
*/
struct PEheader_optional_commonext {
  uint32_t SectionAlignment;          /**< The alignment (in bytes) of sections when they are loaded into memory. It must be greater than or equal to FileAlignment. The default is the page size for the architecture. */
  uint32_t FileAlignment;             /**< The alignment factor (in bytes) that is used to align the raw data of sections in the image file. The value should be a power of 2 between 512 and 64 K, inclusive. The default is 512. If the SectionAlignment is less than the architecture's page size, then FileAlignment must match SectionAlignment. */
  uint16_t MajorOSVersion;            /**< The major version number of the required operating system. */
  uint16_t MinorOSVersion;            /**< The minor version number of the required operating system. */
  uint16_t MajorImageVersion;         /**< The major version number of the image. */
  uint16_t MinorImageVersion;         /**< The minor version number of the image. */
  uint16_t MajorSubsystemVersion;     /**< The major version number of the subsystem. */
  uint16_t MinorSubsystemVersion;     /**< The minor version number of the subsystem. */
  uint32_t Win32VersionValue;         /**< Reserved, must be zero. */
  uint32_t SizeOfImage;               /**< The size (in bytes) of the image, including all headers, as the image is loaded in memory. It must be a multiple of SectionAlignment. */
  uint32_t SizeOfHeaders;             /**< The combined size of an MS-DOS stub, PE header, and section headers rounded up to a multiple of FileAlignment. */
  uint32_t Checksum;                  /**< The image file checksum. The algorithm for computing the checksum is incorporated into IMAGHELP.DLL. The following are checked for validation at load time: all drivers, any DLL loaded at boot time, and any DLL that is loaded into a critical Windows process. */
  uint16_t Subsystem;                 /**< The subsystem that is required to run this image. For more information, see Windows Subsystem. */
  uint16_t DLLCharacteristics;        /**< For more information, see DLL Characteristics later in this specification. */
};

/*! \brief DLL characteristics
 * \sa     PEheader_optional_commonext
 * \name   PE_DLLCHARACTERISTICS_*
 * \{
 */
#define PE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA	       0x0020	    /**< Image can handle a high entropy 64-bit virtual address space. */
#define PE_DLLCHARACTERISTICS_DYNAMIC_BASE	         0x0040	    /**< DLL can be relocated at load time. */
#define PE_DLLCHARACTERISTICS_FORCE_INTEGRITY	       0x0080	    /**< Code Integrity checks are enforced. */
#define PE_DLLCHARACTERISTICS_NX_COMPAT 	           0x0100	    /**< Image is NX compatible. */
#define PE_DLLCHARACTERISTICS_NO_ISOLATION	         0x0200	    /**< Isolation aware, but do not isolate the image. */
#define PE_DLLCHARACTERISTICS_NO_SEH	               0x0400	    /**< Does not use structured exception (SE) handling. No SE handler may be called in this image. */
#define PE_DLLCHARACTERISTICS_NO_BIND	               0x0800	    /**< Do not bind the image. */
#define PE_DLLCHARACTERISTICS_APPCONTAINER	         0x1000	    /**< Image must execute in an AppContainer. */
#define PE_DLLCHARACTERISTICS_WDM_DRIVER	           0x2000	    /**< A WDM driver. */
#define PE_DLLCHARACTERISTICS_GUARD_CF	             0x4000	    /**< Image supports Control Flow Guard. */
#define PE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE  0x8000	    /**< Terminal Server aware. */
/*! @} */

/*! \brief PE (32-bit) optional header
*/
struct PEheader_optional32 {
  struct PEheader_optional_common common;       /**< common fields of optional header */
  uint32_t BaseOfData;                          /**< The address that is relative to the image base of the beginning-of-data section when it is loaded into memory. */
  /*The next 21 fields are an extension to the COFF optional header format*/
  uint32_t ImageBase;                           /**< The preferred address of the first byte of image when loaded into memory; must be a multiple of 64 K. The default for DLLs is 0x10000000. The default for Windows CE EXEs is 0x00010000. The default for Windows NT, Windows 2000, Windows XP, Windows 95, Windows 98, and Windows Me is 0x00400000. */
  struct PEheader_optional_commonext commonext; /**< common section within the optional header */
  uint32_t SizeOfStackReserve;                  /**< The size of the stack to reserve. Only SizeOfStackCommit is committed; the rest is made available one page at a time until the reserve size is reached. */
  uint32_t SizeOfStackCommit;                   /**< The size of the stack to commit. */
  uint32_t SizeOfHeapReserve;                   /**< The size of the local heap space to reserve. Only SizeOfHeapCommit is committed; the rest is made available one page at a time until the reserve size is reached.  */
  uint32_t SizeOfHeapCommit;                    /**< The size of the local heap space to commit.  */
  uint32_t LoaderFlags;                         /**< Reserved, must be zero. */
  uint32_t NumberOfRvaAndSizes;                 /**< The number of data-directory entries in the remainder of the optional header. Each describes a location and size. */
  struct PEheader_data_directory firstdatadir;  /**< placeholder for the first data directory */
};

/*! \brief PE+ (64-bit) optional header
*/
struct PEheader_optional64 {
  struct PEheader_optional_common common;       /**< common fields of optional header */
  /*The next 21 fields are an extension to the COFF optional header format*/
  uint64_t ImageBase;                           /**< The preferred address of the first byte of image when loaded into memory; must be a multiple of 64 K. The default for DLLs is 0x10000000. The default for Windows CE EXEs is 0x00010000. The default for Windows NT, Windows 2000, Windows XP, Windows 95, Windows 98, and Windows Me is 0x00400000. */
  struct PEheader_optional_commonext commonext; /**< common section within the optional header */
  uint64_t SizeOfStackReserve;                  /**< The size of the stack to reserve. Only SizeOfStackCommit is committed; the rest is made available one page at a time until the reserve size is reached. */
  uint64_t SizeOfStackCommit;                   /**< The size of the stack to commit. */
  uint64_t SizeOfHeapReserve;                   /**< The size of the local heap space to reserve. Only SizeOfHeapCommit is committed; the rest is made available one page at a time until the reserve size is reached.  */
  uint64_t SizeOfHeapCommit;                    /**< The size of the local heap space to commit.  */
  uint32_t LoaderFlags;                         /**< Reserved, must be zero. */
  uint32_t NumberOfRvaAndSizes;                 /**< The number of data-directory entries in the remainder of the optional header. Each describes a location and size. */
  struct PEheader_data_directory firstdatadir;  /**< placeholder for the first data directory */
};

/*! \brief union of different optional headers
*/
union PEheader_optional {
  struct PEheader_optional_common common;       /**< common fields of optional header */
  struct PEheader_optional32 opt32;             /**< PE (32-bit) optional header */
  struct PEheader_optional64 opt64;             /**< PE+ (64-bit) optional header */
};

/*! \brief image section header
 * \sa     PE_IMGSECTION_TYPE_*
*/
struct peheader_imagesection {
  uint8_t Name[8];                      /**< An 8-byte, null-padded UTF-8 encoded string. If the string is exactly 8 characters long, there is no terminating null. For longer names, this field contains a slash (/) that is followed by an ASCII representation of a decimal number that is an offset into the string table. Executable images do not use a string table and do not support section names longer than 8 characters. Long names in object files are truncated if they are emitted to an executable file. */
  union {
    uint32_t PhysicalAddress;           /**<  */
    uint32_t VirtualSize;               /**< The total size of the section when loaded into memory. If this value is greater than SizeOfRawData, the section is zero-padded. This field is valid only for executable images and should be set to zero for object files. */
  } Misc;
  uint32_t VirtualAddress;              /**< For executable images, the address of the first byte of the section relative to the image base when the section is loaded into memory. For object files, this field is the address of the first byte before relocation is applied; for simplicity, compilers should set this to zero. Otherwise, it is an arbitrary value that is subtracted from offsets during relocation. */
  uint32_t SizeOfRawData;               /**< The size of the section (for object files) or the size of the initialized data on disk (for image files). For executable images, this must be a multiple of FileAlignment from the optional header. If this is less than VirtualSize, the remainder of the section is zero-filled. Because the SizeOfRawData field is rounded but the VirtualSize field is not, it is possible for SizeOfRawData to be greater than VirtualSize as well. When a section contains only uninitialized data, this field should be zero.  */
  uint32_t PointerToRawData;            /**< The file pointer to the first page of the section within the COFF file. For executable images, this must be a multiple of FileAlignment from the optional header. For object files, the value should be aligned on a 4-byte boundary for best performance. When a section contains only uninitialized data, this field should be zero. */
  uint32_t PointerToRelocations;        /**< The file pointer to the beginning of relocation entries for the section. This is set to zero for executable images or if there are no relocations. */
  uint32_t PointerToLinenumbers;        /**< The file pointer to the beginning of line-number entries for the section. This is set to zero if there are no COFF line numbers. This value should be zero for an image because COFF debugging information is deprecated. */
  uint16_t NumberOfRelocations;         /**< The number of relocation entries for the section. This is set to zero for executable images. */
  uint16_t NumberOfLinenumbers;         /**< The number of line-number entries for the section. This value should be zero for an image because COFF debugging information is deprecated. */
  uint32_t Characteristics;             /**< The flags that describe the characteristics of the section. */
};

/*! \brief image section types
 * \sa     peheader_imagesection
 * \name   PE_IMGSECTION_TYPE_*
 * \{
 */
#define PE_IMGSECTION_TYPE_CODE                 0x00000020      /**< The section contains executable code. */
#define PE_IMGSECTION_TYPE_INITIALIZED_DATA     0x00000040      /**< The section contains initialized data. */
#define PE_IMGSECTION_TYPE_UNINITIALIZED_DATA   0x00000080      /**< The section contains uninitialized data. */
#define PE_IMGSECTION_TYPE_LINK_INFO            0x00000200      /**< The section contains comments or other information. The .drectve section has this type. This is valid for object files only. */
#define PE_IMGSECTION_TYPE_LINK_REMOVE          0x00000800      /**< The section will not become part of the image. This is valid only for object files. */
#define PE_IMGSECTION_TYPE_LINK_COMDAT          0x00001000      /**< The section contains COMDAT data. */
#define PE_IMGSECTION_TYPE_NO_DEFER_SPEC_EXC    0x00004000      /**< Reset speculative exceptions handling bits in the TLB entries for this section. */
#define PE_IMGSECTION_TYPE_GPREL                0x00008000      /**< The section contains data referenced through the global pointer (GP). */
//#define PE_IMGSECTION_TYPE_MEM_PURGEABLE        0x00020000      /**< Reserved for future use. */
//#define PE_IMGSECTION_TYPE_MEM_LOCKED           0x00040000      /**< Reserved for future use. */
//#define PE_IMGSECTION_TYPE_MEM_PRELOAD          0x00080000      /**< Reserved for future use. */
#define PE_IMGSECTION_TYPE_ALIGN_1BYTES         0x00100000      /**< Align data on a 1-byte boundary. Valid only for object files. */
#define PE_IMGSECTION_TYPE_ALIGN_2BYTES         0x00200000      /**< Align data on a 2-byte boundary. Valid only for object files. */
#define PE_IMGSECTION_TYPE_ALIGN_4BYTES         0x00300000      /**< Align data on a 4-byte boundary. Valid only for object files. */
#define PE_IMGSECTION_TYPE_ALIGN_8BYTES         0x00400000      /**< Align data on an 8-byte boundary. Valid only for object files. */
#define PE_IMGSECTION_TYPE_ALIGN_16BYTES        0x00500000      /**< Align data on a 16-byte boundary. Valid only for object files. */
#define PE_IMGSECTION_TYPE_ALIGN_32BYTES        0x00600000      /**< Align data on a 32-byte boundary. Valid only for object files. */
#define PE_IMGSECTION_TYPE_ALIGN_64BYTES        0x00700000      /**< Align data on a 64-byte boundary. Valid only for object files. */
#define PE_IMGSECTION_TYPE_ALIGN_128BYTES       0x00800000      /**< Align data on a 128-byte boundary. Valid only for object files. */
#define PE_IMGSECTION_TYPE_ALIGN_256BYTES       0x00900000      /**< Align data on a 256-byte boundary. Valid only for object files. */
#define PE_IMGSECTION_TYPE_ALIGN_512BYTES       0x00A00000      /**< Align data on a 512-byte boundary. Valid only for object files. */
#define PE_IMGSECTION_TYPE_ALIGN_1024BYTES      0x00B00000      /**< Align data on a 1024-byte boundary. Valid only for object files. */
#define PE_IMGSECTION_TYPE_ALIGN_2048BYTES      0x00C00000      /**< Align data on a 2048-byte boundary. Valid only for object files. */
#define PE_IMGSECTION_TYPE_ALIGN_4096BYTES      0x00D00000      /**< Align data on a 4096-byte boundary. Valid only for object files. */
#define PE_IMGSECTION_TYPE_ALIGN_8192BYTES      0x00E00000      /**< Align data on an 8192-byte boundary. Valid only for object files. */
#define PE_IMGSECTION_TYPE_LNK_NRELOC_OVFL      0x01000000      /**< The section contains extended relocations. */
#define PE_IMGSECTION_TYPE_MEM_DISCARDABLE      0x02000000      /**< The section can be discarded as needed. */
#define PE_IMGSECTION_TYPE_MEM_NOT_CACHED       0x04000000      /**< The section cannot be cached. */
#define PE_IMGSECTION_TYPE_MEM_NOT_PAGED        0x08000000      /**< The section is not pageable. */
#define PE_IMGSECTION_TYPE_MEM_SHARED           0x10000000      /**< The section can be shared in memory. */
#define PE_IMGSECTION_TYPE_MEM_EXECUTE          0x20000000      /**< The section can be executed as code. */
#define PE_IMGSECTION_TYPE_MEM_READ             0x40000000      /**< The section can be read. */
#define PE_IMGSECTION_TYPE_MEM_WRITE            0x80000000      /**< The section can be written to. */
/*! @} */

/*! \brief image export directory
*/
struct peheader_imageexportdirectory {
  uint32_t Characteristics;         /**< Reserved, must be 0. */
  uint32_t TimeDateStamp;           /**< The time and date that the export data was created. */
  uint16_t MajorVersion;            /**< The major version number. The major and minor version numbers can be set by the user. */
  uint16_t MinorVersion;            /**< The minor version number. */
  uint32_t Name;                    /**< The address of the ASCII string that contains the name of the DLL. This address is relative to the image base. */
  uint32_t Base;                    /**< The starting ordinal number for exports in this image. This field specifies the starting ordinal number for the export address table. It is usually set to 1. */
  uint32_t NumberOfFunctions;       /**< The number of entries in the export address table. */
  uint32_t NumberOfNames;           /**< The number of entries in the name pointer table. This is also the number of entries in the ordinal table. */
  uint32_t AddressOfFunctions;      /**< The address of the export address table, relative to the image base. (RVA) */
  uint32_t AddressOfNames;          /**< The address of the export name pointer table, relative to the image base. The table size is given by the Number of Name Pointers field. (RVA) */
  uint32_t AddressOfNameOrdinals;   /**< The address of the ordinal table, relative to the image base. (RVA) */
};

/*! \brief image import directory
*/
struct peheader_imageimportdirectory {
  uint32_t ImportLookupTable;       /**< The RVA of the import lookup table. This table contains a name or ordinal for each import. (The name "Characteristics" is used in Winnt.h, but no longer describes this field.) (RVA) */
  uint32_t TimeDateStamp;           /**< The stamp that is set to zero until the image is bound. After the image is bound, this field is set to the time/data stamp of the DLL. */
  uint32_t ForwarderChain;          /**< The index of the first forwarder reference. */
  uint32_t Name;                    /**< The address of an ASCII string that contains the name of the DLL. This address is relative to the image base. (RVA) */
  uint32_t ImportAddressTable;      /**< The RVA of the import address table. The contents of this table are identical to the contents of the import lookup table until the image is bound. (RVA) */
};

/*! \brief get short machine architecture name
 * \param  machine               machine architecture code
 * \return short machine architecture name (e.g.: "x86" or "x86_64")
 * \sa     PEheader_optional_common
 */
DLL_EXPORT_PEDEPS const char* pe_get_arch_name (uint16_t machine);

/*! \brief get long machine architecture name
 * \param  machine               machine architecture code
 * \return long machine architecture name
 * \sa     PEheader_optional_common
 */
DLL_EXPORT_PEDEPS const char* pe_get_machine_name (uint16_t machine);

/*! \brief get subsystem name
 * \param  subsystem             subsystem code
 * \return subsystem name (e.g.: "Windows GUI" or "Windows console")
 * \sa     PEheader_optional_commonext
 */
DLL_EXPORT_PEDEPS const char* pe_get_subsystem_name (uint16_t subsystem);

/*! \brief locate section pointed to by relative virtual address (RVA)
 * \param  sections              pointer to array of image sections
 * \param  sectioncount          number of image sections in \b sections
 * \param  rva                   relative virtual address
 * \return pointer to section or NULL if not found
 * \sa     peheader_imagesection
 */
DLL_EXPORT_PEDEPS struct peheader_imagesection* PE_find_rva_section (struct peheader_imagesection* sections, uint16_t sectioncount, uint32_t rva);

#ifdef __cplusplus
}
#endif

#endif
