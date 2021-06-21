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
#include <stdlib.h>

DLL_EXPORT_PEDEPS struct peheader_imagesection* pe_find_rva_section (struct peheader_imagesection* sections, uint16_t sectioncount, uint32_t rva)
{
  uint16_t i;
  for (i = 0; i < sectioncount; i++) {
    if (rva >= sections[i].VirtualAddress && rva < sections[i].VirtualAddress + sections[i].SizeOfRawData)
      return &(sections[i]);
  }
  return NULL;
}

DLL_EXPORT_PEDEPS const char* pe_get_arch_name (uint16_t machine)
{
  switch (machine) {
    case 0x014C: return "x86";
    //case 0x0162: return "MIPS R3000";
    //case 0x0168: return "MIPS R10000";
    //case 0x0169: return "MIPS little endian WCI v2";
    //case 0x0183: return "old Alpha AXP";
    //case 0x0184: return "Alpha AXP";
    //case 0x01A2: return "Hitachi SH3";
    //case 0x01A3: return "Hitachi SH3 DSP";
    //case 0x01A6: return "Hitachi SH4";
    //case 0x01A8: return "Hitachi SH5";
    //case 0x01C0: return "ARM little endian";
    //case 0x01C2: return "Thumb";
    //case 0x01C4: return "ARMv7";
    //case 0x01D3: return "Matsushita AM33";
    //case 0x01F0: return "PowerPC little endian";
    //case 0x01F1: return "PowerPC with floating point support";
    case 0x0200: return "ia64";
    //case 0x0266: return "MIPS16";
    case 0x0268: return "m68k";
    case 0x0284: return "alpha";
    //case 0x0366: return "MIPS with FPU";
    //case 0x0466: return "MIPS16 with FPU";
    case 0x0EBC: return "EFI Byte Code";
    case 0x8664: return "x86_64";
    //case 0x9041: return "Mitsubishi M32R little endian";
    //case 0xAA64: return "ARM64 little endian";
    //case 0xC0EE: return "clr pure MSIL";
    default:     return "(unknown)";
  }
  return NULL;
}

DLL_EXPORT_PEDEPS const char* pe_get_machine_name (uint16_t machine)
{
  switch (machine) {
    case 0x014C: return "Intel 386 (x86)";
    case 0x0162: return "MIPS R3000";
    case 0x0168: return "MIPS R10000";
    case 0x0169: return "MIPS little endian WCI v2";
    case 0x0183: return "old Alpha AXP";
    case 0x0184: return "Alpha AXP";
    case 0x01A2: return "Hitachi SH3";
    case 0x01A3: return "Hitachi SH3 DSP";
    case 0x01A6: return "Hitachi SH4";
    case 0x01A8: return "Hitachi SH5";
    case 0x01C0: return "ARM little endian";
    case 0x01C2: return "Thumb";
    case 0x01C4: return "ARMv7";
    case 0x01D3: return "Matsushita AM33";
    case 0x01F0: return "PowerPC little endian";
    case 0x01F1: return "PowerPC with floating point support";
    case 0x0200: return "Intel IA64";
    case 0x0266: return "MIPS16";
    case 0x0268: return "Motorola 68000 series";
    case 0x0284: return "Alpha AXP 64-bit";
    case 0x0366: return "MIPS with FPU";
    case 0x0466: return "MIPS16 with FPU";
    case 0x0EBC: return "EFI Byte Code";
    case 0x8664: return "AMD AMD64 (x64)";
    case 0x9041: return "Mitsubishi M32R little endian";
    case 0xAA64: return "ARM64 little endian";
    case 0xC0EE: return "clr pure MSIL";
    default:     return "(unknown)";
  }
  return NULL;
}

DLL_EXPORT_PEDEPS const char* pe_get_subsystem_name (uint16_t subsystem)
{
  switch (subsystem) {
    case 0:  return "generic";
    case 1:  return "native";            //(device drivers and native system processes)
    case 2:  return "Windows GUI";
    case 3:  return "Windows console";   //Windows CUI
    case 5:  return "OS/2 console";      //OS/2 CUI
    case 7:  return "POSIX console";     //POSIX CUI
    case 9:  return "Windows CE GUI";
    case 10: return "EFI";              //Extensible Firmware Interface (EFI)
    case 11: return "EFI/boot";         //EFI driver with boot services
    case 12: return "EFI/runtime";      //EFI driver with run-time services
    case 13: return "EFI ROM image";
    case 14: return "Xbox";
    case 16: return "boot application";
    default: return "(unknown)";
  }
  return NULL;
}

DLL_EXPORT_PEDEPS const char* pe_get_resourceid_name (uint32_t resourceid)
{
  switch (resourceid) {
    case PE_RESOURCE_TYPE_CURSOR:       return "cursor";
    case PE_RESOURCE_TYPE_BITMAP:       return "bitmap";
    case PE_RESOURCE_TYPE_ICON:         return "icon";
    case PE_RESOURCE_TYPE_MENU:         return "menu";
    case PE_RESOURCE_TYPE_DIALOG:       return "dialog";
    case PE_RESOURCE_TYPE_STRING:       return "string";
    case PE_RESOURCE_TYPE_FONTDIR:      return "fontdir";
    case PE_RESOURCE_TYPE_FONT:         return "font";
    case PE_RESOURCE_TYPE_ACCELERATOR:  return "accelerator";
    case PE_RESOURCE_TYPE_RCDATA:       return "rcdata";
    case PE_RESOURCE_TYPE_MESSAGETABLE: return "messagetable";
    case PE_RESOURCE_TYPE_GROUP_CURSOR: return "group_cursor";
    case PE_RESOURCE_TYPE_GROUP_ICON:   return "group_icon";
    case PE_RESOURCE_TYPE_VERSION:      return "version";
    case PE_RESOURCE_TYPE_DLGINCLUDE:   return "dlginclude";
    case PE_RESOURCE_TYPE_PLUGPLAY:     return "plugplay";
    case PE_RESOURCE_TYPE_VXD:          return "vxd";
    case PE_RESOURCE_TYPE_ANICURSOR:    return "anicursor";
    case PE_RESOURCE_TYPE_ANIICON:      return "aniicon";
    case PE_RESOURCE_TYPE_HTML:         return "html";
    case PE_RESOURCE_TYPE_MANIFEST:     return "manifest";
    default:                            return "(unknown)";
  }
  return NULL;
}

DLL_EXPORT_PEDEPS const char* pe_version_fileinfo_get_type_name (uint32_t filetype)
{
  switch (filetype) {
    case PE_VERSION_FILEINFO_TYPE_APP:        return "Application";
    case PE_VERSION_FILEINFO_TYPE_DLL:        return "DLL";
    case PE_VERSION_FILEINFO_TYPE_DRV:        return "Device driver";
    case PE_VERSION_FILEINFO_TYPE_FONT:       return "Font";
    case PE_VERSION_FILEINFO_TYPE_VXD:        return "Virtual device";
    case PE_VERSION_FILEINFO_TYPE_STATIC_LIB: return "Static-link library";
    default:                                  return "(unknown file type)";
  }
  return NULL;
}

DLL_EXPORT_PEDEPS const char* pe_version_fileinfo_get_subtype_name (uint32_t filetype, uint32_t filesubtype)
{
  switch (filetype) {
    case PE_VERSION_FILEINFO_TYPE_DRV:
      switch (filesubtype) {
        case PE_VERSION_FILEINFO_SUBTYPE_DRV_COMM:              return "communications driver";
        case PE_VERSION_FILEINFO_SUBTYPE_DRV_DISPLAY:           return "display driver";
        case PE_VERSION_FILEINFO_SUBTYPE_DRV_INSTALLABLE:       return "installable driver";
        case PE_VERSION_FILEINFO_SUBTYPE_DRV_KEYBOARD:          return "keyboard driver";
        case PE_VERSION_FILEINFO_SUBTYPE_DRV_LANGUAGE:          return "language driver";
        case PE_VERSION_FILEINFO_SUBTYPE_DRV_MOUSE:             return "mouse driver";
        case PE_VERSION_FILEINFO_SUBTYPE_DRV_NETWORK:           return "network driver";
        case PE_VERSION_FILEINFO_SUBTYPE_DRV_PRINTER:           return "printer driver";
        case PE_VERSION_FILEINFO_SUBTYPE_DRV_SOUND:             return "sound driver";
        case PE_VERSION_FILEINFO_SUBTYPE_DRV_SYSTEM:            return "system driver";
        case PE_VERSION_FILEINFO_SUBTYPE_DRV_VERSIONED_PRINTER: return "versioned printer driver";
        default:                                                return "(unknown driver type)";
      }
      break;
    case PE_VERSION_FILEINFO_TYPE_FONT:
      switch (filesubtype) {
        case PE_VERSION_FILEINFO_SUBTYPE_FONT_RASTER:   return "raster font";
        case PE_VERSION_FILEINFO_SUBTYPE_FONT_TRUETYPE: return "TrueType font";
        case PE_VERSION_FILEINFO_SUBTYPE_FONT_VECTOR:   return "vector font";
        default:                                        return "(unknown font type)";
      }
      break;
    case PE_VERSION_FILEINFO_TYPE_VXD:
      return "(subtype value is virtual device identifier)";
    default:
      return "-";
  }
  return NULL;
}

