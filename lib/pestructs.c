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
    default: return "(unknown)";
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
    default: return "(unknown)";
  }
  return NULL;
}

DLL_EXPORT_PEDEPS const char* pe_get_subsystem_name (uint16_t subsystem)
{
  switch (subsystem) {
    case 0: return "generic";
    case 1: return "native";            //(device drivers and native system processes)
    case 2: return "Windows GUI";
    case 3: return "Windows console";   //Windows CUI
    case 5: return "OS/2 console";      //OS/2 CUI
    case 7: return "POSIX console";     //POSIX CUI
    case 9: return "Windows CE GUI";
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

DLL_EXPORT_PEDEPS struct peheader_imagesection* PE_find_rva_section (struct peheader_imagesection* sections, uint16_t sectioncount, uint32_t rva)
{
  uint16_t i;
  for (i = 0; i < sectioncount; i++) {
    if (rva >= sections[i].VirtualAddress && rva < sections[i].VirtualAddress + sections[i].SizeOfRawData)
      return &(sections[i]);
  }
  return NULL;
}

