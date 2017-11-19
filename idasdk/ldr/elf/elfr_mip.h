#ifndef __ELFR_MIP_H__
#define __ELFR_MIP_H__

#ifndef __ELFBASE_H__
#include "elfbase.h"
#endif

#define EF_MIPS_NOREORDER       0x00000001 // At least one .noreorder directive appears in the source.
#define EF_MIPS_PIC             0x00000002 // File contains position independent code.
#define EF_MIPS_CPIC            0x00000004 // Code in file uses the standard calling sequence for calling osition independent code.
#define EF_MIPS_UGEN_ALLOC      0x00000008
#define EF_MIPS_UCODE           0x00000010 // Code in file uses UCODE (obsolete)
#define EF_MIPS_ABI2            0x00000020 // Code in file uses new ABI (-n32 on Irix 6).
#define EF_MIPS_DYNAMIC         0x00000040 // MIPS dynamic
#define EF_MIPS_OPTIONS_FIRST   0x00000080
#define EF_MIPS_32BITMODE       0x00000100 // Indicates code compiled for a 64-bit machine in 32-bit mode. (regs are 32-bits wide.)
#define EF_MIPS_ARCH            0xf0000000 // Four bit MIPS architecture field.
#define  E_MIPS_ARCH_1          0x00000000 //   -mips1 code.
#define  E_MIPS_ARCH_2          0x10000000 //   -mips2 code.
#define  E_MIPS_ARCH_3          0x20000000 //   -mips3 code.
#define  E_MIPS_ARCH_4          0x30000000 //   -mips4 code.
#define  E_MIPS_ARCH_5          0x40000000 //   -mips5 code.
#define  E_MIPS_ARCH_32         0x50000000 //   -mips32 code.
#define  E_MIPS_ARCH_64         0x60000000 //   -mips64 code.
#define  E_MIPS_ARCH_32R2       0x70000000 //   -mips32r2
#define  E_MIPS_ARCH_64R2       0x80000000 //   -mips64r2
#define EF_MIPS_ABI             0x0000F000 // The ABI of the file.  Also see EF_MIPS_ABI2 above.
#define  E_MIPS_ABI_O32         0x00001000 //   The original o32 abi.
#define  E_MIPS_ABI_O64         0x00002000 //   O32 extended to work on 64 bit architectures
#define  E_MIPS_ABI_EABI32      0x00003000 //   EABI in 32 bit mode
#define  E_MIPS_ABI_EABI64      0x00004000 //   EABI in 64 bit mode
#define EF_MIPS_ARCH_ASE            0x0f000000 // Architectural Extensions used by this file
#define  EF_MIPS_ARCH_ASE_MDMX  0x08000000 //   Use MDMX multimedia extensions
#define  EF_MIPS_ARCH_ASE_M16   0x04000000 //   Use MIPS-16 ISA extensions
#define  EF_MIPS_ARCH_ASE_MICROMIPS  0x02000000 // Use microMIPS ISA extensions

/* Machine variant if we know it.  This field was invented at Cygnus,
   but it is hoped that other vendors will adopt it.  If some standard
   is developed, this code should be changed to follow it. */

#define EF_MIPS_MACH            0x00FF0000

/* Cygnus is choosing values between 80 and 9F;
   00 - 7F should be left for a future standard;
   the rest are open. */

#define E_MIPS_MACH_3900        0x00810000 // R3900/Toshiba TX39
#define E_MIPS_MACH_4010        0x00820000 //
#define E_MIPS_MACH_4100        0x00830000
#define E_MIPS_MACH_4650        0x00850000
#define E_MIPS_MACH_4120        0x00870000
#define E_MIPS_MACH_4111        0x00880000
#define E_MIPS_MACH_MIPS32_4K   0x00890000
#define E_MIPS_MACH_SB1         0x008a0000 // SiByte SB-1
#define E_MIPS_MACH_OCTEON      0x008b0000 // Cavium Networks OCTEON
#define E_MIPS_MACH_XLR         0x008c0000 // RMI XLR
#define E_MIPS_MACH_OCTEON2     0x008d0000 // Cavium Networks OCTEON 2
#define E_MIPS_MACH_OCTEON3     0x008e0000 // Cavium Networks OCTEON 3
#define E_MIPS_MACH_5400        0x00910000
#define E_MIPS_MACH_5900        0x00920000 // r5900 (Sony Playstation 2 Emotion Engine)
#define E_MIPS_MACH_5500        0x00980000
#define E_MIPS_MACH_9000        0x00990000
#define E_MIPS_MACH_LS2E        0x00A00000 // Loongson/Godson 2E
#define E_MIPS_MACH_LS2F        0x00A10000 // Loongson/Godson 2F
#define E_MIPS_MACH_ALLEGREX    0x00A20000 // Allegrex (Sony PlayStation Portable)
#define E_MIPS_MACH_LS3A        0x00A20000 // Loongson/Godson 3A

// relocation field - word32 with HIGH BYTE FIRST!!!
// A-   from Elf32_Rela
// B-   Loading address of shared object
// G-   offset into global objet table
// GOT- adress of global object table
// L-   linkage table entry
// P-   plase of storage unit (computed using r_offset)
// S-   value of symbol
enum elf_RTYPE_mips
{
  R_MIPS_NONE             =  0,       //No reloc
  R_MIPS_16               =  1,
  R_MIPS_32               =  2,       //S+A-P Direct32
  R_MIPS_REL              =  3,       //S+A Relative32
  R_MIPS_26               =  4,       //S+A Relative26
  R_MIPS_HI16             =  5,
  R_MIPS_LO16             =  6,
  R_MIPS_GPREL            =  7,       //S+A Relative16
  R_MIPS_LITERAL          =  8,
  R_MIPS_GOT              =  9,
  R_MIPS_PC16             = 10,
  R_MIPS_CALL             = 11,       //Call16
  R_MIPS_GPREL32          = 12,

  R_MIPS_SHIFT5           = 16,
  R_MIPS_SHIFT6           = 17,
  R_MIPS_64               = 18,
  R_MIPS_GOT_DISP         = 19,
  R_MIPS_GOT_PAGE         = 20,
  R_MIPS_GOT_OFST         = 21,
  R_MIPS_GOT_HI16         = 22,
  R_MIPS_GOT_LO16         = 23,
  R_MIPS_SUB              = 24,
  R_MIPS_INSERT_A         = 25,
  R_MIPS_INSERT_B         = 26,
  R_MIPS_DELETE           = 27,
  R_MIPS_HIGHER           = 28,
  R_MIPS_HIGHEST          = 29,
  R_MIPS_CALL_HI16        = 30,
  R_MIPS_CALL_LO16        = 31,
  R_MIPS_SCN_DISP         = 32,
  R_MIPS_REL16            = 33,
  R_MIPS_ADD_IMMEDIATE    = 34,
  R_MIPS_PJUMP            = 35,
  R_MIPS_RELGOT           = 36,
  R_MIPS_JALR             = 37,
  R_MIPS_TLS_DTPMOD32     = 38,
  R_MIPS_TLS_DTPREL32     = 39,
  R_MIPS_TLS_DTPMOD64     = 40,
  R_MIPS_TLS_DTPREL64     = 41,
  R_MIPS_TLS_GD           = 42,
  R_MIPS_TLS_LDM          = 43,
  R_MIPS_TLS_DTPREL_HI16  = 44,
  R_MIPS_TLS_DTPREL_LO16  = 45,
  R_MIPS_TLS_GOTTPREL     = 46,
  R_MIPS_TLS_TPREL32      = 47,
  R_MIPS_TLS_TPREL64      = 48,
  R_MIPS_TLS_TPREL_HI16   = 49,
  R_MIPS_TLS_TPREL_LO16   = 50,

  R_MIPS16_26             = 100,
  R_MIPS16_GPREL          = 101,
  R_MIPS16_GOT16          = 102,
  R_MIPS16_CALL16         = 103,
  R_MIPS16_HI16           = 104,
  R_MIPS16_LO16           = 105,

  // For these two:
  // http://sourceware.org/ml/binutils/2008-07/txt00000.txt
  R_MIPS_COPY             = 126,
  R_MIPS_JUMP_SLOT        = 127,

  R_MIPS_PC32             = 248,
  R_MIPS_GNU_REL16_S2     = 250,
  R_MIPS_GNU_VTINHERIT    = 253,
  R_MIPS_GNU_VTENTRY      = 254
};

// autoconvert got-entries to offsets
#define ELF_RPL_MIPS_DEFAULT  (ELF_BUG_GOT | ELF_BS_DBG)

enum elf_ET_MIPS
{
  ET_IRX     = 0xFF80u,  // IRX file for PS2's IOP
  ET_PSPEXEC = 0xFFA0u   // Sony PSP executable file
};

enum elf_PHT_MIPS
{
  PT_MIPS_IOPMOD  = 0x70000080,  // Sony PS2 IOP module extension
  PT_MIPS_EEMOD   = 0x70000090,  // Sony PS2 EE module extension
  PT_MIPS_PSPREL  = 0x700000A0,  // Sony PRX relocations (ELF-style)
  PT_MIPS_PSPREL2 = 0x700000A1,  // Sony PRX relocations (packed)
};

enum elf_DTAG_MIPS
{
  DT_MIPS_RLD_VERSION          = 0x70000001, /* 32 bit version number for runtime linker interface.  */
  DT_MIPS_TIME_STAMP           = 0x70000002, /* Time stamp.  */
  DT_MIPS_ICHECKSUM            = 0x70000003, /* Checksum of external strings and common sizes.  */
  DT_MIPS_IVERSION             = 0x70000004, /* Index of version string in string table.  */
  DT_MIPS_FLAGS                = 0x70000005, /* 32 bits of flags.  */
  DT_MIPS_BASE_ADDRESS         = 0x70000006, /* Base address of the segment.  */
  DT_MIPS_MSYM                 = 0x70000007, /* ??? */
  DT_MIPS_CONFLICT             = 0x70000008, /* Address of .conflict section.  */
  DT_MIPS_LIBLIST              = 0x70000009, /* Address of .liblist section.  */
  DT_MIPS_LOCAL_GOTNO          = 0x7000000a, /* Number of local global offset table entries.  */
  DT_MIPS_CONFLICTNO           = 0x7000000b, /* Number of entries in the .conflict section.  */
  DT_MIPS_LIBLISTNO            = 0x70000010, /* Number of entries in the .liblist section.  */
  DT_MIPS_SYMTABNO             = 0x70000011, /* Number of entries in the .dynsym section.  */
  DT_MIPS_UNREFEXTNO           = 0x70000012, /* Index of first external dynamic symbol not referenced locally.  */
  DT_MIPS_GOTSYM               = 0x70000013, /* Index of first dynamic symbol in global offset table.  */
  DT_MIPS_HIPAGENO             = 0x70000014, /* Number of page table entries in global offset table.  */
  DT_MIPS_RLD_MAP              = 0x70000016, /* Address of run time loader map, used for debugging.  */
  DT_MIPS_DELTA_CLASS          = 0x70000017, /* Delta C++ class definition.  */
  DT_MIPS_DELTA_CLASS_NO       = 0x70000018, /* Number of entries in DT_MIPS_DELTA_CLASS.  */
  DT_MIPS_DELTA_INSTANCE       = 0x70000019, /* Delta C++ class instances.  */
  DT_MIPS_DELTA_INSTANCE_NO    = 0x7000001a, /* Number of entries in DT_MIPS_DELTA_INSTANCE.  */
  DT_MIPS_DELTA_RELOC          = 0x7000001b, /* Delta relocations.  */
  DT_MIPS_DELTA_RELOC_NO       = 0x7000001c, /* Number of entries in DT_MIPS_DELTA_RELOC.  */
  DT_MIPS_DELTA_SYM            = 0x7000001d, /* Delta symbols that Delta relocations refer to.  */
  DT_MIPS_DELTA_SYM_NO         = 0x7000001e, /* Number of entries in DT_MIPS_DELTA_SYM.  */
  DT_MIPS_DELTA_CLASSSYM       = 0x70000020, /* Delta symbols that hold class declarations.  */
  DT_MIPS_DELTA_CLASSSYM_NO    = 0x70000021, /* Number of entries in DT_MIPS_DELTA_CLASSSYM.  */
  DT_MIPS_CXX_FLAGS            = 0x70000022, /* Flags indicating information about C++ flavor.  */
  DT_MIPS_PIXIE_INIT           = 0x70000023, /* Pixie information (???).  */
  DT_MIPS_SYMBOL_LIB           = 0x70000024, /* Address of .MIPS.symlib */
  DT_MIPS_LOCALPAGE_GOTIDX     = 0x70000025, /* The GOT index of the first PTE for a segment */
  DT_MIPS_LOCAL_GOTIDX         = 0x70000026, /* The GOT index of the first PTE for a local symbol */
  DT_MIPS_HIDDEN_GOTIDX        = 0x70000027, /* The GOT index of the first PTE for a hidden symbol */
  DT_MIPS_PROTECTED_GOTIDX     = 0x70000028, /* The GOT index of the first PTE for a protected symbol */
  DT_MIPS_OPTIONS              = 0x70000029, /* Address of `.MIPS.options'.  */
  DT_MIPS_INTERFACE            = 0x7000002a, /* Address of `.interface'.  */
  DT_MIPS_DYNSTR_ALIGN         = 0x7000002b, /* ??? */
  DT_MIPS_INTERFACE_SIZE       = 0x7000002c, /* Size of the .interface section.  */
  DT_MIPS_RLD_TEXT_RESOLVE_ADDR= 0x7000002d, /* Size of rld_text_resolve function stored in the GOT.  */
  DT_MIPS_PERF_SUFFIX          = 0x7000002e, /* Default suffix of DSO to be added by rld on dlopen() calls.  */
  DT_MIPS_COMPACT_SIZE         = 0x7000002f, /* Size of compact relocation section (O32).  */
  DT_MIPS_GP_VALUE             = 0x70000030, /* GP value for auxiliary GOTs.  */
  DT_MIPS_AUX_DYNAMIC          = 0x70000031, /* Address of auxiliary .dynamic.  */
  DT_MIPS_PLTGOT               = 0x70000032, /* Address of the base of the PLTGOT */
  DT_MIPS_RWPLT                = 0x70000034, /* Points to the base of a writable PLT. */
};

enum elf_SHN_MIPS
{
  SHN_MIPS_ACOMMON    = 0xff00, // Defined and allocated common symbol.  Value is virtual address.
  SHN_MIPS_TEXT       = 0xff01, // Defined and allocated text symbol.  Value is virtual address.
  SHN_MIPS_DATA       = 0xff02, // Defined and allocated data symbol.  Value is virtual address.
  SHN_MIPS_SCOMMON    = 0xff03, // Small common symbol.
  SHN_MIPS_SUNDEFINED = 0xff04  // Small undefined symbol.
};

enum elf_SHF_MIPS
{
  SHF_MIPS_GPREL      = 0x10000000, // Section must be part of global data area.
  SHF_MIPS_MERGE      = 0x20000000, // Section data should be merged to eliminate duplication
  SHF_MIPS_ADDR       = 0x40000000, // Section data is addresses by default. Address size to be inferred from section entry size.
  SHF_MIPS_STRING     = 0x80000000, // Section data is string data by default
  SHF_MIPS_NOSTRIP    = 0x08000000, // Section data may not be stripped
  SHF_MIPS_LOCAL      = 0x04000000, // Section data local to process
  SHF_MIPS_NAMES      = 0x02000000, // Linker must generate implicit hidden weak names
  SHF_MIPS_NODUPE     = 0x01000000, // Section contains text/data which may be replicated in other sections. Linker must retain only one copy.
};

enum elf_SHT_MIPS
{
  SHT_MIPS_LIBLIST    = 0x70000000, // contains the set of dynamic shared objects used when statically linking.
  SHT_MIPS_MSYM       = 0x70000001, //unknown Irix5 usage
  SHT_MIPS_CONFLICT   = 0x70000002, // list of confliction symbols
  SHT_MIPS_GPTAB      = 0x70000003, // Section contains the global pointer table.
  SHT_MIPS_UCODE      = 0x70000004, //microcode information
  SHT_MIPS_DEBUG      = 0x70000005, //start of debugging information
  SHT_MIPS_REGINFO    = 0x70000006, // Section contains register usage information.
  SHT_MIPS_IFACE      = 0x7000000b, // Section contains interface information.
  SHT_MIPS_CONTENT    = 0x7000000c, // Section contains description of contents of another section.
  SHT_MIPS_OPTIONS    = 0x7000000d, // Section contains miscellaneous options.
  SHT_MIPS_DWARF      = 0x7000001e, // DWARF debugging section.
  SHT_MIPS_SYMBOL_LIB = 0x70000020,  //unknown Irix6 usage
  SHT_MIPS_EVENTS     = 0x70000021, // Events section.
  SHT_MIPS_IOPMOD     = 0x70000080, // .ipmod section for PS2 IRXs
  SHT_MIPS_PSPREL     = 0x700000A0, // PSP executable relocation section
  // VU overlay table (PS2?)
  SHT_DVP_OVERLAY_TABLE = 0x7ffff420,
  SHT_DVP_OVERLAY       = 0x7ffff421,
};

// Special values for the st_other field in the symbol table.
enum elf_STO_MIPS
{
  // Two topmost bits denote the MIPS ISA for .text symbols:
  // + 00 -- standard MIPS code,
  // + 10 -- microMIPS code,
  // + 11 -- MIPS16 code; requires the following two bits to be set too.
  // Note that one of the MIPS16 bits overlaps with STO_MIPS_PIC.
  STO_MIPS_ISA = 0xc0,

  // The MIPS psABI was updated in 2008 with support for PLTs and copy
  // relocs.  There are therefore two types of nonzero SHN_UNDEF functions:
  // PLT entries and traditional MIPS lazy binding stubs.  We mark the former
  // with STO_MIPS_PLT to distinguish them from the latter.
  STO_MIPS_PLT = 0x8,

  // This value is used to mark PIC functions in an object that mixes
  // PIC and non-PIC.  Note that this bit overlaps with STO_MIPS16,
  // although MIPS16 symbols are never considered to be MIPS_PIC.
  STO_MIPS_PIC = 0x20,

  // This value is used for a mips16 .text symbol.
  STO_MIPS16 = 0xf0,

  // This value is used for a microMIPS .text symbol.  To distinguish from
  // STO_MIPS16, we set top two bits to be 10 to denote STO_MICROMIPS.  The
  // mask is STO_MIPS_ISA.
  STO_MICROMIPS  = 0x80
};

// PSP-specific encoding of r_info field
// segment in which the relocation resides
// i.e. relocation is at pht[ofs_base].p_vaddr + r_offset
#define ELF32_R_OFS_BASE(i) (((i)>>8) & 0xFF)
// segment number with the target
// i.e. the final address should be adjusted with pht[ofs_base].p_vaddr
#define ELF32_R_ADDR_BASE(i) (((i)>>16) & 0xFF)

void set_mips_compact_encoding(ea_t ea, bool enable);
void relocate_psp_section(Elf64_Shdr *rsh, linput_t *li);
inline bool is_psp_file(reader_t &reader) { return reader.get_header().e_machine == EM_MIPS && reader.get_header().e_type == ET_PSPEXEC; }

#endif
