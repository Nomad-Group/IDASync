#ifndef __ELFR_ARM_H__
#define __ELFR_ARM_H__

#include <map>
#include <set>

#ifndef __ELFBASE_H__
#include "elfbase.h"
#endif

// relocation field - word32 with HIGH BYTE FIRST!!!
// A-   from Elf32_Rela
// B-   Loading address of shared object  (REAL section when symbol defined)
//  (not)          G-   offset into global objet table
//  (not)          GOT- adress of global object table
//  (not)          L-   linkage table entry
// P-   place of storage unit (computed using r_offset)
// S-   value of symbol
enum elf_RTYPE_arm
{

  R_ARM_NONE      =  0,        //No reloc
  R_ARM_PC24      =  1,    // S-P+A  (relative 26 bit branch)
  R_ARM_ABS32     =  2,    // S+A
  R_ARM_REL32     =  3,    // S-P+A
  R_ARM_PC13      =  4,    // S-P+A
  R_ARM_ABS16     =  5,    // S+A
  R_ARM_ABS12     =  6,    // S+A
  R_ARM_THM_ABS5  =  7,    // S+A
  R_ARM_ABS8      =  8,    // S+A
  R_ARM_SBREL32   =  9,    // S-B+A
  R_ARM_THM_PC22  = 10,    // S-P+A
  R_ARM_THM_PC8   = 11,    // S-P+A
  R_ARM_VCALL9    = 12,    // S-B+A
  R_ARM_SWI24     = 13,    // S+A
  R_ARM_THM_SWI8  = 14,    // S+A
  R_ARM_XPC25     = 15,    // S-P+A
  R_ARM_THM_XPC22 = 16,    // S-P+A
  R_ARM_TLS_DTPMOD32 = 17,      /* ID of module containing symbol */
  R_ARM_TLS_DTPOFF32 = 18,      /* Offset in TLS block */
  R_ARM_TLS_TPOFF32  = 19,      /* Offset in static TLS block */
// linux-specific
  R_ARM_COPY      = 20,     // none (copy symbol at runtime)
  R_ARM_GLOB_DAT  = 21,     // S (create .got entry)
  R_ARM_JUMP_SLOT = 22,     // S (create .plt entry)
  R_ARM_RELATIVE  = 23,     // B+A (adjust by programm base)
  R_ARM_GOTOFF    = 24,     // S+A-G (32bit offset to .got)
  R_ARM_GOTPC     = 25,     // S+A-P (32bit IP-relative offset to .got)
  R_ARM_GOT32     = 26,     // G+A-P (32bit .got entry)
  R_ARM_PLT32     = 27,     // L+A-P (32bit .plt entry)

  R_ARM_CALL            =  28,
  R_ARM_JUMP24          =  29,
  R_ARM_THM_JUMP24      =  30, // ((S + A) | T) � P
  R_ARM_BASE_ABS        =  31, // B(S) + A
  R_ARM_ALU_PCREL7_0    =  32,
  R_ARM_ALU_PCREL15_8   =  33,
  R_ARM_ALU_PCREL23_15  =  34,
  R_ARM_LDR_SBREL_11_0  =  35,
  R_ARM_ALU_SBREL_19_12 =  36,
  R_ARM_ALU_SBREL_27_20 =  37,
  R_ARM_TARGET1         =  38,
  R_ARM_ROSEGREL32      =  39,
  R_ARM_V4BX            =  40,
  R_ARM_TARGET2         =  41,
  R_ARM_PREL31          =  42,
  R_ARM_MOVW_ABS_NC     =  43, //  Static ARM       (S + A) | T
  R_ARM_MOVT_ABS        =  44, //  Static ARM       S + A
  R_ARM_MOVW_PREL_NC    =  45, //  Static ARM       ((S + A) | T) � P
  R_ARM_MOVT_PREL       =  46, //  Static ARM       S + A � P
  R_ARM_THM_MOVW_ABS_NC =  47, //  Static Thumb32   (S + A) | T
  R_ARM_THM_MOVT_ABS    =  48, //  Static Thumb32   S + A
  R_ARM_THM_MOVW_PREL_NC=  49, //  Static Thumb32   ((S + A) | T) � P
  R_ARM_THM_MOVT_PREL   =  50, //  Static Thumb32   S + A � P
  R_ARM_THM_JUMP19      =  51, //  Static Thumb32   ((S + A) | T) � P
  R_ARM_THM_JUMP6       =  52, //  Static Thumb16   S + A � P
  R_ARM_THM_ALU_PREL_11_0= 53, //  Static Thumb32   ((S + A) | T) � Pa
  R_ARM_THM_PC12        =  54, //  Static Thumb32   S + A � Pa
  R_ARM_ABS32_NOI       =  55, //  Static Data      S + A
  R_ARM_REL32_NOI       =  56, //  Static Data      S + A � P
  R_ARM_ALU_PC_G0_NC    =  57, //  Static ARM       ((S + A) | T) � P
  R_ARM_ALU_PC_G0       =  58, //  Static ARM       ((S + A) | T) � P
  R_ARM_ALU_PC_G1_NC    =  59, //  Static ARM       ((S + A) | T) � P
  R_ARM_ALU_PC_G1       =  60, //  Static ARM       ((S + A) | T) � P
  R_ARM_ALU_PC_G2       =  61, //  Static ARM       ((S + A) | T) � P
  R_ARM_LDR_PC_G1       =  62, //  Static ARM       S + A � P
  R_ARM_LDR_PC_G2       =  63, //  Static ARM       S + A � P
  R_ARM_LDRS_PC_G0      =  64, //  Static ARM       S + A � P

  R_ARM_LDRS_PC_G1 = 65,       // Static       ARM     S + A - P
  R_ARM_LDRS_PC_G2 = 66,       // Static       ARM     S + A - P
  R_ARM_LDC_PC_G0 = 67,        // Static       ARM     S + A - P
  R_ARM_LDC_PC_G1 = 68,        // Static       ARM     S + A - P
  R_ARM_LDC_PC_G2 = 69,        // Static       ARM     S + A - P
  R_ARM_ALU_SB_G0_NC = 70,     // Static       ARM     ((S + A) | T) - B(S)
  R_ARM_ALU_SB_G0 = 71,        // Static       ARM     ((S + A) | T) - B(S)
  R_ARM_ALU_SB_G1_NC = 72,     // Static       ARM     ((S + A) | T) - B(S)
  R_ARM_ALU_SB_G1 = 73,        // Static       ARM     ((S + A) | T) - B(S)
  R_ARM_ALU_SB_G2 = 74,        // Static       ARM     ((S + A) | T) - B(S)
  R_ARM_LDR_SB_G0 = 75,        // Static       ARM     S + A - B(S)
  R_ARM_LDR_SB_G1 = 76,        // Static       ARM     S + A - B(S)
  R_ARM_LDR_SB_G2 = 77,        // Static       ARM     S + A - B(S)
  R_ARM_LDRS_SB_G0 = 78,       // Static       ARM     S + A - B(S)
  R_ARM_LDRS_SB_G1 = 79,       // Static       ARM     S + A - B(S)
  R_ARM_LDRS_SB_G2 = 80,       // Static       ARM     S + A - B(S)
  R_ARM_LDC_SB_G0 = 81,        // Static       ARM     S + A - B(S)
  R_ARM_LDC_SB_G1 = 82,        // Static       ARM     S + A - B(S)
  R_ARM_LDC_SB_G2 = 83,        // Static       ARM     S + A - B(S)
  R_ARM_MOVW_BREL_NC = 84,     // Static       ARM     ((S + A) | T) - B(S)
  R_ARM_MOVT_BREL = 85,        // Static       ARM     S + A - B(S)
  R_ARM_MOVW_BREL = 86,        // Static       ARM     ((S + A) | T) - B(S)
  R_ARM_THM_MOVW_BREL_NC = 87, // Static       Thumb32 ((S + A) | T) - B(S)
  R_ARM_THM_MOVT_BREL    = 88, // Static       Thumb32 S + A - B(S)
  R_ARM_THM_MOVW_BREL    = 89, // Static       Thumb32 ((S + A) | T) - B(S)
  R_ARM_TLS_GOTDESC      = 90, // Static       Data
  R_ARM_TLS_CALL         = 91, // Static       ARM
  R_ARM_TLS_DESCSEQ      = 92, // Static       ARM     TLS relaxation
  R_ARM_THM_TLS_CALL     = 93, // Static       Thumb32
  R_ARM_PLT32_ABS        = 94, // Static       Data    PLT(S) + A

  R_ARM_GOT_ABS         = 95,
  R_ARM_GOT_PREL        = 96,
  R_ARM_GOT_BREL12      = 97,
  R_ARM_GOTOFF12        = 98,
  R_ARM_GOTRELAX        = 99,
  R_ARM_GNU_VTENTRY     = 100,
  R_ARM_GNU_VTINHERIT   = 101,

  R_ARM_THM_PC11        = 102, /* Cygnus extension to abi: Thumb unconditional branch.  */
  R_ARM_THM_PC9         = 103, /* Cygnus extension to abi: Thumb conditional branch.  */
  R_ARM_THM_JUMP11 = 102,       // Static       Thumb16 S + A - P
  R_ARM_THM_JUMP8 = 103,        // Static       Thumb16 S + A - P
  R_ARM_TLS_GD32 = 104,         // Static       Data    GOT(S) + A - P
  R_ARM_TLS_LDM32 = 105,        // Static       Data    GOT(S) + A - P
  R_ARM_TLS_LDO32 = 106,        // Static       Data    S + A - TLS
  R_ARM_TLS_IE32 = 107,         // Static       Data    GOT(S) + A - P
  R_ARM_TLS_LE32 = 108,         // Static       Data    S + A - tp
  R_ARM_TLS_LDO12 = 109,        // Static       ARM     S + A - TLS
  R_ARM_TLS_LE12 = 110,         // Static       ARM     S + A - tp
  R_ARM_TLS_IE12GP = 111,       // Static       ARM     GOT(S) + A - GOT_ORG
  R_ARM_PRIVATE_0 = 112,        // Private (n = 0, 1, ... 15)
  R_ARM_PRIVATE_1 = 113,
  R_ARM_PRIVATE_2 = 114,
  R_ARM_PRIVATE_3 = 115,
  R_ARM_PRIVATE_4 = 116,
  R_ARM_PRIVATE_5 = 117,
  R_ARM_PRIVATE_6 = 118,
  R_ARM_PRIVATE_7 = 119,
  R_ARM_PRIVATE_8 = 120,
  R_ARM_PRIVATE_9 = 121,
  R_ARM_PRIVATE_10 = 122,
  R_ARM_PRIVATE_11 = 123,
  R_ARM_PRIVATE_12 = 124,
  R_ARM_PRIVATE_13 = 125,
  R_ARM_PRIVATE_14 = 126,
  R_ARM_PRIVATE_15 = 127,
  R_ARM_ME_TOO = 128,           // Obsolete
  R_ARM_THM_TLS_DESCSEQ16 = 129,// Static       Thumb16
  R_ARM_THM_TLS_DESCSEQ32 = 130,// Static       Thumb32

  // 131 - 139                  Unallocated
  // 140 - 159                  Dynamic         Reserved for future allocation

  R_ARM_IRELATIVE  = 160,

  // 161 - 255                  Unallocated

//
//ATT: R_ARM_RXPC25 used ONLY in OLD_ABI (+ 15 OTHER relocs!)
// dynamic sections only
  R_ARM_RXPC25    = 249,   // (BLX) call between segments
//
  R_ARM_RSBREL32  = 250,   // (Word) SBrelative offset
  R_ARM_THM_RPC22 = 251,   // (Thumb BL/BLX) call between segments
  R_ARM_RREL32    = 252,   // (Word) inter-segment offset
  R_ARM_RABS32    = 253,   // (Word) Target segment displacement
  R_ARM_RPC24     = 254,   // (BL/BLX) call between segment
  R_ARM_RBASE     = 255    // segment being relocated
};

// Flags:
#define EF_ARM_RELEXEC        0x00000001  // dynamic only how to relocation
#define EF_ARM_HASENTRY       0x00000002  // e_entry is real start address

// GNU flags (EABI version = 0)
#define EF_ARM_INTERWORK      0x00000004  // interworking enabled
#define EF_ARM_APCS_26        0x00000008  // APCS-26 used (otherwise APCS-32)
#define EF_ARM_APCS_FLOAT     0x00000010  // floats passed in float registers
#define EF_ARM_PIC            0x00000020  // Position-independent code
#define EF_ARM_ALIGN8         0x00000040  // 8-bit struct alignment
#define EF_ARM_NEW_ABI        0x00000080  // New ABI
#define EF_ARM_OLD_ABI        0x00000100  // Old ABI
#define EF_ARM_SOFT_FLOAT     0x00000200  // software FP
#define EF_ARM_VFP_FLOAT      0x00000400  // VFP float format
#define EF_ARM_MAVERICK_FLOAT 0x00000800  // Maverick float format

// ARM flags:
#define EF_ARM_SYMSARESORTED  0x00000004  // Each subsection of the symbol table is sorted by symbol value (NB conflicts with EF_INTERWORK)
#define EF_ARM_DYNSYMSUSESEGIDX 0x00000008 // Symbols in dynamic symbol tables that are defined in sections
                                          // included in program segment n have st_shndx = n + 1. (NB conflicts with EF_APCS26)
#define EF_ARM_MAPSYMSFIRST   0x00000010  // Mapping symbols precede other local symbols in the symbol
                                          // table (NB conflicts with EF_APCS_FLOAT)
#define EF_ARM_LE8	      0x00400000  // LE-8 code
#define EF_ARM_BE8            0x00800000  // BE-8 code for ARMv6 or later
#define EF_ARM_EABIMASK       0xFF000000  // ARM EABI version

/* Additional symbol types for Thumb.  */
#define STT_ARM_TFUNC      STT_LOPROC   /* A Thumb function.  */
#define STT_ARM_16BIT      STT_HIPROC   /* A Thumb label.  */

// patching GOT loading,
// discard auxiliary values in plt/got
// can present offset bypass segment
#define ELF_RPL_ARM_DEFAULT  (ELF_RPL_GL | ELF_RPL_UNL | \
                              ELF_DIS_OFFW | ELF_DIS_GPLT | ELF_BS_DBG)

enum elf_SHT_ARM {
  SHT_ARM_EXIDX = 0x70000001,          // Exception Index table
  SHT_ARM_PREEMPTMAP = 0x70000002,     // BPABI DLL dynamic linking pre-emption map
  SHT_ARM_ATTRIBUTES = 0x70000003,     // Object file compatibility attributes
  SHT_ARM_DEBUGOVERLAY = 0x70000004,   //
  SHT_ARM_OVERLAYSECTION = 0x70000005, //
};

enum elf_PT_ARM {
  PT_ARM_ARCHEXT = 0x70000000,         // Platform architecture compatibility information
  PT_ARM_EXIDX = 0x70000001            // Exception unwind tables
};

enum eabi_tags_t
{
  Tag_NULL,
  Tag_File,                       // (=1) <uint32: byte-size> <attribute>*
  Tag_Section,                    // (=2) <uint32: byte-size> <section number>* 0 <attribute>*
  Tag_Symbol,                     // (=3) <unit32: byte-size> <symbol number>* 0 <attribute>*
  Tag_CPU_raw_name,               // (=4), NTBS
  Tag_CPU_name,                   // (=5), NTBS
  Tag_CPU_arch,                   // (=6), uleb128
  Tag_CPU_arch_profile,           // (=7), uleb128
  Tag_ARM_ISA_use,                // (=8), uleb128
  Tag_THUMB_ISA_use,              // (=9), uleb128
  Tag_FP_arch,                   // (=10), uleb128 (formerly Tag_VFP_arch = 10)
  Tag_VFP_arch = Tag_FP_arch,
  Tag_WMMX_arch,                  // (=11), uleb128
  Tag_NEON_arch,                  // (=12), uleb128
  Tag_PCS_config,                 // (=13), uleb128
  Tag_ABI_PCS_R9_use,             // (=14), uleb128
  Tag_ABI_PCS_RW_data,            // (=15), uleb128
  Tag_ABI_PCS_RO_data,            // (=16), uleb128
  Tag_ABI_PCS_GOT_use,            // (=17), uleb128
  Tag_ABI_PCS_wchar_t,            // (=18), uleb128
  Tag_ABI_FP_rounding,            // (=19), uleb128
  Tag_ABI_FP_denormal,            // (=20), uleb128
  Tag_ABI_FP_exceptions,          // (=21), uleb128
  Tag_ABI_FP_user_exceptions,     // (=22), uleb128
  Tag_ABI_FP_number_model,        // (=23), uleb128
  Tag_ABI_align_needed,           // (=24), uleb128
  Tag_ABI_align8_needed = Tag_ABI_align_needed,
  Tag_ABI_align_preserved,        // (=25), uleb128
  Tag_ABI_align8_preserved = Tag_ABI_align_preserved,
  Tag_ABI_enum_size,              // (=26), uleb128
  Tag_ABI_HardFP_use,             // (=27), uleb128
  Tag_ABI_VFP_args,               // (=28), uleb128
  Tag_ABI_WMMX_args,              // (=29), uleb128
  Tag_ABI_optimization_goals,     // (=30), uleb128
  Tag_ABI_FP_optimization_goals,  // (=31), uleb128
  Tag_compatibility,              // (=32), uleb128: flag, NTBS: vendor-name
  Tag_CPU_unaligned_access=34,    // (=34), uleb128
  Tag_FP_HP_extension=36,         // (=36), uleb128 (formerly Tag_VFP_HP_extension = 36)
  Tag_VFP_HP_extension = Tag_FP_HP_extension,
  Tag_ABI_FP_16bit_format=38,     // (=38), uleb128
  Tag_MPextension_use=42,         // (=42), uleb128
  Tag_DIV_use=44,                 // (=44), uleb128
  Tag_nodefaults=64,              // (=64), uleb128: ignored (write as 0)
  Tag_also_compatible_with,       // (=65), NTBS: data; ULEB128-encoded tag followed by a value of that tag.
  Tag_T2EE_use,                   // (=66), uleb128
  Tag_conformance,                // (=67), string: ABI-version
  Tag_Virtualization_use,         // (=68), uleb128
  Tag_MPextension_use_legacy=70,  // (=70),
};

//----------------------------------------------------------------------------
class arm_arch_specific_t : public arch_specific_t
{
public:
  arm_arch_specific_t()
    : isa_handler(NULL),
      has_mapsym(false),
      track_mapsym(false),
      be8_code(false),
      isa_ranges(),
      thumb_entry(BADADDR) {}

  virtual ~arm_arch_specific_t() {}
  virtual void on_start_symbols(reader_t& reader);
  virtual void on_symbol_read(reader_t & reader,
                              buffered_input_t<sym_rel> &input,
                              sym_rel &sym);
  bool is_mapping_symbol(const char *name) const;
  bool has_mapping_symbols() const {return has_mapsym;}

  // Tracking mapping symbols can be useful for
  // determining whether a certain function is using
  // the Thumb or ARM ISA.
  // In some ELF files, the only way to know what ISA
  // certain functions are in is by looking at some
  // mapping symbols (i.e., '$a', '$t').
  // By default, tracking of such symbols in an
  // instance of this class is _not_ enabled.
  void set_mapping_symbols_tracking(bool track) { track_mapsym = track; }
  bool  is_mapping_symbols_tracking() const { return track_mapsym; }

  enum isa_t
  {
    isa_arm = 1,
    isa_thumb
  };
  void set_isa_handler(void (*ih) (reader_t &reader,
                                   sym_rel &symbol,
                                   isa_t isa,
                                   bool force)) { isa_handler = ih; }

  std::set<ea_t> forced_isas;

  void set_thumb_entry(ea_t te) { thumb_entry = te; }
  void set_be8(bool be8)        { be8_code = be8; }
  bool is_be8()                 { return be8_code; }

private:
  void notify_isa(reader_t &reader, sym_rel &symbol, isa_t isa, bool force)
  {
    if ( isa_handler != NULL )
      isa_handler(reader, symbol, isa, force);
  }

  isa_t get_isa(const sym_rel &symbol) const;
  void  set_isa(const sym_rel &symbol, isa_t isa);

  void (*isa_handler) (reader_t &reader, sym_rel &symbol, isa_t isa, bool force);
  bool has_mapsym;
  bool track_mapsym;
  bool be8_code;

  typedef std::map<uint64,isa_t> section_isa_ranges_t;
  typedef std::map<uint16,section_isa_ranges_t> isa_ranges_t;
  isa_ranges_t isa_ranges;
  ea_t thumb_entry;
};

//----------------------------------------------------------------------------
// Specific flags that will be set on sym_rel instances.
enum arm_sym_rel_flags
{
  thumb_function = 1
};

#endif
