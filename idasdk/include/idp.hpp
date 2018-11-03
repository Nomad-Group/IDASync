/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2015 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef _IDP_HPP
#define _IDP_HPP

#include <fpro.h>
#include <nalt.hpp>
#include <segment.hpp>
#include <funcs.hpp>
#include <ua.hpp>
#include <bitrange.hpp>
#include <config.hpp>

/*! \file idp.hpp

  \brief Contains definition of the interface to IDP modules.

  The interface consists of 2 structures:
    - definition of target assembler: ::ash
    - definition of current processor: ::ph

  These structures contain information about processor features,
  function pointers, etc.
*/

typedef int help_t; ///< help screen number

struct outctx_t;
struct regval_t;
struct simd_info_t;

/// The interface version number.
/// \note see also #IDA_SDK_VERSION from pro.h

#define IDP_INTERFACE_VERSION 700

//-----------------------------------------------------------------------
/// Structure used to describe byte streams
/// (for "ret" instruction and empirics)
struct bytes_t
{
  uchar len;
  const uchar *bytes;
};

//-----------------------------------------------------------------------
/// Internal representation of processor instructions.
/// Definition of all internal instructions are kept in special arrays.
/// One of such arrays describes instruction names and features.
struct instruc_t
{
  const char *name;       ///< instruction name
  uint32 feature;         ///< combination of \ref CF_
/// \defgroup CF_ Instruction feature bits
/// Used by instruc_t::feature
//@{
#define CF_STOP 0x00001   ///< Instruction doesn't pass execution to the
                          ///< next instruction
#define CF_CALL 0x00002   ///< CALL instruction (should make a procedure here)
#define CF_CHG1 0x00004   ///< The instruction modifies the first operand
#define CF_CHG2 0x00008   ///< The instruction modifies the second operand
#define CF_CHG3 0x00010   ///< The instruction modifies the third operand
#define CF_CHG4 0x00020   ///< The instruction modifies 4 operand
#define CF_CHG5 0x00040   ///< The instruction modifies 5 operand
#define CF_CHG6 0x00080   ///< The instruction modifies 6 operand
#define CF_USE1 0x00100   ///< The instruction uses value of the first operand
#define CF_USE2 0x00200   ///< The instruction uses value of the second operand
#define CF_USE3 0x00400   ///< The instruction uses value of the third operand
#define CF_USE4 0x00800   ///< The instruction uses value of the 4 operand
#define CF_USE5 0x01000   ///< The instruction uses value of the 5 operand
#define CF_USE6 0x02000   ///< The instruction uses value of the 6 operand
#define CF_JUMP 0x04000   ///< The instruction passes execution using indirect
                          ///< jump or call (thus needs additional analysis)
#define CF_SHFT 0x08000   ///< Bit-shift instruction (shl,shr...)
#define CF_HLL  0x10000   ///< Instruction may be present in a high level
                          ///< language function.
//@}
};


/// Does the specified instruction have the specified feature?

idaman bool ida_export has_insn_feature(int icode,int bit);



/// Is the instruction a "call"?

idaman bool ida_export is_call_insn(const insn_t &insn);


/// Is the instruction a "return"?

idaman bool ida_export is_ret_insn(const insn_t &insn, bool strict=true);


/// Is the instruction an indirect jump?

idaman bool ida_export is_indirect_jump_insn(const insn_t &insn);


/// Is the instruction the end of a basic block?

idaman bool ida_export is_basic_block_end(const insn_t &insn, bool call_insn_stops_block);


//--------------------------------------------------------------------------
/// Callback provided to hook_to_notification_point().
/// A plugin can hook to a notification point and receive notifications
/// of all major events in IDA. The callback function will be called
/// for each event.
/// \param user_data          data supplied in call to hook_to_notification_point()
/// \param notification_code  processor_t::event_t or ::ui_notification_t, depending on
///                           the hook type
/// \param va                 additional parameters supplied with the notification.
///                           see the event descriptions for information
/// \retval 0    ok, the event should be processed further
/// \retval !=0  the event is blocked and should be discarded.
///              in the case of processor modules, the returned value is used
///              as the return value of processor_t::notify()

typedef ssize_t idaapi hook_cb_t(void *user_data, int notification_code, va_list va);

/// Types of events that be hooked to with hook_to_notification_point()
enum hook_type_t
{
  HT_IDP,         ///< Hook to the processor module.
                  ///< The callback will receive all processor_t::event_t events.
  HT_UI,          ///< Hook to the user interface.
                  ///< The callback will receive all ::ui_notification_t events.
  HT_DBG,         ///< Hook to the debugger.
                  ///< The callback will receive all ::dbg_notification_t events.
  HT_IDB,         ///< Hook to the database events.
                  ///< These events are separated from the ::HT_IDP group
                  ///< to speed things up (there are too many plugins and
                  ///< modules hooking to the ::HT_IDP). Some essential events
                  ///< are still generated in th ::HT_IDP group:
                  ///< make_code, make_data
                  ///< This list is not exhaustive.
                  ///< A common trait of all events in this group: the kernel
                  ///< does not expect any reaction to the event and does not
                  ///< check the return code. For event names, see ::idb_event.
  HT_DEV,         ///< Internal debugger events.
                  ///< Not stable and undocumented for the moment
  HT_VIEW,        ///< Custom/IDA views notifications.
                  ///< Refer to ::view_notification_t
                  ///< for notification codes
  HT_OUTPUT,      ///< Output window notifications.
                  ///< Refer to ::msg_notification_t
                  ///< (::view_notification_t)
  HT_GRAPH,       ///< Handling graph operations
                  ///< (::graph_notification_t)
  HT_LAST
};


/// Register a callback for a class of events in IDA

idaman bool ida_export hook_to_notification_point(
        hook_type_t hook_type,
        hook_cb_t *cb,
        void *user_data = NULL);


/// Unregister a callback (also see hook_to_notification_point()).
/// A plugin should unhook before being unloaded
/// (preferably in its termination function).
/// If different callbacks have the same callback function pointer
/// and user_data is not NULL, only the callback whose associated
/// user defined data matches will be removed.
/// \return number of unhooked functions.

idaman int ida_export unhook_from_notification_point(
        hook_type_t hook_type,
        hook_cb_t *cb,
        void *user_data = NULL);


/// Generate event notification.
/// \param hook_type hook type
/// \param code      event code
/// \param va        additional arguments
/// \return !=0: event processed

idaman ssize_t ida_export invoke_callbacks(hook_type_t hook_type, int code, va_list va);


#ifdef __BORLANDC__
#pragma option push -b-
#endif

#ifdef __BORLANDC__
#pragma option pop
#endif

//=====================================================================
/// Describes the target assembler.
/// An IDP module may have several target assemblers.
/// In this case you should create a structure for each supported
/// assembler.
struct asm_t
{
  uint32 flag;                          ///< \ref AS_
/// \defgroup AS_ Assembler feature bits
/// Used by asm_t::flag.
//@{
#define AS_OFFST      0x00000001L       ///< offsets are 'offset xxx' ?
#define AS_COLON      0x00000002L       ///< create colons after data names ?
#define AS_UDATA      0x00000004L       ///< can use '?' in data directives

#define AS_2CHRE      0x00000008L       ///< double char constants are: "xy
#define AS_NCHRE      0x00000010L       ///< char constants are: 'x
#define AS_N2CHR      0x00000020L       ///< can't have 2 byte char consts

                                        // String literals:
#define AS_1TEXT      0x00000040L       ///<   1 text per line, no bytes
#define AS_NHIAS      0x00000080L       ///<   no characters with high bit
#define AS_NCMAS      0x00000100L       ///<   no commas in ascii directives

#define AS_HEXFM      0x00000E00L       ///< mask - hex number format
#define ASH_HEXF0     0x00000000L       ///<   34h
#define ASH_HEXF1     0x00000200L       ///<   h'34
#define ASH_HEXF2     0x00000400L       ///<   34
#define ASH_HEXF3     0x00000600L       ///<   0x34
#define ASH_HEXF4     0x00000800L       ///<   $34
#define ASH_HEXF5     0x00000A00L       ///<   <^R   > (radix)
#define AS_DECFM      0x00003000L       ///< mask - decimal number format
#define ASD_DECF0     0x00000000L       ///<   34
#define ASD_DECF1     0x00001000L       ///<   #34
#define ASD_DECF2     0x00002000L       ///<   34.
#define ASD_DECF3     0x00003000L       ///<   .34
#define AS_OCTFM      0x0001C000L       ///< mask - octal number format
#define ASO_OCTF0     0x00000000L       ///<   123o
#define ASO_OCTF1     0x00004000L       ///<   0123
#define ASO_OCTF2     0x00008000L       ///<   123
#define ASO_OCTF3     0x0000C000L       ///<   @123
#define ASO_OCTF4     0x00010000L       ///<   o'123
#define ASO_OCTF5     0x00014000L       ///<   123q
#define ASO_OCTF6     0x00018000L       ///<   ~123
#define ASO_OCTF7     0x0001C000L       ///<   q'123
#define AS_BINFM      0x000E0000L       ///< mask - binary number format
#define ASB_BINF0     0x00000000L       ///<   010101b
#define ASB_BINF1     0x00020000L       ///<   ^B010101
#define ASB_BINF2     0x00040000L       ///<   %010101
#define ASB_BINF3     0x00060000L       ///<   0b1010101
#define ASB_BINF4     0x00080000L       ///<   b'1010101
#define ASB_BINF5     0x000A0000L       ///<   b'1010101'

#define AS_UNEQU      0x00100000L       ///< replace undefined data items with EQU (for ANTA's A80)
#define AS_ONEDUP     0x00200000L       ///< One array definition per line
#define AS_NOXRF      0x00400000L       ///< Disable xrefs during the output file generation
#define AS_XTRNTYPE   0x00800000L       ///< Assembler understands type of extern symbols as ":type" suffix
#define AS_RELSUP     0x01000000L       ///< Checkarg: 'and','or','xor' operations with addresses are possible
#define AS_LALIGN     0x02000000L       ///< Labels at "align" keyword are supported.
#define AS_NOCODECLN  0x04000000L       ///< don't create colons after code names
#define AS_NOSPACE    0x10000000L       ///< No spaces in expressions
#define AS_ALIGN2     0x20000000L       ///< .align directive expects an exponent rather than a power of 2
                                        ///< (.align 5 means to align at 32byte boundary)
#define AS_ASCIIC     0x40000000L       ///< ascii directive accepts C-like escape sequences
                                        ///< (\\n,\\x01 and similar)
#define AS_ASCIIZ     0x80000000L       ///< ascii directive inserts implicit zero byte at the end
//@}
  uint16 uflag;                         ///< user defined flags (local only for IDP)
                                        ///< you may define and use your own bits
  const char *name;                     ///< Assembler name (displayed in menus)
  help_t help;                          ///< Help screen number, 0 - no help
  const char *const *header;            ///< array of automatically generated header lines
                                        ///< they appear at the start of disassembled text
  const char *origin;                   ///< org directive
  const char *end;                      ///< end directive
  const char *cmnt;                     ///< comment string (see also cmnt2)
  char ascsep;                          ///< string literal delimiter
  char accsep;                          ///< char constant delimiter
  const char *esccodes;                 ///< special chars that can not appear
                                        ///< as is in string and char literals

  // Data representation (db,dw,...):
  const char *a_ascii;                  ///< string literal directive
  const char *a_byte;                   ///< byte directive
  const char *a_word;                   ///< word directive
  const char *a_dword;                  ///< NULL if not allowed
  const char *a_qword;                  ///< NULL if not allowed
  const char *a_oword;                  ///< NULL if not allowed
  const char *a_float;                  ///< float;  4bytes; NULL if not allowed
  const char *a_double;                 ///< double; 8bytes; NULL if not allowed
  const char *a_tbyte;                  ///< long double;    NULL if not allowed
  const char *a_packreal;               ///< packed decimal real NULL if not allowed
  const char *a_dups;                   ///< array keyword. the following
                                        ///< sequences may appear:
                                        ///<      - #h  header
                                        ///<      - #d  size
                                        ///<      - #v  value
                                        ///<      - #s(b,w,l,q,f,d,o)  size specifiers
                                        ///<                        for byte,word,
                                        ///<                            dword,qword,
                                        ///<                            float,double,oword
  const char *a_bss;                    ///< uninitialized data directive
                                        ///< should include '%s' for the
                                        ///< size of data
  const char *a_equ;                    ///< 'equ' Used if AS_UNEQU is set
  const char *a_seg;                    ///< 'seg ' prefix (example: push seg seg001)

  const char *a_curip;                  ///< current IP (instruction pointer) symbol in assembler

  /// Generate function header lines.
  /// If NULL, then function headers are displayed as normal lines
  void (idaapi *out_func_header)(outctx_t &ctx, func_t *);

  /// Generate function footer lines.
  /// If NULL, then a comment line is displayed
  void (idaapi *out_func_footer)(outctx_t &ctx, func_t *);

  const char *a_public;                 ///< "public" name keyword. NULL-use default, ""-do not generate
  const char *a_weak;                   ///< "weak"   name keyword. NULL-use default, ""-do not generate
  const char *a_extrn;                  ///< "extern" name keyword
  const char *a_comdef;                 ///< "comm" (communal variable)

  /// Get name of type of item at ea or id.
  /// (i.e. one of: byte,word,dword,near,far,etc...)
  ssize_t (idaapi *get_type_name)(
        qstring *buf,
        flags_t flag,
        ea_t ea_or_id);

  const char *a_align;                  ///< "align" keyword

  char lbrace;                          ///< left brace used in complex expressions
  char rbrace;                          ///< right brace used in complex expressions

  const char *a_mod;                    ///< %  mod     assembler time operation
  const char *a_band;                   ///< &  bit and assembler time operation
  const char *a_bor;                    ///< |  bit or  assembler time operation
  const char *a_xor;                    ///< ^  bit xor assembler time operation
  const char *a_bnot;                   ///< ~  bit not assembler time operation
  const char *a_shl;                    ///< << shift left assembler time operation
  const char *a_shr;                    ///< >> shift right assembler time operation
  const char *a_sizeof_fmt;             ///< size of type (format string)

  uint32 flag2;                         ///< \ref AS2_
/// \defgroup AS2_ Secondary assembler feature bits
/// Used by asm_t::flag2
//@{
#define AS2_BRACE     0x00000001        ///< Use braces for all expressions
#define AS2_STRINV    0x00000002        ///< Invert meaning of \inf{wide_high_byte_first} for text strings
                                        ///< (For processors with bytes bigger than 8 bits)
#define AS2_BYTE1CHAR 0x00000004        ///< One symbol per processor byte
                                        ///< Meaningful only for wide byte processors
#define AS2_IDEALDSCR 0x00000008        ///< Description of struc/union is in
                                        ///< the 'reverse' form (keyword before name)
                                        ///< the same as in borland tasm ideal
#define AS2_TERSESTR  0x00000010        ///< 'terse' structure initialization form
                                        ///< NAME<fld,fld,...> is supported
#define AS2_COLONSUF  0x00000020        ///< addresses may have ":xx" suffix
                                        ///< this suffix must be ignored when extracting
                                        ///< the address under the cursor
#define AS2_YWORD     0x00000040        ///< a_yword field is present and valid
//@}

  const char *cmnt2;                    ///< comment close string (usually NULL)
                                        ///< this is used to denote a string which
                                        ///< closes comments, for example, if the
                                        ///< comments are represented with (* ... *)
                                        ///< then cmnt = "(*" and cmnt2 = "*)"
  const char *low8;                     ///< low8 operation, should contain %s for the operand
  const char *high8;                    ///< high8
  const char *low16;                    ///< low16
  const char *high16;                   ///< high16
  const char *a_include_fmt;            ///< the include directive (format string)
  const char *a_vstruc_fmt;             ///< if a named item is a structure and displayed
                                        ///< in the verbose (multiline) form then display the name
                                        ///< as printf(a_strucname_fmt, typename)
                                        ///< (for asms with type checking, e.g. tasm ideal)
  const char *a_rva;                    ///< 'rva' keyword for image based offsets
                                        ///< (see #REFINFO_RVAOFF)
  const char *a_yword;                  ///< 32-byte (256-bit) data; NULL if not allowed
                                        ///< requires #AS2_YWORD
};

// forward declarations for notification helpers
struct proc_def_t;
struct extlang_t;
class qflow_chart_t;
struct libfunc_t;
struct fixup_data_t;
struct idd_opinfo_t;
class argloc_t;
struct func_type_data_t;
struct regobjs_t;
class callregs_t;
struct funcarg_t;

//=====================================================================
/// Describes a processor module (IDP).
/// An IDP file may have only one such structure called LPH.
/// The kernel will copy it to ::ph structure and use ::ph.
struct processor_t
{
  int32 version;                  ///< Expected kernel version,
                                  ///<   should be #IDP_INTERFACE_VERSION
  int32 id;                       ///< one of \ref PLFM_
/// \defgroup PLFM_ Processor IDs
/// Used by processor_t::id.
/// Numbers above 0x8000 are reserved for the third-party modules
//@{
#define PLFM_386        0         ///< Intel 80x86
#define PLFM_Z80        1         ///< 8085, Z80
#define PLFM_I860       2         ///< Intel 860
#define PLFM_8051       3         ///< 8051
#define PLFM_TMS        4         ///< Texas Instruments TMS320C5x
#define PLFM_6502       5         ///< 6502
#define PLFM_PDP        6         ///< PDP11
#define PLFM_68K        7         ///< Motorola 680x0
#define PLFM_JAVA       8         ///< Java
#define PLFM_6800       9         ///< Motorola 68xx
#define PLFM_ST7        10        ///< SGS-Thomson ST7
#define PLFM_MC6812     11        ///< Motorola 68HC12
#define PLFM_MIPS       12        ///< MIPS
#define PLFM_ARM        13        ///< Advanced RISC Machines
#define PLFM_TMSC6      14        ///< Texas Instruments TMS320C6x
#define PLFM_PPC        15        ///< PowerPC
#define PLFM_80196      16        ///< Intel 80196
#define PLFM_Z8         17        ///< Z8
#define PLFM_SH         18        ///< Renesas (formerly Hitachi) SuperH
#define PLFM_NET        19        ///< Microsoft Visual Studio.Net
#define PLFM_AVR        20        ///< Atmel 8-bit RISC processor(s)
#define PLFM_H8         21        ///< Hitachi H8/300, H8/2000
#define PLFM_PIC        22        ///< Microchip's PIC
#define PLFM_SPARC      23        ///< SPARC
#define PLFM_ALPHA      24        ///< DEC Alpha
#define PLFM_HPPA       25        ///< Hewlett-Packard PA-RISC
#define PLFM_H8500      26        ///< Hitachi H8/500
#define PLFM_TRICORE    27        ///< Tasking Tricore
#define PLFM_DSP56K     28        ///< Motorola DSP5600x
#define PLFM_C166       29        ///< Siemens C166 family
#define PLFM_ST20       30        ///< SGS-Thomson ST20
#define PLFM_IA64       31        ///< Intel Itanium IA64
#define PLFM_I960       32        ///< Intel 960
#define PLFM_F2MC       33        ///< Fujistu F2MC-16
#define PLFM_TMS320C54  34        ///< Texas Instruments TMS320C54xx
#define PLFM_TMS320C55  35        ///< Texas Instruments TMS320C55xx
#define PLFM_TRIMEDIA   36        ///< Trimedia
#define PLFM_M32R       37        ///< Mitsubishi 32bit RISC
#define PLFM_NEC_78K0   38        ///< NEC 78K0
#define PLFM_NEC_78K0S  39        ///< NEC 78K0S
#define PLFM_M740       40        ///< Mitsubishi 8bit
#define PLFM_M7700      41        ///< Mitsubishi 16bit
#define PLFM_ST9        42        ///< ST9+
#define PLFM_FR         43        ///< Fujitsu FR Family
#define PLFM_MC6816     44        ///< Motorola 68HC16
#define PLFM_M7900      45        ///< Mitsubishi 7900
#define PLFM_TMS320C3   46        ///< Texas Instruments TMS320C3
#define PLFM_KR1878     47        ///< Angstrem KR1878
#define PLFM_AD218X     48        ///< Analog Devices ADSP 218X
#define PLFM_OAKDSP     49        ///< Atmel OAK DSP
#define PLFM_TLCS900    50        ///< Toshiba TLCS-900
#define PLFM_C39        51        ///< Rockwell C39
#define PLFM_CR16       52        ///< NSC CR16
#define PLFM_MN102L00   53        ///< Panasonic MN10200
#define PLFM_TMS320C1X  54        ///< Texas Instruments TMS320C1x
#define PLFM_NEC_V850X  55        ///< NEC V850 and V850ES/E1/E2
#define PLFM_SCR_ADPT   56        ///< Processor module adapter for processor modules written in scripting languages
#define PLFM_EBC        57        ///< EFI Bytecode
#define PLFM_MSP430     58        ///< Texas Instruments MSP430
#define PLFM_SPU        59        ///< Cell Broadband Engine Synergistic Processor Unit
#define PLFM_DALVIK     60        ///< Android Dalvik Virtual Machine
#define PLFM_65C816     61        ///< 65802/65816
#define PLFM_M16C       62        ///< Renesas M16C
#define PLFM_ARC        63        ///< Argonaut RISC Core
#define PLFM_UNSP       64        ///< SunPlus unSP
#define PLFM_TMS320C28  65        ///< Texas Instruments TMS320C28x
#define PLFM_DSP96K     66        ///< Motorola DSP96000
#define PLFM_SPC700     67        ///< Sony SPC700
//@}

  uint32 flag;                    ///< \ref PR_
/// \defgroup PR_ Processor feature bits
/// Used by processor_t::flag
//@{
#define PR_SEGS       0x000001    ///< has segment registers?
#define PR_USE32      0x000002    ///< supports 32-bit addressing?
#define PR_DEFSEG32   0x000004    ///< segments are 32-bit by default
#define PR_RNAMESOK   0x000008    ///< allow user register names for location names
//#define PR_DB2CSEG    0x0010    // .byte directive in code segments
//                                // should define even number of bytes
//                                // (used by AVR processor)
#define PR_ADJSEGS    0x000020    ///< IDA may adjust segments' starting/ending addresses.
#define PR_DEFNUM     0x0000C0    ///< mask - default number representation
#define PRN_HEX       0x000000    ///<      hex
#define PRN_OCT       0x000040    ///<      octal
#define PRN_DEC       0x000080    ///<      decimal
#define PRN_BIN       0x0000C0    ///<      binary
#define PR_WORD_INS   0x000100    ///< instruction codes are grouped 2bytes in binary line prefix
#define PR_NOCHANGE   0x000200    ///< The user can't change segments and code/data attributes
                                  ///< (display only)
#define PR_ASSEMBLE   0x000400    ///< Module has a built-in assembler and will react to ev_assemble
#define PR_ALIGN      0x000800    ///< All data items should be aligned properly
#define PR_TYPEINFO   0x001000    ///< the processor module supports type information callbacks
                                  ///< ALL OF THEM SHOULD BE IMPLEMENTED!
#define PR_USE64      0x002000    ///< supports 64-bit addressing?
#define PR_SGROTHER   0x004000    ///< the segment registers don't contain the segment selectors.
#define PR_STACK_UP   0x008000    ///< the stack grows up
#define PR_BINMEM     0x010000    ///< the processor module provides correct segmentation for binary files
                                  ///< (i.e. it creates additional segments)
                                  ///< The kernel will not ask the user to specify the RAM/ROM sizes
#define PR_SEGTRANS   0x020000    ///< the processor module supports the segment translation feature
                                  ///< (meaning it calculates the code
                                  ///< addresses using the map_code_ea() function)
#define PR_CHK_XREF   0x040000    ///< don't allow near xrefs between segments with different bases
#define PR_NO_SEGMOVE 0x080000    ///< the processor module doesn't support move_segm()
                                  ///< (i.e. the user can't move segments)
//#define PR_FULL_HIFXP 0x100000  // ::REF_VHIGH operand value contains full operand
//                                // (not only the high bits) Meaningful if \ph{high_fixup_bits}
#define PR_USE_ARG_TYPES 0x200000 ///< use \ph{use_arg_types} callback
#define PR_SCALE_STKVARS 0x400000 ///< use \ph{get_stkvar_scale} callback
#define PR_DELAYED    0x800000    ///< has delayed jumps and calls
                                  ///< if this flag is set, \ph{is_basic_block_end}, \ph{has_delay_slot}
                                  ///< should be implemented
#define PR_ALIGN_INSN 0x1000000   ///< allow ida to create alignment instructions arbitrarily.
                                  ///< Since these instructions might lead to other wrong instructions
                                  ///< and spoil the listing, IDA does not create them by default anymore
#define PR_PURGING    0x2000000   ///< there are calling conventions which may purge bytes from the stack
#define PR_CNDINSNS   0x4000000   ///< has conditional instructions
#define PR_USE_TBYTE  0x8000000   ///< ::BTMT_SPECFLT means _TBYTE type
#define PR_DEFSEG64  0x10000000   ///< segments are 64-bit by default
#define PR_OUTER     0x20000000   ///< has outer operands (currently only mc68k)
//@}

  uint32 flag2;                   ///< \ref PR2_
/// \defgroup PR2_ Processor additional feature bits
/// Used by processor_t::flag2
//@{
#define PR2_MAPPINGS  0x000001    ///< the processor module uses memory mapping
#define PR2_IDP_OPTS  0x000002    ///< the module has processor-specific configuration options
#define PR2_REALCVT   0x000004    ///< the module has 'realcvt' event implementation
//@}

  bool has_idp_opts(void) const { return (flag2 & PR2_IDP_OPTS)       != 0; }  ///< #PR_IDP_OPTS
  bool has_realcvt(void) const  { return (flag2 & PR2_REALCVT)        != 0; }  ///< #PR_REALCVT
  bool has_segregs(void) const  { return (flag & PR_SEGS)             != 0; }  ///< #PR_SEGS
  bool use32(void) const        { return (flag & (PR_USE64|PR_USE32)) != 0; }  ///< #PR_USE64 or #PR_USE32
  bool use64(void) const        { return (flag & PR_USE64)            != 0; }  ///< #PR_USE64
  bool ti(void) const           { return (flag & PR_TYPEINFO)         != 0; }  ///< #PR_TYPEINFO
  bool stkup(void) const        { return (flag & PR_STACK_UP)         != 0; }  ///< #PR_STACK_UP
  bool use_tbyte(void) const    { return (flag & PR_USE_TBYTE)        != 0; }  ///< #PR_USE_TBYTE
  bool use_mappings(void) const { return (flag2 & PR2_MAPPINGS) != 0; }        ///< #PR2_MAPPINGS


  /// Get segment bitness
  /// \retval 2  #PR_DEFSEG64
  /// \retval 1  #PR_DEFSEG32
  /// \retval 0  none specified

  int get_segm_bitness(void) const { return (flag & PR_DEFSEG64) != 0 ? 2 : (flag & PR_DEFSEG32) != 0; }

  int32 cnbits;                   ///< Number of bits in a byte
                                  ///< for code segments (usually 8).
                                  ///< IDA supports values up to 32 bits
  int32 dnbits;                   ///< Number of bits in a byte
                                  ///< for non-code segments (usually 8).
                                  ///< IDA supports values up to 32 bits

  /// \name Byte size
  /// Number of 8bit bytes required to hold one byte of the target processor.
  //@{
  int cbsize(void) { return (cnbits+7)/8; }  ///< for code segments
  int dbsize(void) { return (dnbits+7)/8; }  ///< for non-code segments
  //@}

  /// \name Names
  /// IDP module may support several compatible processors.
  /// The following arrays define processor names:
  //@{
  const char *const *psnames;     ///< short processor names (NULL terminated).
                                  ///< Each name should be shorter than 9 characters
  const char *const *plnames;     ///< long processor names (NULL terminated).
                                  ///< No restriction on name lengths.
  //@}

  const asm_t *const *assemblers; ///< pointer to array of target
                                  ///< assembler definitions. You may
                                  ///< change this array when current
                                  ///< processor is changed.
                                  ///< (NULL terminated)

/// Custom instruction codes defined by processor extension plugins
/// must be greater than or equal to this
#define CUSTOM_INSN_ITYPE 0x8000

/// processor_t::use_regarg_type uses this bit in the return value
/// to indicate that the register value has been spoiled
#define REG_SPOIL 0x80000000L

  typedef const regval_t &(idaapi regval_getter_t)(
        const char *name,
        const regval_t *regvalues);

  //<hookgen IDP>

  /// Callback notification codes.
  ///
  /// These are passed to notify() when certain events occur in the kernel,
  /// allowing the processor module to take appropriate action.
  ///
  /// If you are not developing a processor module, many of these
  /// codes already have a corresponding function to use instead
  /// (\idpcode{is_call_insn} vs is_call_insn(ea_t), for example).
  ///
  /// If you are developing a processor module, your notify() function
  /// must implement the desired behavior when called with a given code.
  enum event_t
  {
     ev_init,                   ///< The IDP module is just loaded.
                                ///< \param idp_modname  (const char *) processor module name
                                ///< \return <0 on failure

     ev_term,                   ///< The IDP module is being unloaded

     ev_newprc,                 ///< Before changing processor type.
                                ///< \param pnum  (int) processor number in the array of processor names
                                ///< \param keep_cfg (bool) true: do not modify kernel configuration
                                ///< \retval 1  ok
                                ///< \retval <0  prohibit

     ev_newasm,                 ///< Before setting a new assembler.
                                ///< \param asmnum  (int)

     ev_newfile,                ///< A new file has been loaded.
                                ///< \param fname  (char *) input file name

     ev_oldfile,                ///< An old file has been loaded.
                                ///< \param fname  (char *) input file name

     ev_newbinary,              ///< IDA is about to load a binary file.
                                ///< \param filename  (char *)   binary file name
                                ///< \param fileoff   (::qoff64_t) offset in the file
                                ///< \param basepara  (::ea_t)   base loading paragraph
                                ///< \param binoff    (::ea_t)   loader offset
                                ///< \param nbytes    (::uint64) number of bytes to load

     ev_endbinary,              ///< IDA has loaded a binary file.
                                ///< \param ok  (bool) file loaded successfully?

     ev_set_idp_options,        ///< Set IDP-specific configuration option
                                ///< Also see set_options_t above
                                ///< \param keyword     (const char *)
                                ///< \param value_type  (int)
                                ///< \param value       (const void *)
                                ///< \param errbuf      (const char **) - a error message will be returned here (can be NULL)
                                ///< \return  1  ok
                                ///< \return  0  not implemented
                                ///< \return -1  error (and message in errbuf)

     ev_set_proc_options,       ///< Called if the user specified an option string in the command line:
                                ///<  -p<processor name>:<options>.
                                ///< Can be used for setting a processor subtype.
                                ///< Also called if option string is passed to set_processor_type()
                                ///< and IDC's SetProcessorType().
                                ///< \param options     (const char *)
                                ///< \param confidence  (int)
                                ///<          0: loader's suggestion
                                ///<          1: user's decision
                                ///< \return < 0 if bad option string

     ev_ana_insn,               ///< Analyze one instruction and fill 'out' structure.
                                ///< This function shouldn't change the database, flags or anything else.
                                ///< All these actions should be performed only by emu_insn() function.
                                ///< \insn_t{ea} contains address of instruction to analyze.
                                ///< \param out           (::insn_t *)
                                ///< \return length of the instruction in bytes, 0 if instruction can't be decoded.
                                ///< \return 0 if instruction can't be decoded.

     ev_emu_insn,               ///< Emulate instruction, create cross-references, plan to analyze
                                ///< subsequent instructions, modify flags etc. Upon entrance to this function,
                                ///< all information about the instruction is in 'insn' structure.
                                ///< \param insn          (const ::insn_t *)
                                ///< \return  1 ok
                                ///< \return -1 the kernel will delete the instruction

     ev_out_header,             ///< Function to produce start of disassembled text
                                ///< \param outctx        (::outctx_t *)
                                ///< \return void

     ev_out_footer,             ///< Function to produce end of disassembled text
                                ///< \param outctx        (::outctx_t *)
                                ///< \return void

     ev_out_segstart,           ///< Function to produce start of segment
                                ///< \param outctx        (::outctx_t *)
                                ///< \param seg           (::segment_t *)
                                ///< \return 1 ok
                                ///< \return 0 not implemented

     ev_out_segend,             ///< Function to produce end of segment
                                ///< \param outctx        (::outctx_t *)
                                ///< \param seg           (::segment_t *)
                                ///< \return 1 ok
                                ///< \return 0 not implemented

     ev_out_assumes,            ///< Function to produce assume directives
                                ///< when segment register value changes.
                                ///< \param outctx        (::outctx_t *)
                                ///< \return 1 ok
                                ///< \return 0 not implemented

     ev_out_insn,               ///< Generate text representation of an instruction in 'ctx.insn'
                                ///< outctx_t provides functions to output the generated text.
                                ///< This function shouldn't change the database, flags or anything else.
                                ///< All these actions should be performed only by emu_insn() function.
                                ///< \param outctx        (::outctx_t *)
                                ///< \return void

     ev_out_mnem,               ///< Generate instruction mnemonics.
                                ///< This callback should append the colored mnemonics to ctx.outbuf
                                ///< Optional notification, if absent, out_mnem will be called.
                                ///< \param outctx        (::outctx_t *)
                                ///< \return 1 if appended the mnemonics
                                ///< \return 0 not implemented

     ev_out_operand,            ///< Generate text representation of an instruction operand
                                ///< outctx_t provides functions to output the generated text.
                                ///< All these actions should be performed only by emu_insn() function.
                                ///< \param outctx        (::outctx_t *)
                                ///< \param op            (const ::op_t *)
                                ///< \return  1 ok
                                ///< \return -1 operand is hidden

     ev_out_data,               ///< Generate text representation of data items
                                ///< This function may change the database and create cross-references
                                ///< if analyze_only is set
                                ///< \param outctx        (::outctx_t *)
                                ///< \param analyze_only  (bool)
                                ///< \return 1 ok
                                ///< \return 0 not implemented

     ev_out_label,              ///< The kernel is going to generate an instruction
                                ///< label line or a function header.
                                ///< \param outctx        (::outctx_t *)
                                ///< \param colored_name  (const char *)
                                ///< \return <0 if the kernel should not generate the label
                                ///< \return 0 not implemented or continue

     ev_out_special_item,       ///< Generate text representation of an item in a special segment
                                ///< i.e. absolute symbols, externs, communal definitions etc
                                ///< \param outctx  (::outctx_t *)
                                ///< \param segtype (uchar)
                                ///< \return  1  ok
                                ///< \return  0  not implemented
                                ///< \return -1  overflow

     ev_gen_stkvar_def,         ///< Generate stack variable definition line
                                ///< Default line is
                                ///<             varname = type ptr value,
                                ///< where 'type' is one of byte,word,dword,qword,tbyte
                                ///< \param outctx   (::outctx_t *)
                                ///< \param mptr     (const ::member_t *)
                                ///< \param v        (sval_t)
                                ///< \return 1 - ok
                                ///< \return 0 - not implemented

     ev_gen_regvar_def,         ///< Generate register variable definition line.
                                ///< \param outctx  (::outctx_t *)
                                ///< \param v       (::regvar_t *)
                                ///< \retval >0  ok, generated the definition text
                                ///< \return 0 - not implemented

     ev_gen_src_file_lnnum,     ///< Callback: generate analog of:
                                ///<
                                ///< #line "file.c" 123
                                ///<
                                ///< directive.
                                ///< \param outctx  (::outctx_t *) output context
                                ///< \param file    (const char *) source file (may be NULL)
                                ///< \param lnnum   (size_t) line number
                                ///< \retval 1 directive has been generated
                                ///< \return 0 - not implemented

     ev_creating_segm,          ///< A new segment is about to be created.
                                ///< \param seg  (::segment_t *)
                                ///< \retval 1  ok
                                ///< \retval <0  segment should not be created

     ev_moving_segm,            ///< May the kernel move the segment?
                                ///< \param seg    (::segment_t *) segment to move
                                ///< \param to     (::ea_t) new segment start address
                                ///< \param flags  (int) combination of \ref MSF_
                                ///< \retval 0   yes
                                ///< \retval <0  the kernel should stop

     ev_coagulate,              ///< Try to define some unexplored bytes.
                                ///< This notification will be called if the
                                ///< kernel tried all possibilities and could
                                ///< not find anything more useful than to
                                ///< convert to array of bytes.
                                ///< The module can help the kernel and convert
                                ///< the bytes into something more useful.
                                ///< \param start_ea  (::ea_t)
                                ///< \return number of converted bytes

     ev_undefine,               ///< An item in the database (insn or data) is being deleted.
                                ///< \param ea  (ea_t)
                                ///< \return 1 do not delete srranges at the item end
                                ///< \return 0 srranges can be deleted

     ev_treat_hindering_item,   ///< An item hinders creation of another item.
                                ///< \param hindering_item_ea  (::ea_t)
                                ///< \param new_item_flags     (::flags_t)  (0 for code)
                                ///< \param new_item_ea        (::ea_t)
                                ///< \param new_item_length    (::asize_t)
                                ///< \retval 0   no reaction
                                ///< \retval !=0 the kernel may delete the hindering item

     ev_rename,                 ///< The kernel is going to rename a byte.
                                ///< \param ea       (::ea_t)
                                ///< \param new_name (const char *)
                                ///< \param flags    (int) \ref SN_
                                ///< \return <0 if the kernel should not rename it.
                                ///< \return 2 to inhibit the notification. I.e.,
                                ///<           the kernel should not rename, but
                                ///<           'set_name()' should return 'true'.
                                ///<         also see \idpcode{renamed}
                                ///< the return value is ignored when kernel is going to delete name

     ev_is_far_jump,            ///< is indirect far jump or call instruction?
                                ///< meaningful only if the processor has 'near' and 'far' reference types
                                ///< \param icode (int)
                                ///< \return  0  not implemented
                                ///< \return  1  yes
                                ///< \return -1  no

     ev_is_sane_insn,           ///< Is the instruction sane for the current file type?.
                                ///< \param insn      (const ::insn_t*) the instruction
                                ///< \param no_crefs  (int)
                                ///<   1: the instruction has no code refs to it.
                                ///<      ida just tries to convert unexplored bytes
                                ///<      to an instruction (but there is no other
                                ///<      reason to convert them into an instruction)
                                ///<   0: the instruction is created because
                                ///<      of some coderef, user request or another
                                ///<      weighty reason.
                                ///< \retval >=0  ok
                                ///< \retval <0   no, the instruction isn't
                                ///<              likely to appear in the program

     ev_is_cond_insn,           ///< Is conditional instruction?
                                ///< \param insn (const ::insn_t *)    instruction address
                                ///< \retval  1 yes
                                ///< \retval -1 no
                                ///< \retval  0 not implemented or not instruction

     ev_is_call_insn,           ///< Is the instruction a "call"?
                                ///< \param insn (const ::insn_t *) instruction
                                ///< \retval 0  unknown
                                ///< \retval <0 no
                                ///< \retval 1  yes

     ev_is_ret_insn,            ///< Is the instruction a "return"?
                                ///< \param insn    (const ::insn_t *) instruction
                                ///< \param strict  (bool)
                                ///<          1: report only ret instructions
                                ///<          0: include instructions like "leave"
                                ///<             which begins the function epilog
                                ///< \retval 0  unknown
                                ///< \retval <0 no
                                ///< \retval 1  yes

     ev_may_be_func,            ///< Can a function start here?
                                ///< \param insn  (const ::insn_t*) the instruction
                                ///< \param state (int)  autoanalysis phase
                                ///<   0: creating functions
                                ///<   1: creating chunks
                                ///< \return probability 0..100

     ev_is_basic_block_end,     ///< Is the current instruction end of a basic block?.
                                ///< This function should be defined for processors
                                ///< with delayed jump slots.
                                ///< \param insn                   (const ::insn_t*) the instruction
                                ///< \param call_insn_stops_block  (bool)
                                ///< \retval  0  unknown
                                ///< \retval <0  no
                                ///< \retval  1  yes

     ev_is_indirect_jump,       ///< Determine if instruction is an indirect jump.
                                ///< If #CF_JUMP bit can not describe all jump types
                                ///< jumps, please define this callback.
                                ///< \param insn (const ::insn_t*) the instruction
                                ///< \retval 0  use #CF_JUMP
                                ///< \retval 1  no
                                ///< \retval 2  yes

     ev_is_insn_table_jump,     ///< Determine if instruction is a table jump or call.
                                ///< If #CF_JUMP bit can not describe all kinds of table
                                ///< jumps, please define this callback.
                                ///< It will be called for insns with #CF_JUMP bit set.
                                ///< \param insn (const ::insn_t*) the instruction
                                ///< \retval 0   yes
                                ///< \retval <0  no

     ev_is_switch,              ///< Find 'switch' idiom.
                                ///< It will be called for instructions marked with #CF_JUMP.
                                ///< \param si   (switch_info_t *), out
                                ///< \param insn (const ::insn_t *) instruction possibly belonging to a switch
                                ///< \retval 1 switch is found, 'si' is filled
                                ///< \retval 0 no switch found or not implemented

     ev_calc_switch_cases,      ///< Calculate case values and targets for a custom jump table.
                                ///< \param casevec  (::casevec_t *) vector of case values (may be NULL)
                                ///< \param targets  (::eavec_t *) corresponding target addresses (my be NULL)
                                ///< \param insn_ea  (::ea_t) address of the 'indirect jump' instruction
                                ///< \param si       (::switch_info_t *) switch information
                                ///< \retval 1    ok
                                ///< \retval <=0  failed

     ev_create_switch_xrefs,    ///< Create xrefs for a custom jump table.
                                ///< \param jumpea   (::ea_t) address of the jump insn
                                ///< \param si       (const ::switch_info_t *) switch information
                                ///< \return must return 1
                                ///< Must be implemented if module uses custom jump tables, \ref SWI_CUSTOM

     ev_is_align_insn,          ///< Is the instruction created only for alignment purposes?.
                                /// Do not directly call this function, use ::is_align_insn()
                                ///< \param ea (ea_t) - instruction address
                                ///< \retval number of bytes in the instruction

     ev_is_alloca_probe,        ///< Does the function at 'ea' behave as __alloca_probe?
                                ///< \param ea  (::ea_t)
                                ///< \retval 1  yes
                                ///< \retval 0  no

     ev_delay_slot_insn,        ///< Get delay slot instruction
                                ///< \param ea    (::ea_t *) instruction address in question,
                                ///<                         if answer is positive then set 'ea' to
                                ///<                         the delay slot insn address
                                ///< \param bexec (bool *)   execute slot if jumping,
                                ///<                         initially set to 'true'
                                ///< \param fexec (bool *)   execute slot if not jumping,
                                ///<                         initally set to 'true'
                                ///< \retval 1   positive answer
                                ///< \retval <=0 ordinary insn
                                ///< \note Input 'ea' may point to the instruction with a delay slot or
                                ///<       to the delay slot instruction itself.

     ev_is_sp_based,            ///< Check whether the operand is relative to stack pointer or frame pointer
                                ///< This event is used to determine how to output a stack variable
                                ///< If not implemented, then all operands are sp based by default.
                                ///< Implement this event only if some stack references use frame pointer
                                ///< instead of stack pointer.
                                ///< \param mode  (int *) out, combination of \ref OP_FP_SP
                                ///< \param insn  (const insn_t *)
                                ///< \param op    (const op_t *)
                                ///< \return 0  not implemented
                                ///< \return 1  ok

     ev_can_have_type,          ///< Can the operand have a type as offset, segment, decimal, etc?
                                ///< (for example, a register AX can't have a type, meaning that the user can't
                                ///< change its representation. see bytes.hpp for information about types and flags)
                                ///< \param op    (const ::op_t *)
                                ///< \retval 0  unknown
                                ///< \retval <0 no
                                ///< \retval 1  yes

     ev_cmp_operands,           ///< Compare instruction operands
                                ///< \param op1      (const ::op_t*)
                                ///< \param op2      (const ::op_t*)
                                ///< \retval  1  equal
                                ///< \retval -1  not equal
                                ///< \retval  0  not implemented

     ev_adjust_refinfo,         ///< Called from apply_fixup before converting operand to reference.
                                ///< Can be used for changing the reference info.
                                ///< \param ri      (refinfo_t *)
                                ///< \param ea      (::ea_t) instruction address
                                ///< \param n       (int) operand number
                                ///< \param fd      (const fixup_data_t *)
                                ///< \return < 0 - do not create an offset
                                ///< \return 0   - not implemented or refinfo adjusted

     ev_get_operand_string,     ///< Request text string for operand (cli, java, ...).
                                ///< \param buf    (qstring *)
                                ///< \param insn   (const ::insn_t*) the instruction
                                ///< \param opnum  (int) operand number, -1 means any string operand
                                ///< \return  0  no string (or empty string)
                                ///<         >0  original string length without terminating zero

     ev_get_reg_name,           ///< Generate text representation of a register.
                                ///< Most processor modules do not need to implement this callback.
                                ///< It is useful only if \ph{reg_names}[reg] does not provide
                                ///< the correct register name.
                                ///< \param buf     (qstring *) output buffer
                                ///< \param reg     (int) internal register number as defined in the processor module
                                ///< \param width   (size_t) register width in bytes
                                ///< \param reghi   (int) if not -1 then this function will return the register pair
                                ///< \return -1 if error, strlen(buf) otherwise

     ev_str2reg,                ///< Convert a register name to a register number.
                                ///< The register number is the register index in the \ph{reg_names} array
                                ///< Most processor modules do not need to implement this callback
                                ///< It is useful only if \ph{reg_names}[reg] does not provide
                                ///< the correct register names
                                ///< \param regname  (const char *)
                                ///< \return register number + 1
                                ///< \return 0 not implemented or could not be decoded

     ev_get_autocmt,            ///< Callback: get dynamic auto comment.
                                ///< Will be called if the autocomments are enabled
                                ///< and the comment retrieved from ida.int starts with
                                ///< '$!'. 'insn' contains valid info.
                                ///< \param buf     (qstring *) output buffer
                                ///< \param insn    (const ::insn_t*) the instruction
                                ///< \retval 1  new comment has been generated
                                ///< \retval 0  callback has not been handled.
                                ///<            the buffer must not be changed in this case

     ev_get_bg_color,           ///< Get item background color.
                                ///< Plugins can hook this callback to color disassembly lines dynamically
                                ///< \param color  (::bgcolor_t *), out
                                ///< \param ea     (::ea_t)
                                ///< \retval 0  not implemented
                                ///< \retval 1  color set

     ev_is_jump_func,           ///< Is the function a trivial "jump" function?.
                                ///< \param pfn           (::func_t *)
                                ///< \param jump_target   (::ea_t *)
                                ///< \param func_pointer  (::ea_t *)
                                ///< \retval <0  no
                                ///< \retval 0  don't know
                                ///< \retval 1  yes, see 'jump_target' and 'func_pointer'

     ev_func_bounds,            ///< find_func_bounds() finished its work.
                                ///< The module may fine tune the function bounds
                                ///< \param possible_return_code  (int *), in/out
                                ///< \param pfn                   (::func_t *)
                                ///< \param max_func_end_ea       (::ea_t) (from the kernel's point of view)
                                ///< \return void

     ev_verify_sp,              ///< All function instructions have been analyzed.
                                ///< Now the processor module can analyze the stack pointer
                                ///< for the whole function
                                ///< \param pfn  (::func_t *)
                                ///< \retval 0  ok
                                ///< \retval <0 bad stack pointer

     ev_verify_noreturn,        ///< The kernel wants to set 'noreturn' flags for a function.
                                ///< \param pfn  (::func_t *)
                                ///< \return 0: ok. any other value: do not set 'noreturn' flag

     ev_create_func_frame,      ///< Create a function frame for a newly created function
                                ///< Set up frame size, its attributes etc
                                ///< \param pfn      (::func_t *)
                                ///< \return  1  ok
                                ///< \return  0  not implemented

     ev_get_frame_retsize,      ///< Get size of function return address in bytes
                                ///< If this eveny is not implemented, the kernel will assume
                                ///<  - 8 bytes for 64-bit function
                                ///<  - 4 bytes for 32-bit function
                                ///<  - 2 bytes otherwise
                                ///< If this eveny is not implemented, the kernel will assume
                                ///< \param frsize   (int *) frame size (out)
                                ///< \param pfn      (const ::func_t *), can't be NULL
                                ///< \return  1  ok
                                ///< \return  0  not implemented

     ev_get_stkvar_scale_factor,///< Should stack variable references be multiplied by
                                ///< a coefficient before being used in the stack frame?.
                                ///< Currently used by TMS320C55 because the references into
                                ///< the stack should be multiplied by 2
                                ///< \note #PR_SCALE_STKVARS should be set to use this callback
                                ///< \return scaling factor, 0-not implemented

     ev_demangle_name,          ///< Demangle a C++ (or another language) name into a user-readable string.
                                ///< This event is called by demangle_name()
                                ///< \param res     (int32 *) value to return from demangle_name()
                                ///< \param out     (::qstring *) output buffer. may be NULL
                                ///< \param name    (const char *) mangled name
                                ///< \param disable_mask  (uint32) flags to inhibit parts of output or compiler info/other (see MNG_)
                                ///< \param demreq  (demreq_type_t) operation to perform
                                ///< \return: 1 if success, 0-not implemented
                                ///< \note if you call demangle_name() from the handler, protect against recursion!

        // the following 5 events are very low level
        // take care of possible recursion
     ev_add_cref,               ///< A code reference is being created.
                                ///< \param from  (::ea_t)
                                ///< \param to    (::ea_t)
                                ///< \param type  (::cref_t)
                                ///< \return < 0 - cancel cref creation
                                ///< \return 0 - not implemented or continue

     ev_add_dref,               ///< A data reference is being created.
                                ///< \param from  (::ea_t)
                                ///< \param to    (::ea_t)
                                ///< \param type  (::dref_t)
                                ///< \return < 0 - cancel dref creation
                                ///< \return 0 - not implemented or continue

     ev_del_cref,               ///< A code reference is being deleted.
                                ///< \param from    (::ea_t)
                                ///< \param to      (::ea_t)
                                ///< \param expand  (bool)
                                ///< \return < 0 - cancel cref deletion
                                ///< \return 0 - not implemented or continue

     ev_del_dref,               ///< A data reference is being deleted.
                                ///< \param from    (::ea_t)
                                ///< \param to      (::ea_t)
                                ///< \return < 0 - cancel dref deletion
                                ///< \return 0 - not implemented or continue

     ev_coagulate_dref,         ///< Data reference is being analyzed.
                                ///< plugin may correct 'code_ea' (e.g. for thumb mode refs, we clear the last bit)
                                ///< \param from        (::ea_t)
                                ///< \param to          (::ea_t)
                                ///< \param may_define  (bool)
                                ///< \param code_ea     (::ea_t *)
                                ///< \return < 0 - cancel dref analysis
                                ///< \return 0 - not implemented or continue

     ev_may_show_sreg,          ///< The kernel wants to display the segment registers
                                ///< in the messages window.
                                ///< \param current_ea  (::ea_t)
                                ///< \return <0 if the kernel should not show the segment registers.
                                ///< (assuming that the module has done it)
                                ///< \return 0 - not implemented

     ev_loader_elf_machine,     ///< ELF loader machine type checkpoint.
                                ///< A plugin check of the 'machine_type'. If it is the desired one,
                                ///< the the plugin fills 'p_procname' with the processor name
                                ///< (one of the names present in \ph{psnames}).
                                ///< 'p_pd' is used to handle relocations, otherwise can be left untouched.
                                ///< This event occurs for each newly loaded ELF file
                                ///< \param li            (linput_t *)
                                ///< \param machine_type  (int)
                                ///< \param p_procname    (const char **)
                                ///< \param p_pd          (proc_def_t **) (see ldr\elf.h)
                                ///< \return  e_machine value (if it is different from the
                                ///<          original e_machine value, procname and 'p_pd' will be ignored
                                ///<          and the new value will be used)

     ev_auto_queue_empty,       ///< One analysis queue is empty.
                                ///< \param type  (::atype_t)
                                ///< \retval >=0  yes, keep the queue empty (default)
                                ///< \retval <0   no, the queue is not empty anymore
                                ///< see also \ref idb_event::auto_empty_finally

     ev_validate_flirt_func,    ///< Flirt has recognized a library function.
                                ///< This callback can be used by a plugin or proc module
                                ///< to intercept it and validate such a function.
                                ///< \param start_ea  (::ea_t)
                                ///< \param funcname  (const char *)
                                ///< \retval -1  do not create a function,
                                ///< \retval  0  function is validated

     ev_adjust_libfunc_ea,      ///< Called when a signature module has been matched against
                                ///< bytes in the database. This is used to compute the
                                ///< offset at which a particular module's libfunc should
                                ///< be applied.
                                ///< \param sig     (const idasgn_t *)
                                ///< \param libfun  (const libfunc_t *)
                                ///< \param ea      (::ea_t *) \note 'ea' initially contains the ea_t of the
                                ///<                                 start of the pattern match
                                ///< \retval 1   the ea_t pointed to by the third argument was modified.
                                ///< \retval <=0 not modified. use default algorithm.

     ev_assemble,               ///< Assemble an instruction.
                                ///< (display a warning if an error is found).
                                ///< \param bin    (::uchar *) pointer to output opcode buffer
                                ///< \param ea     (::ea_t) linear address of instruction
                                ///< \param cs     (::ea_t) cs of instruction
                                ///< \param ip     (::ea_t) ip of instruction
                                ///< \param use32  (bool) is 32bit segment?
                                ///< \param line   (const char *) line to assemble
                                ///< \return size of the instruction in bytes

     ev_extract_address,        ///< Extract address from a string.
                                ///< \param  out_ea    (ea_t *), out
                                ///< \param  screen_ea (ea_t)
                                ///< \param  string    (const char *)
                                ///< \param  position  (size_t)
                                ///< \retval  1 ok
                                ///< \retval  0 kernel should use the standard algorithm
                                ///< \retval -1 error

     ev_realcvt,                ///< Floating point -> IEEE conversion
                                ///< \param m    (void *)   pointer to data
                                ///< \param e    (uint16 *) internal IEEE format data
                                ///< \param swt  (uint16)   operation (see realcvt() in ieee.h)
                                ///< \return  0  not implemented
                                ///< \return  1  ok
                                ///< \return  \ref REAL_ERROR_ on error

     ev_gen_asm_or_lst,         ///< Callback: generating asm or lst file.
                                ///< The kernel calls this callback twice, at the beginning
                                ///< and at the end of listing generation. The processor
                                ///< module can intercept this event and adjust its output
                                ///< \param starting  (bool) beginning listing generation
                                ///< \param fp        (FILE *) output file
                                ///< \param is_asm    (bool) true:assembler, false:listing
                                ///< \param flags     (int) flags passed to gen_file()
                                ///< \param outline   (gen_outline_t **) ptr to ptr to outline callback.
                                ///<                  if this callback is defined for this code, it will be
                                ///<                  used by the kernel to output the generated lines
                                ///< \return void

     ev_gen_map_file,           ///<  Generate map file. If not implemented
                                ///< the kernel itself will create the map file.
                                ///< \param nlines (int *) number of lines in map file (-1 means write error)
                                ///< \param fp     (FILE *) output file
                                ///< \return  0  not implemented
                                ///< \return  1  ok
                                ///< \retval -1  write error

     ev_create_flat_group,      ///< Create special segment representing the flat group.
                                ///< \param image_base  (::ea_t)
                                ///< \param bitness     (int)
                                ///< \param dataseg_sel (::sel_t)
                                ///< return value is ignored

     ev_getreg,                 ///< IBM PC only internal request,
                                ///< should never be used for other purpose
                                ///< Get register value by internal index
                                ///< \param regval   (uval_t *), out
                                ///< \param regnum   (int)
                                ///< \return  1 ok
                                ///< \return  0 not implemented
                                ///< \return -1 failed (undefined value or bad regnum)

     ev_last_cb_before_debugger,///< START OF DEBUGGER CALLBACKS

     ev_next_exec_insn = 1000,  ///< Get next address to be executed
                                ///< This function must return the next address to be executed.
                                ///< If the instruction following the current one is executed, then it must return #BADADDR
                                ///< Usually the instructions to consider are: jumps, branches, calls, returns.
                                ///< This function is essential if the 'single step' is not supported in hardware.
                                ///< \param target     (::ea_t *), out: pointer to the answer
                                ///< \param ea         (::ea_t) instruction address
                                ///< \param tid        (int) current therad id
                                ///< \param getreg     (::processor_t::regval_getter_t *) function to get register values
                                ///< \param regvalues  (const ::regval_t *) register values array
                                ///< \retval 0 unimplemented
                                ///< \retval 1 implemented

     ev_calc_step_over,         ///< Calculate the address of the instruction which will be
                                ///< executed after "step over". The kernel will put a breakpoint there.
                                ///< If the step over is equal to step into or we can not calculate
                                ///< the address, return #BADADDR.
                                ///< \param target  (::ea_t *) pointer to the answer
                                ///< \param ip      (::ea_t) instruction address
                                ///< \retval 0 unimplemented
                                ///< \retval 1 implemented

     ev_calc_next_eas,          ///< Calculate list of addresses the instruction in 'insn'
                                ///< may pass control to.
                                ///< This callback is required for source level debugging.
                                ///< \param res       (::eavec_t *), out: array for the results.
                                ///< \param insn      (const ::insn_t*) the instruction
                                ///< \param over      (bool) calculate for step over (ignore call targets)
                                ///< \retval  <0 incalculable (indirect jumps, for example)
                                ///< \retval >=0 number of addresses of called functions in the array.
                                ///<             They must be put at the beginning of the array (0 if over=true)

     ev_get_macro_insn_head,    ///< Calculate the start of a macro instruction.
                                ///< This notification is called if IP points to the middle of an instruction
                                ///< \param head  (::ea_t *), out: answer, #BADADDR means normal instruction
                                ///< \param ip    (::ea_t) instruction address
                                ///< \retval 0 unimplemented
                                ///< \retval 1 implemented

     ev_get_dbr_opnum,          ///< Get the number of the operand to be displayed in the
                                ///< debugger reference view (text mode).
                                ///< \param opnum  (int *) operand number (out, -1 means no such operand)
                                ///< \param insn   (const ::insn_t*) the instruction
                                ///< \retval 0 unimplemented
                                ///< \retval 1 implemented

     ev_insn_reads_tbit,        ///< Check if insn will read the TF bit.
                                ///< \param insn       (const ::insn_t*) the instruction
                                ///< \param getreg     (::processor_t::regval_getter_t *) function to get register values
                                ///< \param regvalues  (const ::regval_t *) register values array
                                ///< \retval 2  yes, will generate 'step' exception
                                ///< \retval 1  yes, will store the TF bit in memory
                                ///< \retval 0  no

     ev_clean_tbit,             ///< Clear the TF bit after an insn like pushf stored it in memory.
                                ///< \param ea  (::ea_t) instruction address
                                ///< \param getreg     (::processor_t::regval_getter_t *) function to get register values
                                ///< \param regvalues  (const ::regval_t *) register values array
                                ///< \retval 1  ok
                                ///< \retval 0  failed

     ev_get_idd_opinfo,         ///< Get operand information.
                                ///< This callback is used to calculate the operand
                                ///< value for double clicking on it, hints, etc.
                                ///< \param opinf      (::idd_opinfo_t *) the output buffer
                                ///< \param ea         (::ea_t) instruction address
                                ///< \param n          (int) operand number
                                ///< \param thread_id  (int) current thread id
                                ///< \param getreg     (::processor_t::regval_getter_t *) function to get register values
                                ///< \param regvalues  (const ::regval_t *) register values array
                                ///< \return 1-ok, 0-failed

     ev_get_reg_info,           ///< Get register information by its name.
                                ///< example: "ah" returns:
                                ///<   - main_regname="eax"
                                ///<   - bitrange_t = { offset==8, nbits==8 }
                                ///<
                                ///< This callback may be unimplemented if the register
                                ///< names are all present in \ph{reg_names} and they all have
                                ///< the same size
                                ///< \param main_regname  (const char **), out
                                ///< \param bitrange      (::bitrange_t *), out: position and size of the value within 'main_regname' (empty bitrange == whole register)
                                ///< \param regname       (const char *)
                                ///< \retval  1  ok
                                ///< \retval -1  failed (not found)
                                ///< \retval  0  unimplemented

        // END OF DEBUGGER CALLBACKS

        // START OF TYPEINFO CALLBACKS TODO: get this into doxygen output
        // The codes below will be called only if #PR_TYPEINFO is set.
        // The codes ev_max_ptr_size, ev_get_default_enum_size MUST be implemented.
        // (other codes are optional but still require for normal
        // operation of the type system. without calc_arglocs,
        // for example, ida will not know about the argument
        // locations for function calls.

     ev_last_cb_before_type_callbacks,

     ev_setup_til = 2000,       ///< Setup default type libraries. (called after loading
                                ///< a new file into the database).
                                ///< The processor module may load tils, setup memory
                                ///< model and perform other actions required to set up
                                ///< the type system.
                                ///< This is an optional callback.
                                ///< \param none
                                ///< \return void

     ev_get_abi_info,           ///< Get all possible ABI names and optional extensions for given compiler
                                ///< abiname/option is a string entirely consisting of letters, digits and underscore
                                ///< \param abi_names (qstrvec_t *) - all possible ABis each in form abiname-opt1-opt2-...
                                ///< \param abi_opts  (qstrvec_t *) - array of all possible options in form "opt:description" or opt:hint-line#description
                                ///< \param comp      (comp_t) - compiler ID
                                ///< \retval 0 not implemented
                                ///< \retval 1 ok

     ev_max_ptr_size,           ///< Get maximal size of a pointer in bytes.
                                ///< \param none
                                ///< \return max possible size of a pointer

     ev_get_default_enum_size,  ///< Get default enum size.
                                ///< \param cm  (::cm_t)
                                ///< \returns sizeof(enum)

     ev_get_cc_regs,            ///< Get register allocation convention for given calling convention
                                ///< \param regs  (::callregs_t *), out
                                ///< \param cc    (::cm_t)
                                ///< \return 1
                                ///< \return 0 - not implemented

     ev_get_stkarg_offset,      ///< Get offset from SP to the first stack argument.
                                ///< For example: pc: 0, hppa: -0x34, ppc: 0x38
                                ///< \param none
                                ///< \returns the offset

     ev_shadow_args_size,       ///< Get size of shadow args in bytes.
                                ///< \param[out] shadow_args_size  (int *)
                                ///< \param pfn                    (::func_t *) (may be NULL)
                                ///< \return 1 if filled *shadow_args_size
                                ///< \return 0 - not implemented

     ev_get_simd_types,         ///< Get SIMD-related types according to given attributes ant/or argument location
                                ///< \param out (::simd_info_vec_t *)
                                ///< \param simd_attrs (const ::simd_info_t *), may be NULL
                                ///< \param argloc (const ::argloc_t *), may be NULL
                                ///< \param create_tifs (bool) return valid tinfo_t objects, create if neccessary
                                ///< \return number of found types, -1-error
                                ///< If name==NULL, initialize all SIMD types

     ev_calc_cdecl_purged_bytes,
                                ///< Calculate number of purged bytes after call.
                                ///< \param ea  (::ea_t) address of the call instruction
                                ///< \returns number of purged bytes (usually add sp, N)

     ev_calc_purged_bytes,      ///< Calculate number of purged bytes by the given function type.
                                ///< \param[out] p_purged_bytes  (int *) ptr to output
                                ///< \param fti                  (const ::func_type_data_t *) func type details
                                ///< \return 1
                                ///< \return 0 - not implemented

     ev_calc_retloc,            ///< Calculate return value location.
                                ///< \param[out] retloc  (::argloc_t *)
                                ///< \param rettype      (const tinfo_t *)
                                ///< \param cc           (::cm_t)
                                ///< \return  0  not implemented
                                ///< \return  1  ok,
                                ///< \return -1  error

     ev_calc_arglocs,           ///< Calculate function argument locations.
                                ///< This callback should fill retloc, all arglocs, and stkargs.
                                ///< This callback supersedes calc_argloc2.
                                ///< This callback is never called for ::CM_CC_SPECIAL functions.
                                ///< \param fti  (::func_type_data_t *) points to the func type info
                                ///< \retval  0  not implemented
                                ///< \retval  1  ok
                                ///< \retval -1  error

     ev_calc_varglocs,          ///< Calculate locations of the arguments that correspond to '...'.
                                ///< \param ftd      (::func_type_data_t *), inout: info about all arguments (including varargs)
                                ///< \param regs     (::regobjs_t *) buffer for register values
                                ///< \param stkargs  (::relobj_t *) stack arguments
                                ///< \param nfixed   (int) number of fixed arguments
                                ///< \retval  0  not implemented
                                ///< \retval  1  ok
                                ///< \retval -1  error

     ev_adjust_argloc,          ///< Adjust argloc according to its type/size
                                ///< and platform endianess
                                ///< \param argloc  (argloc_t *), inout
                                ///< \param type    (const tinfo_t *), may be NULL
                                ///<   NULL means primitive type of given size
                                ///< \param size    (int)
                                ///<   'size' makes no sense if type != NULL
                                ///<   (type->get_size() should be used instead)
                                ///< \retval  0  not implemented
                                ///< \retval  1  ok
                                ///< \retval -1  error

     ev_lower_func_type,        ///< Get function arguments which should be converted to pointers when lowering function prototype.
                                ///<  Processor module can also modify 'fti' in
                                ///< order to make a non-standard convertion for some of the arguments.
                                ///< \param argnums (intvec_t *), out - numbers of arguments to be converted to pointers in acsending order
                                ///< \param fti     (::func_type_data_t *), inout func type details
                                ///< (special values -1/-2 for return value - position of hidden 'retstr' argument: -1 - at the beginning, -2 - at the end)
                                ///< \retval 0 not implemented
                                ///< \retval 1 argnums was filled
                                ///< \retval 2 argnums was filled and made substantial changes to fti

     ev_equal_reglocs,          ///< Are 2 register arglocs the same?.
                                ///< We need this callback for the pc module.
                                ///< \param a1  (::argloc_t *)
                                ///< \param a2  (::argloc_t *)
                                ///< \retval  1  yes
                                ///< \retval -1  no
                                ///< \retval  0  not implemented

     ev_use_stkarg_type,        ///< Use information about a stack argument.
                                ///< \param ea  (::ea_t) address of the push instruction which
                                ///<                     pushes the function argument into the stack
                                ///< \param arg  (const ::funcarg_t *) argument info
                                ///< \retval 1   ok
                                ///< \retval <=0 failed, the kernel will create a comment with the
                                ///<             argument name or type for the instruction

     ev_use_regarg_type,        ///< Use information about register argument.
                                ///< \param[out] idx (int *) pointer to the returned value, may contain:
                                ///<                         - idx of the used argument, if the argument is defined
                                ///<                           in the current instruction, a comment will be applied by the kernel
                                ///<                         - idx | #REG_SPOIL - argument is spoiled by the instruction
                                ///<                         - -1 if the instruction doesn't change any registers
                                ///<                         - -2 if the instruction spoils all registers
                                ///< \param ea       (::ea_t) address of the instruction
                                ///< \param rargs    (const ::funcargvec_t *) vector of register arguments
                                ///<                               (including regs extracted from scattered arguments)
                                ///< \return 1
                                ///< \return 0  not implemented

     ev_use_arg_types,          ///< Use information about callee arguments.
                                ///< \param ea     (::ea_t) address of the call instruction
                                ///< \param fti    (::func_type_data_t *) info about function type
                                ///< \param rargs  (::funcargvec_t *) array of register arguments
                                ///< \return 1 (and removes handled arguments from fti and rargs)
                                ///< \return 0  not implemented

     ev_arg_addrs_ready,        ///< Argument address info is ready.
                                ///< \param caller  (::ea_t)
                                ///< \param n       (int) number of formal arguments
                                ///< \param tif     (tinfo_t *) call prototype
                                ///< \param addrs   (::ea_t *) argument intilization addresses
                                ///< \return <0: do not save into idb; other values mean "ok to save"

     ev_decorate_name,          ///< Decorate/undecorate a C symbol name.
                                ///< \param outbuf  (::qstring *) output buffer
                                ///< \param name    (const char *) name of symbol
                                ///< \param mangle  (bool) true-mangle, false-unmangle
                                ///< \param cc      (::cm_t) calling convention
                                ///< \param type    (const ::tinfo_t *) name type (NULL-unknown)
                                ///< \return 1 if success
                                ///< \return 0 not implemented or failed

        // END OF TYPEINFO CALLBACKS

     ev_loader=3000,            ///< This code and higher ones are reserved
                                ///< for the loaders.
                                ///< The arguments and the return values are
                                ///< defined by the loaders
  };

  /// Event notification handler
  hook_cb_t *_notify;
  ssize_t notify(event_t event_code, ...)
  {
    va_list va;
    va_start(va, event_code);
    ssize_t code = invoke_callbacks(HT_IDP, event_code, va);
    va_end(va);
    return code;
  }

  // Notification helpers, should be used instead of direct ph.notify(...) calls
  inline int init(const char *idp_modname);
  inline int term();
  inline int newprc(int pnum, bool keep_cfg);
  inline int newasm(int asmnum);
  inline int newfile(const char *fname);
  inline int oldfile(const char *fname);
  inline int newbinary(const char *filename, qoff64_t fileoff, ea_t basepara, ea_t binoff, uint64 nbytes);
  inline int endbinary(bool ok);
  inline int creating_segm(segment_t *seg);
  inline int assemble(uchar *_bin, ea_t ea, ea_t cs, ea_t ip, bool _use32, const char *line);
  inline int ana_insn(insn_t *out);
  inline int emu_insn(const insn_t &insn);
  inline int out_header(outctx_t &ctx);
  inline int out_footer(outctx_t &ctx);
  inline int out_segstart(outctx_t &ctx, segment_t *seg);
  inline int out_segend(outctx_t &ctx, segment_t *seg);
  inline int out_assumes(outctx_t &ctx);
  inline int out_insn(outctx_t &ctx);
  inline int out_mnem(outctx_t &ctx);
  inline int out_operand(outctx_t &ctx, const op_t &op);
  inline int out_data(outctx_t &ctx, bool analyze_only);
  inline int out_label(outctx_t &ctx, const char *colored_name);
  inline int out_special_item(outctx_t &ctx, uchar segtype);
  inline int gen_stkvar_def(outctx_t &ctx, const class member_t *mptr, sval_t v);
  inline int gen_regvar_def(outctx_t &ctx, regvar_t *v);
  inline int gen_src_file_lnnum(outctx_t &ctx, const char *file, size_t lnnum);
  inline int rename(ea_t ea, const char *new_name, int flags);
  inline int may_show_sreg(ea_t current_ea);
  inline int coagulate(ea_t start_ea);
  inline int auto_queue_empty(/*atype_t*/ int type);
  inline int func_bounds(int *possible_return_code, func_t *pfn, ea_t max_func_end_ea);
  inline int may_be_func(const insn_t &insn, int state);
  inline int is_sane_insn(const insn_t &insn, int no_crefs);
  inline int cmp_operands(const op_t &op1, const op_t &op2);
  inline int is_jump_func(func_t *pfn, ea_t *jump_target, ea_t *func_pointer);
  inline int is_basic_block_end(const insn_t &insn, bool call_insn_stops_block);
  inline int getreg(uval_t *rv, int regnum);
  inline int undefine(ea_t ea);
  inline int moving_segm(segment_t *seg, ea_t to, int flags);
  inline int is_sp_based(const insn_t &insn, const op_t &x);
  inline int is_far_jump(int icode);
  inline int is_call_insn(const insn_t &insn);
  inline int is_ret_insn(const insn_t &insn, bool strict);
  inline int is_align_insn(ea_t ea);
  inline int can_have_type(const op_t &op);
  inline int get_stkvar_scale_factor();
  inline int create_flat_group(ea_t image_base, int bitness, sel_t dataseg_sel);
  inline int is_alloca_probe(ea_t ea);
  inline int get_reg_name(qstring *buf, int reg, size_t width, int reghi);
  inline int gen_asm_or_lst(bool starting, FILE *fp, bool is_asm, int flags, /*gen_outline_t ** */ void *outline);
  inline int gen_map_file(int *nlines, FILE *fp);
  inline int get_autocmt(qstring *buf, const insn_t &insn);
  inline int is_insn_table_jump(const insn_t &insn);
  inline int loader_elf_machine(linput_t *li, int machine_type, const char **p_procname, proc_def_t **p_pd);
  inline int is_indirect_jump(const insn_t &insn);
  inline int verify_noreturn(func_t *pfn);
  inline int verify_sp(func_t *pfn);
  inline int create_func_frame(func_t *pfn);
  inline int get_frame_retsize(int *retsize, const func_t *pfn);
  inline int treat_hindering_item(ea_t hindering_item_ea, flags_t new_item_flags, ea_t new_item_ea, asize_t new_item_length);
  inline int extract_address(ea_t *out_ea, ea_t screen_ea, const char *string, size_t x);
  inline int str2reg(const char *regname);
  inline int is_switch(switch_info_t *si, const insn_t &insn);
  inline int create_switch_xrefs(ea_t jumpea, const switch_info_t &si);
  inline int calc_switch_cases(/*casevec_t * */void *casevec, eavec_t *targets, ea_t insn_ea, const switch_info_t &si);
  inline int get_bg_color(bgcolor_t *color, ea_t ea);
  inline int validate_flirt_func(ea_t start_ea, const char *funcname);
  inline int get_operand_string(qstring *buf, const insn_t &insn, int opnum);
  inline int add_cref(ea_t from, ea_t to, cref_t type);
  inline int add_dref(ea_t from, ea_t to, dref_t type);
  inline int del_cref(ea_t from, ea_t to, bool expand);
  inline int del_dref(ea_t from, ea_t to);
  inline int coagulate_dref(ea_t from, ea_t to, bool may_define, ea_t *code_ea);
  inline const char *set_idp_options(const char *keyword, int vtype, const void *value);
  inline int set_proc_options(const char *options, int confidence);
  inline int adjust_libfunc_ea(const idasgn_t &sig, const libfunc_t &libfun, ea_t *ea);
  inline int realcvt(void *m, unsigned short *e, unsigned short swt);
  inline int delay_slot_insn(ea_t *ea, bool *bexec, bool *fexec);
  inline int adjust_refinfo(refinfo_t *ri, ea_t ea, int n, const fixup_data_t &fd);
  inline int is_cond_insn(const insn_t &insn);
  inline int next_exec_insn(ea_t *target, ea_t ea, int tid, regval_getter_t *_getreg, const regval_t &regvalues);
  inline int calc_step_over(ea_t *target, ea_t ip);
  inline int get_macro_insn_head(ea_t *head, ea_t ip);
  inline int get_dbr_opnum(int *opnum, const insn_t &insn);
  inline int insn_reads_tbit(const insn_t &insn, regval_getter_t *_getreg, const regval_t &regvalues);
  inline int get_idd_opinfo(idd_opinfo_t *opinf, ea_t ea, int n, int thread_id, regval_getter_t *_getreg, const regval_t &regvalues);
  inline int calc_next_eas(eavec_t *res, const insn_t &insn, bool over);
  inline int clean_tbit(ea_t ea, regval_getter_t *_getreg, const regval_t &regvalues);
  inline int get_reg_info(const char **main_regname, bitrange_t *bitrange, const char *regname);
  inline int setup_til();
  inline int max_ptr_size();
  inline int get_default_enum_size(cm_t cm);
  inline int calc_cdecl_purged_bytes(ea_t ea);
  inline int get_stkarg_offset();
  inline int equal_reglocs(const argloc_t &a1, const argloc_t &a2);
  inline int decorate_name(qstring *outbuf, const char *name, bool mangle, cm_t cc, const tinfo_t &type);
  inline int calc_retloc(argloc_t *retloc, const tinfo_t &rettype, cm_t cc);
  inline int calc_varglocs(func_type_data_t *ftd, regobjs_t *regs, relobj_t *stkargs, int nfixed);
  inline int calc_arglocs(func_type_data_t *fti);
  inline int use_stkarg_type(ea_t ea, const funcarg_t &arg);
  inline int use_regarg_type(int *idx, ea_t ea, /*const funcargvec_t * */void *rargs);
  inline int use_arg_types(ea_t ea, func_type_data_t *fti, /*funcargvec_t * */void *rargs);
  inline int calc_purged_bytes(int *p_purged_bytes, const func_type_data_t &fti);
  inline int shadow_args_size(int *shadow_size, func_t *pfn);
  inline int get_cc_regs(callregs_t *regs, cm_t cc);
  inline int get_simd_types(/*simd_info_vec_t * */void *out, const simd_info_t *simd_attrs, const argloc_t *argloc, bool create_tifs);
  inline int arg_addrs_ready(ea_t caller, int n, const tinfo_t &tif, ea_t *addrs);
  inline int adjust_argloc(argloc_t *argloc, const tinfo_t *type, int size);
  inline int lower_func_type(intvec_t *argnums, func_type_data_t *fti);
  inline int get_abi_info(qstrvec_t *abi_names, qstrvec_t *abi_opts, comp_t comp);
/// \defgroup OP_FP_SP SP/FP operand flags
/// Return values for processor_t::is_sp_based()
//@{
#define OP_FP_BASED  0x00000000 ///< operand is FP based
#define OP_SP_BASED  0x00000001 ///< operand is SP based
#define OP_SP_ADD    0x00000000 ///< operand value is added to the pointer
#define OP_SP_SUB    0x00000002 ///< operand value is subtracted from the pointer
//@}

  /// Get the stack variable scaling factor.
  /// Useful for processors who refer to the stack with implicit scaling factor.
  /// TMS320C55 for example: SP(#1) really refers to (SP+2)
  int get_stkvar_scale(void)
    {
      if ( (flag & PR_SCALE_STKVARS) == 0 )
        return 1;
      int scale = notify(ev_get_stkvar_scale_factor);
      if ( scale == 0 )
        error("Request ph.get_stkvar_scale_factor should be implemented");
      else if ( scale <= 0 )
        error("Invalid return code from ph.get_stkvar_scale_factor request");
      return scale;
    }

  //  Processor register information:
  const char *const *reg_names;         ///< array of register names
  int32 regs_num;                       ///< number of registers

  /// \name Segment registers
  /// Segment register information (use virtual CS and DS registers if your
  /// processor doesn't have segment registers):
  //@{
  int32 reg_first_sreg;                 ///< number of first segment register
  int32 reg_last_sreg;                  ///< number of last segment register
  int32 segreg_size;                    ///< size of a segment register in bytes
  //@}

  /// \name Virtual segment registers
  /// If your processor doesn't have segment registers,
  /// you should define 2 virtual segment registers for CS and DS.
  /// Let's call them rVcs and rVds.
  //@{
  int32 reg_code_sreg;                  ///< number of CS register
  int32 reg_data_sreg;                  ///< number of DS register
  //@}


  /// \name Empirics
  //@{
  const bytes_t *codestart;             ///< Array of typical code start sequences.
                                        ///< This array is used when a new file
                                        ///< is loaded to find the beginnings of code
                                        ///< sequences.
                                        ///< This array is terminated with
                                        ///< a zero length item.
  const bytes_t *retcodes;              ///< Array of 'return' instruction opcodes.
                                        ///< This array is used to determine
                                        ///< form of autogenerated locret_...
                                        ///< labels.
                                        ///< The last item of it should be { 0, NULL }
                                        ///< This array may be NULL
                                        ///< Better way of handling return instructions
                                        ///< is to define the \idpcode{is_ret_insn} callback in
                                        ///< the notify() function
  //@}

  /// \name Instruction set
  //@{
  int32 instruc_start;                  ///< icode of the first instruction
  int32 instruc_end;                    ///< icode of the last instruction + 1

  /// Does the given value specify a valid instruction for this instruction set?.
  /// See #instruc_start and #instruc_end
  bool is_canon_insn(uint16 itype) const { return itype >= instruc_start && itype < instruc_end; }

  const instruc_t *instruc;             ///< Array of instructions
  //@}

  /// Size of long double (tbyte) for this processor
  /// (meaningful only if \ash{a_tbyte} != NULL)
  size_t tbyte_size;

  /// Number of digits in floating numbers after the decimal point.
  /// If an element of this array equals 0, then the corresponding
  /// floating point data is not used for the processor.
  /// This array is used to align numbers in the output.
  /// - real_width[0] - number of digits for short floats (only PDP-11 has them)
  /// - real_width[1] - number of digits for "float"
  /// - real_width[2] - number of digits for "double"
  /// - real_width[3] - number of digits for "long double"
  ///
  /// Example: IBM PC module has { 0,7,15,19 }
  char real_width[4];

  /// Icode of return instruction. It is ok to give any of possible return instructions
  int32 icode_return;

  /// Reserved, currently equals to NULL
  void *unused_slot;
};

#ifdef __X64__
CASSERT(sizeof(processor_t) == 144);
#else
CASSERT(sizeof(processor_t) == 104);
#endif


// The following two structures contain information about the current
// processor and assembler.

idaman processor_t ida_export_data ph;   ///< current processor
idaman asm_t ida_export_data ash;        ///< current assembler


inline int processor_t::init(const char *idp_modname)
{
  return notify(ev_init, idp_modname);
}
inline int processor_t::term()
{
  return notify(ev_term);
}
inline int processor_t::newprc(int pnum, bool keep_cfg)
{
  return notify(ev_newprc, pnum, keep_cfg);
}
inline int processor_t::newasm(int asmnum)
{
  return notify(ev_newasm, asmnum);
}
inline int processor_t::newfile(const char *fname)
{
  return notify(ev_newfile, fname);
}
inline int processor_t::oldfile(const char *fname)
{
  return notify(ev_oldfile, fname);
}
inline int processor_t::newbinary(const char *filename, qoff64_t fileoff, ea_t basepara, ea_t binoff, uint64 nbytes)
{
  return notify(ev_newbinary, filename, fileoff, basepara, binoff, nbytes);
}
inline int processor_t::endbinary(bool ok)
{
  return notify(ev_endbinary, ok);
}
inline int processor_t::creating_segm(segment_t *seg)
{
  return notify(ev_creating_segm, seg);
}
inline int processor_t::assemble(uchar *_bin, ea_t ea, ea_t cs, ea_t ip, bool _use32, const char *line)
{
  return notify(ev_assemble, _bin, ea, cs, ip, _use32, line, _bin);
}
inline int processor_t::ana_insn(insn_t *out)
{
  return notify(ev_ana_insn, out);
}
inline int processor_t::emu_insn(const insn_t &insn)
{
  return notify(ev_emu_insn, &insn);
}
inline int processor_t::out_header(outctx_t &ctx)
{
  return notify(ev_out_header, &ctx);
}
inline int processor_t::out_footer(outctx_t &ctx)
{
  return notify(ev_out_footer, &ctx);
}
inline int processor_t::out_segstart(outctx_t &ctx, segment_t *seg)
{
  return notify(ev_out_segstart, &ctx, seg);
}
inline int processor_t::out_segend(outctx_t &ctx, segment_t *seg)
{
  return notify(ev_out_segend, &ctx, seg);
}
inline int processor_t::out_assumes(outctx_t &ctx)
{
  return notify(ev_out_assumes, &ctx);
}
inline int processor_t::out_insn(outctx_t &ctx)
{
  return notify(ev_out_insn, &ctx);
}
inline int processor_t::out_mnem(outctx_t &ctx)
{
  return notify(ev_out_mnem, &ctx);
}
inline int processor_t::out_operand(outctx_t &ctx, const op_t &op)
{
  return notify(ev_out_operand, &ctx, &op);
}
inline int processor_t::out_data(outctx_t &ctx, bool analyze_only)
{
  return notify(ev_out_data, &ctx, analyze_only);
}
inline int processor_t::out_label(outctx_t &ctx, const char *colored_name)
{
  return notify(ev_out_label, &ctx, colored_name);
}
inline int processor_t::out_special_item(outctx_t &ctx, uchar segtype)
{
  return notify(ev_out_special_item, &ctx, segtype);
}
inline int processor_t::gen_stkvar_def(outctx_t &ctx, const class member_t *mptr, sval_t v)
{
  return notify(ev_gen_stkvar_def, &ctx, mptr, v);
}
inline int processor_t::gen_regvar_def(outctx_t &ctx, regvar_t *v)
{
  return notify(ev_gen_regvar_def, &ctx, v);
}
inline int processor_t::gen_src_file_lnnum(outctx_t &ctx, const char *file, size_t lnnum)
{
  return notify(ev_gen_src_file_lnnum, &ctx, file, lnnum);
}
inline int processor_t::rename(ea_t ea, const char *new_name, int flags)
{
  return notify(ev_rename, ea, new_name, flags);
}
inline int processor_t::may_show_sreg(ea_t current_ea)
{
  return notify(ev_may_show_sreg, current_ea);
}
inline int processor_t::coagulate(ea_t start_ea)
{
  return notify(ev_coagulate, start_ea);
}
inline int processor_t::auto_queue_empty(/*atype_t*/ int type)
{
  return notify(ev_auto_queue_empty, type);
}
inline int processor_t::func_bounds(int *possible_return_code, func_t *pfn, ea_t max_func_end_ea)
{
  return notify(ev_func_bounds, possible_return_code, pfn, max_func_end_ea);
}
inline int processor_t::may_be_func(const insn_t &insn, int state)
{
  return notify(ev_may_be_func, &insn, state);
}
inline int processor_t::is_sane_insn(const insn_t &insn, int no_crefs)
{
  return notify(ev_is_sane_insn, &insn, no_crefs);
}
inline int processor_t::cmp_operands(const op_t &op1, const op_t &op2)
{
  return notify(ev_cmp_operands, &op1, &op2);
}
inline int processor_t::is_jump_func(func_t *pfn, ea_t *jump_target, ea_t *func_pointer)
{
  return notify(ev_is_jump_func, pfn, jump_target, func_pointer);
}
inline int processor_t::is_basic_block_end(const insn_t &insn, bool call_insn_stops_block)
{
  return notify(ev_is_basic_block_end, &insn, call_insn_stops_block);
}
inline int processor_t::getreg(uval_t *rv, int regnum)
{
  return notify(ph.ev_getreg, rv, regnum);
}
inline int processor_t::undefine(ea_t ea)
{
  return notify(ev_undefine, ea);
}
inline int processor_t::moving_segm(segment_t *seg, ea_t to, int flags)
{
  return notify(ev_moving_segm, seg, to, flags);
}
inline int processor_t::is_sp_based(const insn_t &insn, const op_t &x)
{
  int mode;
  int code = notify(ev_is_sp_based, &mode, &insn, &x);
  return code == 0 ? OP_SP_BASED : mode;
}
inline int processor_t::is_far_jump(int icode)
{
  return notify(ev_is_far_jump, icode);
}
inline int processor_t::is_call_insn(const insn_t &insn)
{
  return notify(ev_is_call_insn, &insn);
}
inline int processor_t::is_ret_insn(const insn_t &insn, bool strict)
{
  return notify(ev_is_ret_insn, &insn, strict);
}
inline int processor_t::is_align_insn(ea_t ea)
{
  return notify(ev_is_align_insn, ea);
}
inline int processor_t::can_have_type(const op_t &op)
{
  return notify(ev_can_have_type, &op);
}
inline int processor_t::get_stkvar_scale_factor()
{
  return notify(ev_get_stkvar_scale_factor);
}
inline int processor_t::create_flat_group(ea_t image_base, int bitness, sel_t dataseg_sel)
{
  return notify(ev_create_flat_group, image_base, bitness, dataseg_sel);
}
inline int processor_t::is_alloca_probe(ea_t ea)
{
  return notify(ev_is_alloca_probe, ea);
}
inline int processor_t::get_reg_name(qstring *buf, int reg, size_t width, int reghi)
{
  return notify(ev_get_reg_name, buf, reg, width, reghi);
}
inline int processor_t::gen_asm_or_lst(bool starting, FILE *fp, bool is_asm, int flags, /*gen_outline_t ** */ void *outline)
{
  return notify(ev_gen_asm_or_lst, starting, fp, is_asm, flags, outline);
}
inline int processor_t::gen_map_file(int *nlines, FILE *fp)
{
  return notify(ev_gen_map_file, nlines, fp);
}
inline int processor_t::get_autocmt(qstring *buf, const insn_t &insn)
{
  return notify(ev_get_autocmt, buf, &insn);
}
inline int processor_t::is_insn_table_jump(const insn_t &insn)
{
  return notify(ev_is_insn_table_jump, &insn);
}
inline int processor_t::loader_elf_machine(linput_t *li, int machine_type, const char **p_procname, proc_def_t **p_pd)
{
  return notify(ev_loader_elf_machine, li, machine_type, p_procname, p_pd);
}
inline int processor_t::is_indirect_jump(const insn_t &insn)
{
  return notify(ev_is_indirect_jump, &insn);
}
inline int processor_t::verify_noreturn(func_t *pfn)
{
  return notify(ev_verify_noreturn, pfn);
}
inline int processor_t::verify_sp(func_t *pfn)
{
  return notify(ev_verify_sp, pfn);
}
inline int processor_t::create_func_frame(func_t *pfn)
{
  return notify(ev_create_func_frame, pfn);
}
inline int processor_t::get_frame_retsize(int *retsize, const func_t *pfn)
{
  return notify(ev_get_frame_retsize, retsize, pfn);
}
inline int processor_t::treat_hindering_item(ea_t hindering_item_ea, flags_t new_item_flags, ea_t new_item_ea, asize_t new_item_length)
{
  return notify(ev_treat_hindering_item, hindering_item_ea, new_item_flags, new_item_ea, new_item_length);
}
inline int processor_t::extract_address(ea_t *out_ea, ea_t screen_ea, const char *string, size_t x)
{
  return notify(ev_extract_address, out_ea, screen_ea, string, x);
}
inline int processor_t::str2reg(const char *regname)
{
  return notify(ev_str2reg, regname);
}
inline int processor_t::is_switch(switch_info_t *si, const insn_t &insn)
{
  return notify(ev_is_switch, si, &insn);
}
inline int processor_t::create_switch_xrefs(ea_t jumpea, const switch_info_t &si)
{
  return notify(ev_create_switch_xrefs, jumpea, &si);
}
inline int processor_t::calc_switch_cases(/*casevec_t * */void *casevec, eavec_t *targets, ea_t insn_ea, const switch_info_t &si)
{
  return notify(ev_calc_switch_cases, casevec, targets, insn_ea, &si);
}
inline int processor_t::get_bg_color(bgcolor_t *color, ea_t ea)
{
  return notify(ev_get_bg_color, color, ea);
}
inline int processor_t::validate_flirt_func(ea_t start_ea, const char *funcname)
{
  return notify(ev_validate_flirt_func, start_ea, funcname);
}
inline int processor_t::get_operand_string(qstring *buf, const insn_t &insn, int opnum)
{
  return notify(ev_get_operand_string, buf, &insn, opnum);
}
inline int processor_t::add_cref(ea_t from, ea_t to, cref_t type)
{
  return notify(ev_add_cref, from, to, type);
}
inline int processor_t::add_dref(ea_t from, ea_t to, dref_t type)
{
  return notify(ev_add_dref, from, to, type);
}
inline int processor_t::del_cref(ea_t from, ea_t to, bool expand)
{
  return notify(ev_del_cref, from, to, expand);
}
inline int processor_t::del_dref(ea_t from, ea_t to)
{
  return notify(ev_del_dref, from, to);
}
inline int processor_t::coagulate_dref(ea_t from, ea_t to, bool may_define, ea_t *code_ea)
{
  return notify(ev_coagulate_dref, from, to, may_define, code_ea);
}
inline const char *processor_t::set_idp_options(const char *keyword, int vtype, const void *value)
{
  const char *errmsg;
  int code = notify(ev_set_idp_options, keyword, vtype, value, &errmsg);
  return code == 1 ? IDPOPT_OK : code == 0 ? IDPOPT_BADKEY : errmsg;
}
inline int processor_t::set_proc_options(const char *options, int confidence)
{
  return notify(ev_set_proc_options, options, confidence);
}
inline int processor_t::adjust_libfunc_ea(const idasgn_t &sig, const libfunc_t &libfun, ea_t *ea)
{
  return notify(ev_adjust_libfunc_ea, &sig, &libfun, ea);
}
inline int processor_t::realcvt(void *m, unsigned short *e, unsigned short swt)
{
  return notify(ev_realcvt, m, e, swt);
}
inline int processor_t::delay_slot_insn(ea_t *ea, bool *bexec, bool *fexec)
{
  return notify(ev_delay_slot_insn, ea, bexec, fexec);
}
inline int processor_t::adjust_refinfo(refinfo_t *ri, ea_t ea, int n, const fixup_data_t &fd)
{
  return notify(ev_adjust_refinfo, ri, ea, n, &fd);
}
inline int processor_t::is_cond_insn(const insn_t &insn)
{
  return notify(ev_is_cond_insn, &insn);
}
inline int processor_t::next_exec_insn(ea_t *target, ea_t ea, int tid, regval_getter_t *_getreg, const regval_t &regvalues)
{
  return notify(ev_next_exec_insn, target, ea, tid, _getreg, &regvalues);
}
inline int processor_t::calc_step_over(ea_t *target, ea_t ip)
{
  return notify(ev_calc_step_over, target, ip);
}
inline int processor_t::get_macro_insn_head(ea_t *head, ea_t ip)
{
  return notify(ev_get_macro_insn_head, head, ip);
}
inline int processor_t::get_dbr_opnum(int *opnum, const insn_t &insn)
{
  return notify(ev_get_dbr_opnum, opnum, &insn);
}
inline int processor_t::insn_reads_tbit(const insn_t &insn, regval_getter_t *_getreg, const regval_t &regvalues)
{
  return notify(ev_insn_reads_tbit, &insn, _getreg, &regvalues);
}
inline int processor_t::get_idd_opinfo(idd_opinfo_t *opinf, ea_t ea, int n, int thread_id, regval_getter_t *_getreg, const regval_t &regvalues)
{
  return notify(ev_get_idd_opinfo, opinf, ea, n, thread_id, _getreg, &regvalues);
}
inline int processor_t::calc_next_eas(eavec_t *res, const insn_t &insn, bool over)
{
  return notify(ev_calc_next_eas, res, &insn, over);
}
inline int processor_t::clean_tbit(ea_t ea, regval_getter_t *_getreg, const regval_t &regvalues)
{
  return notify(ev_clean_tbit, ea, _getreg, &regvalues);
}
inline int processor_t::get_reg_info(const char **main_regname, bitrange_t *bitrange, const char *regname)
{
  return notify(ev_get_reg_info, main_regname, bitrange, regname);
}
inline int processor_t::setup_til()
{
  return notify(ev_setup_til);
}
inline int processor_t::max_ptr_size()
{
  return notify(ev_max_ptr_size);
}
inline int processor_t::get_default_enum_size(cm_t cm)
{
  return ti() ? notify(ev_get_default_enum_size, cm) : -1;
}
inline int processor_t::calc_cdecl_purged_bytes(ea_t ea)
{
  return notify(ev_calc_cdecl_purged_bytes, ea);
}
inline int processor_t::get_stkarg_offset()
{
  return ti() ? notify(ev_get_stkarg_offset) : 0;
}
inline int processor_t::equal_reglocs(const argloc_t &a1, const argloc_t &a2)
{
  return notify(ev_equal_reglocs, &a1, &a2);
}
inline int processor_t::decorate_name(qstring *outbuf, const char *name, bool mangle, cm_t cc, const tinfo_t &type)
{
  return notify(ev_decorate_name, outbuf, name, mangle, cc, &type);
}
inline int processor_t::calc_retloc(argloc_t *retloc, const tinfo_t &rettype, cm_t cc)
{
  return notify(ev_calc_retloc, retloc, &rettype, cc);
}
inline int processor_t::calc_varglocs(func_type_data_t *ftd, regobjs_t *regs, relobj_t *stkargs, int nfixed)
{
  return notify(ev_calc_varglocs, ftd, regs, stkargs, nfixed);
}
inline int processor_t::calc_arglocs(func_type_data_t *fti)
{
  return notify(ev_calc_arglocs, fti);
}
inline int processor_t::use_stkarg_type(ea_t ea, const funcarg_t &arg)
{
  return notify(ev_use_stkarg_type, ea, &arg);
}
inline int processor_t::use_regarg_type(int *idx, ea_t ea, /*const funcargvec_t * */void *rargs)
{
  return notify(ev_use_regarg_type, idx, ea, rargs);
}
inline int processor_t::use_arg_types(ea_t ea, func_type_data_t *fti, /*funcargvec_t * */void *rargs)
{
  return notify(ev_use_arg_types, ea, fti, rargs);
}
inline int processor_t::calc_purged_bytes(int *p_purged_bytes, const func_type_data_t &fti)
{
  return notify(ev_calc_purged_bytes, p_purged_bytes, &fti);
}
inline int processor_t::shadow_args_size(int *shadow_size, func_t *pfn)
{
  return notify(ev_shadow_args_size, shadow_size, pfn);
}
inline int processor_t::get_cc_regs(callregs_t *regs, cm_t cc)
{
  return notify(ev_get_cc_regs, regs, cc);
}
inline int processor_t::get_simd_types(/*simd_info_vec_t * */void *out, const simd_info_t *simd_attrs, const argloc_t *argloc, bool create_tifs)
{
  return notify(ev_get_simd_types, out, simd_attrs, argloc, create_tifs);
}
inline int processor_t::arg_addrs_ready(ea_t caller, int n, const tinfo_t &tif, ea_t *addrs)
{
  return notify(ev_arg_addrs_ready, caller, n, &tif, addrs);
}
inline int processor_t::adjust_argloc(argloc_t *argloc, const tinfo_t *type, int size)
{
  return notify(ev_adjust_argloc, argloc, type, size);
}
inline int processor_t::lower_func_type(intvec_t *argnums, func_type_data_t *fti)
{
  return notify(ev_lower_func_type, argnums, fti);
}
inline int processor_t::get_abi_info(qstrvec_t *abi_names, qstrvec_t *abi_opts, comp_t comp)
{
  return notify(ev_get_abi_info, abi_names, abi_opts, comp);
}


idaman int ida_export str2reg(const char *p);     ///< Get any reg number (-1 on error)


/// If the instruction at 'ea' looks like an alignment instruction,
/// return its length in bytes. Otherwise return 0.

idaman int ida_export is_align_insn(ea_t ea);


/// Get text representation of a register.
/// For most processors this function will just return \ph{reg_names}[reg].
/// If the processor module has implemented processor_t::get_reg_name, it will be
/// used instead
/// \param buf      output buffer
/// \param reg      internal register number as defined in the processor module
/// \param width    register width in bytes
/// \param reghi    if specified, then this function will return the register pair
/// \return length of register name in bytes or -1 if failure

idaman ssize_t ida_export get_reg_name(qstring *buf, int reg, size_t width, int reghi = -1);


/// Get register information - useful for registers like al, ah, dil, etc.
/// \return NULL no such register

inline const char *get_reg_info(const char *regname, bitrange_t *bitrange)
{
  const char *r2;
  int code = ph.notify(ph.ev_get_reg_info, &r2, bitrange, regname);
  if ( code == 0 )  // not implemented?
  {
    if ( str2reg(regname) != -1 )
    {
      if ( bitrange != NULL )
        bitrange->reset();
      return regname;
    }
    return NULL;
  }
  return code == 1 ? r2 : NULL;
}

/// Get register number and size from register name
struct reg_info_t
{
  int reg;              ///< register number
  int size;             ///< register size
  DECLARE_COMPARISONS(reg_info_t)
  {
    if ( reg != r.reg )
      return reg > r.reg ? 1 : -1;
    if ( size != r.size )
      return size > r.size ? 1 : -1;
    return 0;
  }
};
DECLARE_TYPE_AS_MOVABLE(reg_info_t);
typedef qvector<reg_info_t> reginfovec_t; ///< vector of register info objects


/// Get register info by name.
/// \param[out] ri  result
/// \param regname  name of register
/// \return success

idaman bool ida_export parse_reg_name(reg_info_t *ri, const char *regname);


inline bool insn_t::is_canon_insn(void) const // see ::insn_t in ua.hpp
{
  return ph.is_canon_insn(itype);
}

inline const char *insn_t::get_canon_mnem(void) const // see ::insn_t in ua.hpp
{
  return is_canon_insn() ? ph.instruc[itype-ph.instruc_start].name : NULL;
}

inline uint32 insn_t::get_canon_feature(void) const // ::insn_t in ua.hpp
{
  return is_canon_insn() ? ph.instruc[itype-ph.instruc_start].feature : 0;
}


/// Get size of long double

inline size_t sizeof_ldbl(void)
{
  return inf.cc.size_ldbl ? inf.cc.size_ldbl : ph.tbyte_size;
}

/// Flags passed as 'level' parameter to set_processor_type()
enum setproc_level_t
{
  SETPROC_IDB = 0,    ///< set processor type for old idb
  SETPROC_LOADER = 1, ///< set processor type for new idb;
                      ///< if the user has specified a compatible processor,
                      ///< return success without changing it.
                      ///< if failure, call loader_failure()
  SETPROC_LOADER_NON_FATAL = 2, ///< the same as SETPROC_LOADER but non-fatal failures.
  SETPROC_USER = 3,   ///< set user-specified processor
                      ///< used for -p and manual processor change at later time
};

/// Set target processor type.
/// Once a processor module is loaded, it can not be replaced until we close the idb.
/// \param procname  name of processor type (one of names present in \ph{psnames})
/// \param level     \ref SETPROC_
/// \return success

idaman bool ida_export set_processor_type(
        const char *procname,
        setproc_level_t level);


/// Get name of the current processor module.
/// The name is derived from the file name.
/// For example, for IBM PC the module is named "pc.w32" (windows version),
/// then the module name is "PC" (uppercase).
/// If no processor module is loaded, this function will return NULL
/// \param buf          the output buffer, should be at least #QMAXFILE length
/// \param bufsize      size of output buffer

idaman char *ida_export get_idp_name(char *buf, size_t bufsize);


/// Set target assembler.
/// \param asmnum  number of assembler in the current processor module
/// \return success

idaman bool ida_export set_target_assembler(int asmnum);


/// Helper function to get the delay slot instruction
inline bool delay_slot_insn(ea_t *ea, bool *bexec, bool *fexec)
{
  bool ok = (ph.flag & PR_DELAYED) != 0;
  if ( ok )
  {
    bool be = true;
    bool fe = true;
    ok = ph.delay_slot_insn(ea, &be, &fe) == 1;
    if ( ok )
    {
      if ( bexec != NULL )
        *bexec = be;
      if ( fexec != NULL )
        *fexec = fe;
    }
  }
  return ok;
}

/// IDB event group. Some events are still in the processor group, so you will
/// need to hook to both groups. These events do not return anything.
///
/// The callback function should return 0 but the kernel won't check it.
/// Use the hook_to_notification_point() function to install your callback.
namespace idb_event
{
  //<hookgen IDB>

  /// IDB event codes
  enum event_code_t
  {
    closebase,              ///< The database will be closed now

    savebase,               ///< The database is being saved

    upgraded,               ///< The database has been upgraded
                            ///< and the receiver can upgrade its info as well
                            ///< \param from (int) - old IDB version

    auto_empty,             ///< Info: all analysis queues are empty.
                            ///< This callback is called once when the
                            ///< initial analysis is finished. If the queue is
                            ///< not empty upon the return from this callback,
                            ///< it will be called later again.

    auto_empty_finally,     ///< Info: all analysis queues are empty definitively.
                            ///< This callback is called only once.

    determined_main,        ///< The main() function has been determined.
                            ///< \param main (::ea_t) address of the main() function
    local_types_changed,    ///< Local types have been changed

    extlang_changed,        ///< The list of extlangs or the default extlang was changed.
                            ///< \param kind  (int)
                            ///<          0: extlang installed
                            ///<          1: extlang removed
                            ///<          2: default extlang changed
                            ///< \param el (::extlang_t *) pointer to the extlang affected
                            ///< \param idx (int) extlang index

    idasgn_loaded,          ///< FLIRT signature has been loaded
                            ///< for normal processing (not for
                            ///< recognition of startup sequences).
                            ///< \param short_sig_name  (const char *)

    kernel_config_loaded,   ///< This event is issued when ida.cfg is parsed.
                            ///< \param none

    loader_finished,        ///< External file loader finished its work.
                            ///< Use this event to augment the existing loader functionality.
                            ///< \param li            (linput_t *)
                            ///< \param neflags       (::uint16) \ref NEF_
                            ///< \param filetypename  (const char *)

    flow_chart_created,     ///< Gui has retrieved a function flow chart.
                            ///< Plugins may modify the flow chart in this callback.
                            ///< \param fc  (qflow_chart_t *)

    compiler_changed,       ///< The kernel has changed the compiler information.
                            ///< (\inf{cc} structure; \ref get_abi_name)

    changing_ti,            ///< An item typestring (c/c++ prototype) is to be changed.
                            ///< \param ea          (::ea_t)
                            ///< \param new_type    (const ::type_t *)
                            ///< \param new_fnames  (const ::p_list *)

    ti_changed,             ///< An item typestring (c/c++ prototype) has been changed.
                            ///< \param ea      (::ea_t)
                            ///< \param type    (const ::type_t *)
                            ///< \param fnames  (const ::p_list *)

    changing_op_ti,         ///< An operand typestring (c/c++ prototype) is to be changed.
                            ///< \param ea          (::ea_t)
                            ///< \param n           (int)
                            ///< \param new_type    (const ::type_t *)
                            ///< \param new_fnames  (const ::p_list *)
    op_ti_changed,          ///< An operand typestring (c/c++ prototype) has been changed.
                            ///< \param ea (::ea_t)
                            ///< \param n  (int)
                            ///< \param type (const ::type_t *)
                            ///< \param fnames (const ::p_list *)

    changing_op_type,       ///< An operand type (offset, hex, etc...) is to be changed.
                            ///< \param ea  (::ea_t)
                            ///< \param n   (int) eventually or'ed with OPND_OUTER
                            ///< \param opinfo (const opinfo_t *) additional operand info
    op_type_changed,        ///< An operand type (offset, hex, etc...) has been set or deleted.
                            ///< \param ea  (::ea_t)
                            ///< \param n   (int) eventually or'ed with OPND_OUTER

    enum_created,           ///< An enum type has been created.
                            ///< \param id  (::enum_t)

    deleting_enum,          ///< An enum type is to be deleted.
                            ///< \param id  (::enum_t)
    enum_deleted,           ///< An enum type has been deleted.
                            ///< \param id  (::enum_t)

    renaming_enum,          ///< An enum or enum member is to be renamed.
                            ///< \param id       (::tid_t)
                            ///< \param is_enum  (bool)
                            ///< \param newname  (const char *)
    enum_renamed,           ///< An enum or member has been renamed.
                            ///< \param id  (::tid_t)

    changing_enum_bf,       ///< An enum type 'bitfield' attribute is to be changed.
                            ///< \param id      (::enum_t)
                            ///< \param new_bf  (bool)
    enum_bf_changed,        ///< An enum type 'bitfield' attribute has been changed.
                            ///< \param id  (::enum_t)

    changing_enum_cmt,      ///< An enum or member type comment is to be changed.
                            ///< \param id          (::tid_t)
                            ///< \param repeatable  (bool)
                            ///< \param newcmt      (const char *)
    enum_cmt_changed,       ///< An enum or member type comment has been changed.
                            ///< \param id          (::tid_t)
                            ///< \param repeatable  (bool)

    enum_member_created,    ///< An enum member has been created.
                            ///< \param id   (::enum_t)
                            ///< \param cid  (::const_t)

    deleting_enum_member,   ///< An enum member is to be deleted.
                            ///< \param id   (::enum_t)
                            ///< \param cid  (::const_t)
    enum_member_deleted,    ///< An enum member has been deleted.
                            ///< \param id   (::enum_t)
                            ///< \param cid  (::const_t)

    struc_created,          ///< A new structure type has been created.
                            ///< \param struc_id  (::tid_t)

    deleting_struc,         ///< A structure type is to be deleted.
                            ///< \param sptr  (::struc_t *)
    struc_deleted,          ///< A structure type has been deleted.
                            ///< \param struc_id  (::tid_t)

    changing_struc_align,   ///< A structure type is being changed (the struct alignment).
                            ///< \param sptr  (::struc_t *)
    struc_align_changed,    ///< A structure type has been changed (the struct alignment).
                            ///< \param sptr  (::struc_t *)

    renaming_struc,         ///< A structure type is to be renamed.
                            ///< \param id       (::tid_t)
                            ///< \param oldname  (const char *)
                            ///< \param newname  (const char *)
    struc_renamed,          ///< A structure type has been renamed.
                            ///< \param sptr (::struc_t *)

    expanding_struc,        ///< A structure type is to be expanded/shrunk.
                            ///< \param sptr    (::struc_t *)
                            ///< \param offset  (::ea_t)
                            ///< \param delta   (::adiff_t)
    struc_expanded,         ///< A structure type has been expanded/shrank.
                            ///< \param sptr (::struc_t *)

    struc_member_created,   ///< A structure member has been created.
                            ///< \param sptr  (::struc_t *)
                            ///< \param mptr  (::member_t *)

    deleting_struc_member,  ///< A structure member is to be deleted.
                            ///< \param sptr  (::struc_t *)
                            ///< \param mptr  (::member_t *)
    struc_member_deleted,   ///< A structure member has been deleted.
                            ///< \param sptr       (::struc_t *)
                            ///< \param member_id  (::tid_t)
                            ///< \param offset     (::ea_t)

    renaming_struc_member,  ///< A structure member is to be renamed.
                            ///< \param sptr     (::struc_t *)
                            ///< \param mptr     (::member_t *)
                            ///< \param newname  (const char *)
    struc_member_renamed,   ///< A structure member has been renamed.
                            ///< \param sptr  (::struc_t *)
                            ///< \param mptr  (::member_t *)

    changing_struc_member,  ///< A structure member is to be changed.
                            ///< \param sptr    (::struc_t *)
                            ///< \param mptr    (::member_t *)
                            ///< \param flag    (::flags_t)
                            ///< \param ti      (const ::opinfo_t *)
                            ///< \param nbytes  (::asize_t)
    struc_member_changed,   ///< A structure member has been changed.
                            ///< \param sptr  (::struc_t *)
                            ///< \param mptr  (::member_t *)

    changing_struc_cmt,     ///< A structure type comment is to be changed.
                            ///< \param struc_id    (::tid_t)
                            ///< \param repeatable  (bool)
                            ///< \param newcmt      (const char *)
    struc_cmt_changed,      ///< A structure type comment has been changed.
                            ///< \param struc_id        (::tid_t)
                            ///< \param repeatable_cmt  (bool)

    segm_added,             ///< A new segment has been created.
                            ///< \param s  (::segment_t *)

    deleting_segm,          ///< A segment is to be deleted.
                            ///< \param start_ea  (::ea_t)
    segm_deleted,           ///< A segment has been deleted.
                            ///< \param start_ea  (::ea_t)
                            ///< \param end_ea    (::ea_t)

    changing_segm_start,    ///< Segment start address is to be changed.
                            ///< \param s             (::segment_t *)
                            ///< \param new_start     (::ea_t)
                            ///< \param segmod_flags  (int)
    segm_start_changed,     ///< Segment start address has been changed.
                            ///< \param s        (::segment_t *)
                            ///< \param oldstart (::ea_t)

    changing_segm_end,      ///< Segment end address is to be changed.
                            ///< \param s             (::segment_t *)
                            ///< \param new_end       (::ea_t)
                            ///< \param segmod_flags  (int)
    segm_end_changed,       ///< Segment end address has been changed.
                            ///< \param s      (::segment_t *)
                            ///< \param oldend (::ea_t)

    changing_segm_name,     ///< Segment name is being changed.
                            ///< \param s        (::segment_t *)
                            ///< \param oldname  (const char *)
    segm_name_changed,      ///< Segment name has been changed.
                            ///< \param s        (::segment_t *)
                            ///< \param name     (const char *)

    changing_segm_class,    ///< Segment class is being changed.
                            ///< \param s  (::segment_t *)
    segm_class_changed,     ///< Segment class has been changed.
                            ///< \param s        (::segment_t *)
                            ///< \param sclass   (const char *)

    segm_attrs_updated,     ///< Segment attributes has been changed.
                            ///< \param s        (::segment_t *)
                            ///< This event is generated for secondary segment
                            ///< attributes (examples: color, permissions, etc)

    segm_moved,             ///< Segment has been moved.
                            ///< \param from    (::ea_t)
                            ///< \param to      (::ea_t)
                            ///< \param size    (::asize_t)
                            ///< \param changed_netmap (bool)
                            ///< See also \ref idb_event::allsegs_moved

    allsegs_moved,          ///< Program rebasing is complete.
                            ///< This event is generated after series of
                            ///< segm_moved events
                            ///< \param info     (::segm_move_infos_t *)

    func_added,             ///< The kernel has added a function.
                            ///< \param pfn  (::func_t *)

    func_updated,           ///< The kernel has updated a function.
                            ///< \param pfn  (::func_t *)

    set_func_start,         ///< Function chunk start address will be changed.
                            ///< \param pfn        (::func_t *)
                            ///< \param new_start  (::ea_t)

    set_func_end,           ///< Function chunk end address will be changed.
                            ///< \param pfn      (::func_t *)
                            ///< \param new_end  (::ea_t)

    deleting_func,          ///< The kernel is about to delete a function.
                            ///< \param pfn  (::func_t *)
                            //
    frame_deleted,          ///< The kernel has deleted a function frame.
                            ///< \param pfn  (::func_t *)

    thunk_func_created,     ///< A thunk bit has been set for a function.
                            ///< \param pfn  (::func_t *)

    func_tail_appended,     ///< A function tail chunk has been appended.
                            ///< \param pfn   (::func_t *)
                            ///< \param tail  (::func_t *)

    deleting_func_tail,     ///< A function tail chunk is to be removed.
                            ///< \param pfn   (::func_t *)
                            ///< \param tail  (const ::range_t *)

    func_tail_deleted,      ///< A function tail chunk has been removed.
                            ///< \param pfn      (::func_t *)
                            ///< \param tail_ea  (::ea_t)

    tail_owner_changed,     ///< A tail chunk owner has been changed.
                            ///< \param tail        (::func_t *)
                            ///< \param owner_func  (::ea_t)
                            ///< \param old_owner   (::ea_t)

    func_noret_changed,     ///< #FUNC_NORET bit has been changed.
                            ///< \param pfn  (::func_t *)

    stkpnts_changed,        ///< Stack change points have been modified.
                            ///< \param pfn  (::func_t *)

    updating_tryblks,       ///< About to update tryblk information
                            ///< \param tbv      (const ::tryblks_t *)
    tryblks_updated,        ///< Updated tryblk information
                            ///< \param tbv      (const ::tryblks_t *)

    deleting_tryblks,       ///< About to delete tryblk information in given range
                            ///< \param range    (const ::range_t *)
                            //
    sgr_changed,            ///< The kernel has changed a segment register value.
                            ///< \param start_ea    (::ea_t)
                            ///< \param end_ea      (::ea_t)
                            ///< \param regnum     (int)
                            ///< \param value      (::sel_t)
                            ///< \param old_value  (::sel_t)
                            ///< \param tag        (::uchar) \ref SR_

    make_code,              ///< An instruction is being created.
                            ///< \param insn    (const ::insn_t*)

    make_data,              ///< A data item is being created.
                            ///< \param ea     (::ea_t)
                            ///< \param flags  (::flags_t)
                            ///< \param tid    (::tid_t)
                            ///< \param len    (::asize_t)

    destroyed_items,        ///< Instructions/data have been destroyed in [ea1,ea2).
                            ///< \param ea1                 (::ea_t)
                            ///< \param ea2                 (::ea_t)
                            ///< \param will_disable_range  (bool)

    renamed,                ///< The kernel has renamed a byte.
                            ///< See also the \idpcode{rename} event
                            ///< \param ea          (::ea_t)
                            ///< \param new_name    (const char *)
                            ///< \param local_name  (bool)

    byte_patched,           ///< A byte has been patched.
                            ///< \param ea         (::ea_t)
                            ///< \param old_value  (::uint32)

    changing_cmt,           ///< An item comment is to be changed.
                            ///< \param ea              (::ea_t)
                            ///< \param repeatable_cmt  (bool)
                            ///< \param newcmt          (const char *)
    cmt_changed,            ///< An item comment has been changed.
                            ///< \param ea              (::ea_t)
                            ///< \param repeatable_cmt  (bool)

    changing_range_cmt,     ///< Range comment is to be changed.
                            ///< \param kind        (::range_kind_t)
                            ///< \param a           (const ::range_t *)
                            ///< \param cmt         (const char *)
                            ///< \param repeatable  (bool)
    range_cmt_changed,      ///< Range comment has been changed.
                            ///< \param kind        (::range_kind_t)
                            ///< \param a           (const ::range_t *)
                            ///< \param cmt         (const char *)
                            ///< \param repeatable  (bool)

    extra_cmt_changed,      ///< An extra comment has been changed.
                            ///< \param ea        (::ea_t)
                            ///< \param line_idx  (int)
                            ///< \param cmt       (const char *)
  };
}




#endif // _IDP_HPP
