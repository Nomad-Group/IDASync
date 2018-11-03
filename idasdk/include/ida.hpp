/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2015 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef _IDA_HPP
#define _IDA_HPP

#include <pro.h>
#include <range.hpp>

/*! \file ida.hpp

  \brief Contains the ::inf structure definition and some
         functions common to the whole IDA project.

  The ::inf structure is saved in the database and contains information
  specific to the current program being disassembled.
  Initially it is filled with values from ida.cfg.

  Although it is not a good idea to change values in ::inf
  structure (because you will overwrite values taken from ida.cfg),
  you are allowed to do it if you feel it necessary.

*/

//--------------------------------------------------------------------------
/// Known input file formats (kept in \inf{filetype}):
enum filetype_t
{
  f_EXE_old,            ///< MS DOS EXE File
  f_COM_old,            ///< MS DOS COM File
  f_BIN,                ///< Binary File
  f_DRV,                ///< MS DOS Driver
  f_WIN,                ///< New Executable (NE)
  f_HEX,                ///< Intel Hex Object File
  f_MEX,                ///< MOS Technology Hex Object File
  f_LX,                 ///< Linear Executable (LX)
  f_LE,                 ///< Linear Executable (LE)
  f_NLM,                ///< Netware Loadable Module (NLM)
  f_COFF,               ///< Common Object File Format (COFF)
  f_PE,                 ///< Portable Executable (PE)
  f_OMF,                ///< Object Module Format
  f_SREC,               ///< R-records
  f_ZIP,                ///< ZIP file (this file is never loaded to IDA database)
  f_OMFLIB,             ///< Library of OMF Modules
  f_AR,                 ///< ar library
  f_LOADER,             ///< file is loaded using LOADER DLL
  f_ELF,                ///< Executable and Linkable Format (ELF)
  f_W32RUN,             ///< Watcom DOS32 Extender (W32RUN)
  f_AOUT,               ///< Linux a.out (AOUT)
  f_PRC,                ///< PalmPilot program file
  f_EXE,                ///< MS DOS EXE File
  f_COM,                ///< MS DOS COM File
  f_AIXAR,              ///< AIX ar library
  f_MACHO,              ///< Mac OS X
};

//--------------------------------------------------------------------------

typedef uchar comp_t;   ///< target compiler id
typedef uchar cm_t;     ///< calling convention and memory model

/// Information about the target compiler
struct compiler_info_t
{
  comp_t id;            ///< compiler id (see \ref COMP_)
  cm_t cm;              ///< memory model and calling convention (see \ref CM_)
  uchar size_i;         ///< sizeof(int)
  uchar size_b;         ///< sizeof(bool)
  uchar size_e;         ///< sizeof(enum)
  uchar defalign;       ///< default alignment for structures
  uchar size_s;         ///< short
  uchar size_l;         ///< long
  uchar size_ll;        ///< longlong
  uchar size_ldbl;      ///< longdouble (if different from \ph{tbyte_size})
  void set_64bit_pointer_size(); // set the definition in typeinf.hpp
};

//--------------------------------------------------------------------------
/// Storage types for flag bits
enum storage_type_t
{
  STT_CUR = -1, ///< use current storage type (may be used only as a function argument)
  STT_VA  = 0,  ///< regular storage: virtual arrays, an explicit flag for each byte
  STT_MM  = 1,  ///< memory map: sparse storage. useful for huge objects
  STT_DBG = 2,  ///< memory map: temporary debugger storage. used internally
};

/// \def{EA64_ALIGN, Maintain 64-bit alignments in 64-bit mode}
#ifdef __EA64__
#define EA64_ALIGN(n) uint32 n;
#else
#define EA64_ALIGN(n)
#endif

//--------------------------------------------------------------------------
/// The database parameters.
/// This structure is kept in the ida database.
/// It contains the essential parameters for the current program
struct idainfo
{
  char tag[3];                          ///< 'IDA'
  char zero;                            ///< this field is not present in the database
  ushort version;                       ///< Version of database
  char procname[16];                    ///< Name of the current processor (with \0)

  ushort s_genflags;                    ///< \ref INFFL_
/// \defgroup INFFL_ General idainfo flags
/// Used by idainfo::s_genflags
//@{
#define INFFL_AUTO       0x01           ///< Autoanalysis is enabled?
#define INFFL_ALLASM     0x02           ///< may use constructs not supported by
                                        ///< the target assembler
#define INFFL_LOADIDC    0x04           ///< loading an idc file that contains database info
#define INFFL_NOUSER     0x08           ///< do not store user info in the database
#define INFFL_READONLY   0x10           ///< (internal) temporary interdiction to modify the database
#define INFFL_CHKOPS     0x20           ///< check manual operands? (unused)
#define INFFL_NMOPS      0x40           ///< allow non-matched operands? (unused)
#define INFFL_GRAPH_VIEW 0x80           ///< currently using graph options (\dto{graph})
//@}
  bool use_allasm(void) const { return (s_genflags & INFFL_ALLASM) != 0; }   ///< #INFFL_ALLASM
  bool loading_idc(void) const { return (s_genflags & INFFL_LOADIDC) != 0; } ///< #INFFL_LOADIDC
  bool store_user_info(void) const { return (s_genflags & INFFL_NOUSER) == 0; } ///< #INFFL_NOUSER
  bool readonly_idb(void) const { return (s_genflags & INFFL_READONLY) != 0; } ///< #INFFL_READONLY
  bool is_graph_view(void) const { return (s_genflags & INFFL_GRAPH_VIEW) != 0; } ///< #INFFL_GRAPH_VIEW
  void set_graph_view(bool value) { setflag(s_genflags, INFFL_GRAPH_VIEW, value); }

  uint32 lflags;                        ///< \ref LFLG_
/// \defgroup LFLG_ Misc. database flags
/// used by idainfo::lflags
//@{
#define LFLG_PC_FPP     0x00000001      ///< decode floating point processor instructions?
#define LFLG_PC_FLAT    0x00000002      ///< 32-bit program?
#define LFLG_64BIT      0x00000004      ///< 64-bit program?
#define LFLG_IS_DLL     0x00000008      ///< Is dynamic library?
#define LFLG_FLAT_OFF32 0x00000010      ///< treat ::REF_OFF32 as 32-bit offset for 16bit segments (otherwise try SEG16:OFF16)
#define LFLG_MSF        0x00000020      ///< Byte order: is MSB first?
#define LFLG_WIDE_HBF   0x00000040      ///< Bit order of wide bytes: high byte first?
                                        ///< (wide bytes: \ph{dnbits} > 8)
#define LFLG_DBG_NOPATH 0x00000080      ///< do not store input full path in debugger process options
#define LFLG_SNAPSHOT   0x00000100      ///< memory snapshot was taken?
#define LFLG_PACK       0x00000200      ///< pack the database?
#define LFLG_COMPRESS   0x00000400      ///< compress the database?
#define LFLG_KERNMODE   0x00000800      ///< is kernel mode binary?
//@}
  bool is_32bit(void) const         { return (lflags & LFLG_PC_FLAT) != 0; }    ///< #LFLG_PC_FLAT
  bool is_64bit(void) const         { return (lflags & LFLG_64BIT) != 0; }      ///< #LFLG_64BIT
  bool is_snapshot(void) const      { return (lflags & LFLG_SNAPSHOT) != 0; }   ///< #LFLG_SNAPSHOT
  bool is_dll(void) const           { return (lflags & LFLG_IS_DLL) != 0; }     ///< #LFLG_IS_DLL
  bool is_flat_off32(void) const    { return (lflags & LFLG_FLAT_OFF32) != 0; } ///< #LFLG_FLAT_OFF32
  bool is_be(void) const            { return (lflags & LFLG_MSF) != 0; }        ///< #LFLG_MSF
  bool set_be(bool value)           { bool old = is_be(); setflag(lflags, LFLG_MSF, value);; return old; }
  bool is_wide_high_byte_first(void) const
                                    { return (lflags & LFLG_WIDE_HBF) != 0; }   ///< #LFLG_WIDE_HBF
  void set_wide_high_byte_first(bool value)
                                    { setflag(lflags, LFLG_WIDE_HBF, value); }
  void set_64bit(void)
  {
    lflags |= LFLG_PC_FLAT | LFLG_64BIT;
    cc.set_64bit_pointer_size(); // 64-bit programs have 8 byte pointers by default
  }
  bool is_kernel_mode(void) const   { return (lflags & LFLG_KERNMODE) != 0; }   ///< #LFLG_KERNMODE

/// \defgroup IDB_ Line prefix options
/// Used by idainfo::get_pack_mode
//@{
#define IDB_UNPACKED   0                ///< leave database components unpacked
#define IDB_PACKED     1                ///< pack database components into .idb
#define IDB_COMPRESSED 2                ///< compress & pack database components
//@}

  int get_pack_mode() const
  {
    return (lflags & LFLG_COMPRESS) != 0 ? IDB_COMPRESSED
         : (lflags & LFLG_PACK) != 0     ? IDB_PACKED
         :                                 IDB_UNPACKED;
  }
  int set_pack_mode(int pack_mode)
  {
    int old = get_pack_mode();
    setflag(lflags, LFLG_COMPRESS, pack_mode == IDB_COMPRESSED);
    setflag(lflags, LFLG_PACK,     pack_mode == IDB_PACKED);
    return old;
  }

  uint32 database_change_count;         ///< incremented after each byte and regular
                                        ///< segment modifications

  ushort filetype;                      ///< The input file type

  /// Is unstructured input file?
  bool like_binary(void) const
  {
    return filetype == f_BIN
        || filetype == f_HEX
        || filetype == f_MEX
        || filetype == f_SREC;
  }

  ushort ostype;                        ///< OS type the program is for
                                        ///< bit definitions in libfuncs.hpp

  ushort apptype;                       ///< Application type
                                        ///< bit definitions in libfuncs.hpp

  uchar asmtype;                        ///< target assembler number

  uchar specsegs;                       ///< What format do special segments use? 0-unspecified, 4-entries are 4 bytes, 8- entries are 8 bytes.

  uint32 af;                            ///< \ref AF_
/// \defgroup AF_ Analysis flags
/// used by idainfo::af
//@{
#define AF_CODE         0x00000001      ///< Trace execution flow
#define AF_MARKCODE     0x00000002      ///< Mark typical code sequences as code
#define AF_JUMPTBL      0x00000004      ///< Locate and create jump tables
#define AF_PURDAT       0x00000008      ///< Control flow to data segment is ignored
#define AF_USED         0x00000010      ///< Analyze and create all xrefs
#define AF_UNK          0x00000020      ///< Delete instructions with no xrefs

#define AF_PROCPTR      0x00000040      ///< Create function if data xref data->code32 exists
#define AF_PROC         0x00000080      ///< Create functions if call is present
#define AF_FTAIL        0x00000100      ///< Create function tails
#define AF_LVAR         0x00000200      ///< Create stack variables
#define AF_STKARG       0x00000400      ///< Propagate stack argument information
#define AF_REGARG       0x00000800      ///< Propagate register argument information
#define AF_TRACE        0x00001000      ///< Trace stack pointer
#define AF_VERSP        0x00002000      ///< Perform full SP-analysis. (\ph{verify_sp})
#define AF_ANORET       0x00004000      ///< Perform 'no-return' analysis
#define AF_MEMFUNC      0x00008000      ///< Try to guess member function types
#define AF_TRFUNC       0x00010000      ///< Truncate functions upon code deletion

#define AF_STRLIT       0x00020000      ///< Create string literal if data xref exists
#define AF_CHKUNI       0x00040000      ///< Check for unicode strings
#define AF_FIXUP        0x00080000      ///< Create offsets and segments using fixup info
#define AF_DREFOFF      0x00100000      ///< Create offset if data xref to seg32 exists
#define AF_IMMOFF       0x00200000      ///< Convert 32bit instruction operand to offset
#define AF_DATOFF       0x00400000      ///< Automatically convert data to offsets

#define AF_FLIRT        0x00800000      ///< Use flirt signatures
#define AF_SIGCMT       0x01000000      ///< Append a signature name comment for recognized anonymous library functions
#define AF_SIGMLT       0x02000000      ///< Allow recognition of several copies of the same function
#define AF_HFLIRT       0x04000000      ///< Automatically hide library functions

#define AF_JFUNC        0x08000000      ///< Rename jump functions as j_...
#define AF_NULLSUB      0x10000000      ///< Rename empty functions as nullsub_...

#define AF_DODATA       0x20000000      ///< Coagulate data segs at the final pass
#define AF_DOCODE       0x40000000      ///< Coagulate code segs at the final pass
#define AF_FINAL        0x80000000      ///< Final pass of analysis
//@}
  uint32 af2;                           ///< \ref AF2_
/// \defgroup AF2_ Analysis flags 2
/// Used by idainfo::af2
//@{
#define AF2_DOEH        0x00000001      ///< Handle EH information
#define AF2_DORTTI      0x00000002      ///< Handle RTTI information
/// remaining 30 bits are reserved
//@}
  uval_t baseaddr;                      ///< base address of the program (paragraphs)
  sel_t start_ss;                       ///< selector of the initial stack segment
  sel_t start_cs;                       ///< selector of the segment with the main entry point
  ea_t start_ip;                        ///< IP register value at the start of
                                        ///< program execution
  ea_t start_ea;                        ///< Linear address of program entry point
  ea_t start_sp;                        ///< SP register value at the start of
                                        ///< program execution
  ea_t main;                            ///< address of main()
  ea_t min_ea;                          ///< current limits of program
  ea_t max_ea;                          ///< maxEA is excluded
  ea_t omin_ea;                         ///< original minEA (is set after loading the input file)
  ea_t omax_ea;                         ///< original maxEA (is set after loading the input file)

  ea_t lowoff;                          ///< Low  limit for offsets
                                        ///< (used in calculation of 'void' operands)
  ea_t highoff;                         ///< High limit for offsets
                                        ///< (used in calculation of 'void' operands)

  uval_t maxref;                        ///< Max tail for references

  range_t privrange;                    ///< Range of addresses reserved for internal use.
                                        ///< Initially (MAXADDR, MAXADDR+0x800000)
  sval_t netdelta;                      ///< Delta value to be added to all adresses for mapping to netnodes.
                                        ///< Initially 0

  /// CROSS REFERENCES
  uchar xrefnum;                        ///< Number of references to generate
                                        ///< in the disassembly listing
                                        ///< 0 - xrefs won't be generated at all
  uchar type_xrefnum;                   ///< Number of references to generate
                                        ///< in the struct & enum windows
                                        ///< 0 - xrefs won't be generated at all
  uchar refcmtnum;                      ///< Number of comment lines to
                                        ///< generate for refs to string literals
                                        ///< or demangled names
                                        ///< 0 - such comments won't be
                                        ///< generated at all
  uchar s_xrefflag;                     ///< \ref SW_X
/// \defgroup SW_X Xref options
/// Used by idainfo::s_xrefflag
//@{
#define SW_SEGXRF       0x01            ///< show segments in xrefs?
#define SW_XRFMRK       0x02            ///< show xref type marks?
#define SW_XRFFNC       0x04            ///< show function offsets?
#define SW_XRFVAL       0x08            ///< show xref values? (otherwise-"...")
//@}

  /// NAMES
  ushort max_autoname_len;              ///< max autogenerated name length (without zero byte)
  char nametype;                        ///< \ref NM_
/// \defgroup NM_ Dummy names representation types
/// Used by idainfo::nametype
//@{
#define NM_REL_OFF      0
#define NM_PTR_OFF      1
#define NM_NAM_OFF      2
#define NM_REL_EA       3
#define NM_PTR_EA       4
#define NM_NAM_EA       5
#define NM_EA           6
#define NM_EA4          7
#define NM_EA8          8
#define NM_SHORT        9
#define NM_SERIAL       10
//@}

  uint32 short_demnames;                ///< short form of demangled names
  uint32 long_demnames;                 ///< long form of demangled names
                                        ///< see demangle.h for definitions
  uchar demnames;                       ///< \ref DEMNAM_
/// \defgroup DEMNAM_ Demangled name flags
/// used by idainfo::demnames
//@{
#define DEMNAM_MASK  3                  ///< mask for name form
#define DEMNAM_CMNT  0                  ///< display demangled names as comments
#define DEMNAM_NAME  1                  ///< display demangled names as regular names
#define DEMNAM_NONE  2                  ///< don't display demangled names
#define DEMNAM_GCC3  4                  ///< assume gcc3 names (valid for gnu compiler)
#define DEMNAM_FIRST 8                  ///< override type info
//@}
  /// Get #DEMNAM_MASK bits of #demnames
  uchar get_demname_form(void) const { return (uchar)(demnames & DEMNAM_MASK); }

  uchar listnames;                      ///< \ref LN_
/// \defgroup LN_ Name list options
/// Used by idainfo::listnames
//@{
#define LN_NORMAL       0x01            ///< include normal names
#define LN_PUBLIC       0x02            ///< include public names
#define LN_AUTO         0x04            ///< include autogenerated names
#define LN_WEAK         0x08            ///< include weak names
//@}

  /// DISASSEMBLY LISTING DETAILS
  uchar indent;                         ///< Indentation for instructions
  uchar comment;                        ///< Indentation for comments
  ushort margin;                        ///< max length of data lines
  ushort lenxref;                       ///< max length of line with xrefs
  uint32 outflags;                      ///< \ref OFLG_
/// \defgroup OFLG_ output flags
/// used by idainfo::outflags
//@{
#define OFLG_SHOW_VOID    0x002         ///< Display void marks?
#define OFLG_SHOW_AUTO    0x004         ///< Display autoanalysis indicator?
#define OFLG_GEN_NULL     0x010         ///< Generate empty lines?
#define OFLG_SHOW_PREF    0x020         ///< Show line prefixes?
#define OFLG_PREF_SEG     0x040         ///< line prefixes with segment name?
#define OFLG_LZERO        0x080         ///< generate leading zeroes in numbers
#define OFLG_GEN_ORG      0x100         ///< Generate 'org' directives?
#define OFLG_GEN_ASSUME   0x200         ///< Generate 'assume' directives?
#define OFLG_GEN_TRYBLKS  0x400         ///< Generate try/catch directives?
//@}

  uchar s_cmtflg;                       ///< \ref SW_C
/// \defgroup SW_C Comment options
/// Used by idainfo::s_cmtflg
//@{
#define SW_RPTCMT       0x01            ///< show repeatable comments?
#define SW_ALLCMT       0x02            ///< comment all lines?
#define SW_NOCMT        0x04            ///< no comments at all
#define SW_LINNUM       0x08            ///< show source line numbers
#define SW_TESTMODE     0x10            ///< testida.idc is running
#define SW_SHHID_ITEM   0x20            ///< show hidden instructions
#define SW_SHHID_FUNC   0x40            ///< show hidden functions
#define SW_SHHID_SEGM   0x80            ///< show hidden segments
//@}

  uchar s_limiter;                      ///< \ref LMT_
/// \defgroup LMT_ Delimiter options
/// Used by idainfo::s_limiter
//@{
#define LMT_THIN        0x01            ///< thin borders
#define LMT_THICK       0x02            ///< thick borders
#define LMT_EMPTY       0x04            ///< empty lines at the end of basic blocks
//@}

  short bin_prefix_size;                ///< # of instruction bytes to show in line prefix
  uchar s_prefflag;                     ///< \ref PREF_
/// \defgroup PREF_ Line prefix options
/// Used by idainfo::s_prefflag
//@{
#define PREF_SEGADR     0x01            ///< show segment addresses?
#define PREF_FNCOFF     0x02            ///< show function offsets?
#define PREF_STACK      0x04            ///< show stack pointer?
//@}

  /// STRING LITERALS
  uchar strlit_flags;                   ///< \ref STRF_
/// \defgroup STRF_ string literal flags
/// Used by idainfo::strlit_flags
//@{
#define STRF_GEN        0x01            ///< generate names?
#define STRF_AUTO       0x02            ///< names have 'autogenerated' bit?
#define STRF_SERIAL     0x04            ///< generate serial names?
#define STRF_UNICODE    0x08            ///< unicode strings are present?
#define STRF_COMMENT    0x10            ///< generate auto comment for string references?
#define STRF_SAVECASE   0x20            ///< preserve case of strings for identifiers
//@}
  uchar strlit_break;                   ///< string literal line break symbol
  char strlit_zeroes;                   ///< leading zeroes
  int32 strtype;                        ///< current ascii string type
                                        ///< see nalt.hpp for string types
  char strlit_pref[16];                 ///< prefix for string literal names
  uval_t strlit_sernum;                 ///< serial number

  // DATA ITEMS
  uval_t datatypes;                     ///< data types allowed in data carousel

  /// COMPILER
  compiler_info_t cc;                   ///< Target compiler
  uint32 abibits;                       ///< ABI features. Depends on info returned by get_abi_name()
                                        ///< Processor modules may modify them in set_compiler

/// \defgroup ABI_ abi options
/// Used by idainfo::abibits
//@{
#define ABI_8ALIGN4       0x00000001    ///< 4 byte alignment for 8byte scalars (__int64/double) inside structures?
#define ABI_PACK_STKARGS  0x00000002    ///< do not align stack arguments to stack slots
#define ABI_BIGARG_ALIGN  0x00000004    ///< use natural type alignment for argument if the alignment exceeds native word size
                                        ///< (e.g. __int64 argument should be 8byte aligned on some 32bit platforms)
#define ABI_STACK_LDBL    0x00000008    ///< long double areuments are passed on stack
#define ABI_STACK_VARARGS 0x00000010    ///< varargs are always passed on stack (even when there are free registers)
#define ABI_HARD_FLOAT    0x00000020    ///< use the floating-point register set
#define ABI_SET_BY_USER   0x00000040    ///< compiler/abi were set by user flag and require SETCOMP_BY_USER flag to be changed
#define ABI_GCC_LAYOUT    0x00000080    ///< use gcc layout for udts (used for mingw)
//@}

  bool is_mem_aligned4(void) const { return (abibits & ABI_8ALIGN4) != 0; }
  bool pack_stkargs(void) const { return (abibits & ABI_PACK_STKARGS) != 0; }
  bool big_arg_align(void) const { return (abibits & ABI_BIGARG_ALIGN) != 0; }
  bool stack_ldbl() const { return (abibits & ABI_STACK_LDBL) != 0; }
  bool stack_varargs() const { return (abibits & ABI_STACK_VARARGS) != 0; }
  bool is_hard_float(void) const { return (abibits & ABI_HARD_FLOAT) != 0; }
  bool use_gcc_layout(void) const { return (abibits & ABI_GCC_LAYOUT) != 0; }

  uint32 appcall_options;               ///< appcall options, see idd.hpp
  EA64_ALIGN(padding);
                                        ///< total size for 32bit: 216 bytes
                                        ///<            for 64bit: 296 bytes
  bool is_auto_enabled(void) const          { return (s_genflags & INFFL_AUTO) != 0; }   ///< #INFFL_AUTO
  void set_auto_enabled(bool value)         { setflag(s_genflags, INFFL_AUTO, value); }
  bool show_void(void) const                { return (outflags & OFLG_SHOW_VOID) != 0; }   ///< #OFLG_SHOW_VOID
  void set_show_void(bool value)            { setflag(outflags, OFLG_SHOW_VOID, value); }
  bool show_auto(void) const                { return (outflags & OFLG_SHOW_AUTO) != 0; }   ///< #OFLG_SHOW_AUTO
  void set_show_auto(bool value)            { setflag(outflags, OFLG_SHOW_AUTO, value); }
  bool gen_null(void) const                 { return (outflags & OFLG_GEN_NULL) != 0; }   ///< #OFLG_GEN_NULL
  void set_gen_null(bool value)             { setflag(outflags, OFLG_GEN_NULL, value); }
  bool show_line_pref(void) const           { return (outflags & OFLG_SHOW_PREF) != 0; }   ///< #OFLG_SHOW_PREF
  void set_show_line_pref(bool value)       { setflag(outflags, OFLG_SHOW_PREF, value); }
  bool line_pref_with_seg(void) const       { return (outflags & OFLG_PREF_SEG) != 0; }   ///< #OFLG_PREF_SEG
  void set_line_pref_with_seg(bool value)   { setflag(outflags, OFLG_PREF_SEG, value); }
  bool gen_lzero(void) const                { return (outflags & OFLG_LZERO) != 0; }   ///< #OFLG_LZERO
  void set_gen_lzero(bool value)            { setflag(outflags, OFLG_LZERO, value); }
  bool gen_tryblks(void) const              { return (outflags & OFLG_GEN_TRYBLKS) != 0; } /// < #OFLG_GEN_TRYBLKS
  void set_gen_tryblks(bool value)          { setflag(outflags, OFLG_GEN_TRYBLKS, value); }
  bool check_manual_ops(void) const         { return (s_genflags & INFFL_CHKOPS) != 0; } ///< #INFFL_CHKOPS
  void set_check_manual_ops(bool value)     { setflag(s_genflags, INFFL_CHKOPS, value); }
  bool allow_nonmatched_ops(void) const     { return (s_genflags & INFFL_NMOPS) != 0; } ///< #INFFL_NMOPS
  void set_allow_nonmatched_ops(bool value) { setflag(s_genflags, INFFL_NMOPS, value); }


};

idaman idainfo ida_export_data inf;     ///< program specific information




/// Is IDA configured to show all repeatable comments?
inline bool idaapi show_repeatables(void) { return (inf.s_cmtflg & SW_RPTCMT) != 0; }
/// Is IDA configured to show all comment lines?
inline bool idaapi show_all_comments(void) { return (inf.s_cmtflg & SW_ALLCMT) != 0; }
/// Is IDA configured to show any comments at all?
inline bool idaapi show_comments(void)    { return (inf.s_cmtflg & SW_NOCMT)  == 0; }
/// Is IDA configured to trace the stack pointer?
inline bool idaapi should_trace_sp(void) { return (inf.af & AF_TRACE) != 0; }
/// Is IDA configured to create stack variables?
inline bool idaapi should_create_stkvars(void) { return (inf.af & AF_LVAR) != 0; }


//------------------------------------------------------------------------//
/// max number of operands allowed for an instruction

#define UA_MAXOP        8


//------------------------------------------------------------------------//
/// \defgroup IDAPLACE_ Disassembly line options
/// Combinations of these values are used as user data for ::linearray_t.
/// Also see ::idaplace_t.
//@{
#define IDAPLACE_STACK   0x0010  ///< produce 2/4/8 bytes per undefined item.
                                 ///< (used to display the stack contents)
                                 ///< the number of displayed bytes depends on the stack bitness
// not used yet because it confuses users:
//#define IDAPLACE_SHOWPRF 0x0020  // display line prefixes
#define IDAPLACE_SEGADDR 0x0040  ///< display line prefixes with the segment part
//@}


/// Get default disassembly line options (see \ref IDAPLACE_)

inline int calc_default_idaplace_flags(void)
{
  int flags = 0;
//  if ( inf.show_line_pref() ) flags |= IDAPLACE_SHOWPRF;
  if ( inf.s_prefflag & PREF_SEGADR )
    flags |= IDAPLACE_SEGADDR;
  return flags;
}

//------------------------------------------------------------------------//

/// \def{MAXADDR, Max allowed address in IDA (excluded) - OBSOLETE, don't use it!}
#ifdef __EA64__
#ifdef __GNUC__
#define MAXADDR         0xFF00000000000000ll
#else
#define MAXADDR         0xFF00000000000000ui64
#endif
#else
#define MAXADDR         0xFF000000L
#endif


//------------------------------------------------------------------------//
/// Convert (seg,off) value to a linear address

inline ea_t idaapi to_ea(sel_t reg_cs,ea_t reg_ip)
{
  return (reg_cs<<4) + reg_ip;
}

/// \def{IDB_EXT32, Database file extension for 32-bit programs}
/// \def{IDB_EXT64, Database file extension for 64-bit programs}
/// \def{IDB_EXT,   Database file extension}
#define IDB_EXT32 "idb"
#define IDB_EXT64 "i64"
#ifdef __EA64__
#define IDB_EXT IDB_EXT64
#else
#define IDB_EXT IDB_EXT32
#endif



#endif // _IDA_HPP
