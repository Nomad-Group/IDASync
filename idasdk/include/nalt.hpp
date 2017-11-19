/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2015 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef NALT_HPP
#define NALT_HPP

#include <ida.hpp>
#include <netnode.hpp>

#pragma pack(push, 1)           // IDA uses 1 byte alignments

/*! \file nalt.hpp

  \brief Definitions of various information kept in netnodes

  Each address in the program has a corresponding netnode: netnode(ea).

  If we have no information about an address, the corresponding
  netnode is not created.
  Otherwise we will create a netnode and save information in it.
  All variable length information (names, comments, offset information, etc)
  is stored in the netnode.

  Don't forget that some information is already stored in the flags (bytes.hpp)

  \warning
  Many of the functions in this file are very low level (they are marked
  as low level functions). Use them only if you can't find higher level
  function to set/get/del information.

  You can create your own nodes in IDP module and store information
  in them. See ::netnode.
*/

/// \defgroup NALT_ Structure of altvals array
/// Structure of altvals array of netnode(ea).
/// altvals is a virtual array of 32-bit longs attached to a netnode.
/// the size of this array is unlimited. Unused indexes are not kept in the
/// database. We use only first several indexes to this array.
//@{
#define  NALT_ENUM      uval_t(-2) ///< reserved for enums, see enum.hpp
#define  NALT_WIDE      uval_t(-1) ///< 16-bit byte value
#define  NALT_SWITCH    1          ///< switch idiom address (used at jump targets)
//#define  NALT_OBASE1    2        // offset base 2
#define  NALT_STRUCT    3          ///< struct id
//#define  NALT_SEENF     4        // 'seen' flag (used in structures)
//#define  NALT_OOBASE0   5        // outer offset base 1
//#define  NALT_OOBASE1   6        // outer offset base 2
//#define  NALT_XREFPOS   7        // saved xref address in the xrefs window
#define  NALT_AFLAGS    8          ///< additional flags for an item
#define  NALT_LINNUM    9          ///< source line number
#define  NALT_ABSBASE  10          ///< absolute segment location
#define  NALT_ENUM0    11          ///< enum id for the first operand
#define  NALT_ENUM1    12          ///< enum id for the second operand
//#define  NALT_STROFF0  13        // struct offset, struct id for the first operand
//#define  NALT_STROFF1  14        // struct offset, struct id for the second operand
#define  NALT_PURGE    15          ///< number of bytes purged from the stack when a function is called indirectly
#define  NALT_STRTYPE  16          ///< type of string item
#define  NALT_ALIGN    17          ///< alignment value if the item is #FF_ALIGN
                                   ///< (should by equal to power of 2)
//#define  NALT_HIGH0    18        // linear address of byte referenced by
//                                 // high 16 bits of an offset (FF_0HIGH)
//#define  NALT_HIGH1    19        // linear address of byte referenced by
//                                 // high 16 bits of an offset (FF_1HIGH)
#define  NALT_COLOR    20          ///< instruction/data background color
//@}

/// \defgroup NSUP_ Structure of supvals array
/// Structure of supvals array of netnode(ea).
/// Supvals is a virtual array of objects of arbitrary length attached
/// to a netnode (length of one element is limited by #MAXSPECSIZE, though)
/// We use first several indexes to this array:
//@{
#define  NSUP_CMT       0       ///< regular comment
#define  NSUP_REPCMT    1       ///< repeatable comment
#define  NSUP_FOP1      2       ///< forced operand 1
#define  NSUP_FOP2      3       ///< forced operand 2
#define  NSUP_JINFO     4       ///< jump table info
#define  NSUP_ARRAY     5       ///< array parameters
#define  NSUP_OMFGRP    6       ///< OMF: group of segments (not used anymore)
#define  NSUP_FOP3      7       ///< forced operand 3
#define  NSUP_SWITCH    8       ///< switch information
#define  NSUP_REF0      9       ///< complex reference information for operand 1
#define  NSUP_REF1      10      ///< complex reference information for operand 2
#define  NSUP_REF2      11      ///< complex reference information for operand 3
#define  NSUP_OREF0     12      ///< outer complex reference information for operand 1
#define  NSUP_OREF1     13      ///< outer complex reference information for operand 2
#define  NSUP_OREF2     14      ///< outer complex reference information for operand 3
#define  NSUP_STROFF0   15      ///< stroff: struct path for the first operand
#define  NSUP_STROFF1   16      ///< stroff: struct path for the second operand
#define  NSUP_SEGTRANS  17      ///< segment translations
#define  NSUP_FOP4      18      ///< forced operand 4
#define  NSUP_FOP5      19      ///< forced operand 5
#define  NSUP_FOP6      20      ///< forced operand 6
#define  NSUP_REF3      21      ///< complex reference information for operand 4
#define  NSUP_REF4      22      ///< complex reference information for operand 5
#define  NSUP_REF5      23      ///< complex reference information for operand 6
#define  NSUP_OREF3     24      ///< outer complex reference information for operand 4
#define  NSUP_OREF4     25      ///< outer complex reference information for operand 5
#define  NSUP_OREF5     26      ///< outer complex reference information for operand 6
#define  NSUP_XREFPOS   27      ///< saved xref address and type in the xrefs window
#define  NSUP_CUSTDT    28      ///< custom data type id
#define  NSUP_GROUPS    29      ///< SEG_GRP: pack_dd encoded list of selectors

// values E_PREV..E_NEXT+1000 are reserved (1000..2000..3000 decimal)

/// SP change points blob (see funcs.cpp).
/// values NSUP_POINTS..NSUP_POINTS+0x1000 are reserved
#define  NSUP_POINTS    0x1000

/// manual instruction.
/// values NSUP_MANUAL..NSUP_MANUAL+0x1000 are reserved
#define  NSUP_MANUAL    0x2000

/// type information.
/// values NSUP_TYPEINFO..NSUP_TYPEINFO+0x1000 are reserved
#define  NSUP_TYPEINFO  0x3000

/// register variables.
/// values NSUP_REGVAR..NSUP_REGVAR+0x1000 are reserved
#define  NSUP_REGVAR    0x4000

/// local labels.
/// values NSUP_LLABEL..NSUP_LLABEL+0x1000 are reserved
#define  NSUP_LLABEL    0x5000

/// register argument type/name descriptions
/// values NSUP_REGARG..NSUP_REGARG+0x1000 are reserved
#define  NSUP_REGARG    0x6000

/// function tails or tail referers
/// values NSUP_FTAILS..NSUP_FTAILS+0x1000 are reserved
#define  NSUP_FTAILS    0x7000

/// graph group information
/// values NSUP_GROUP..NSUP_GROUP+0x1000 are reserved
#define  NSUP_GROUP     0x8000

/// operand type information.
/// values NSUP_OPTYPES..NSUP_OPTYPES+0x100000 are reserved
#define  NSUP_OPTYPES   0x9000
//@}

/// \defgroup NALT_X Netnode xref tags
/// Tag values to store xrefs (see cref.cpp)
//@{
#define NALT_CREF_TO         'X'     ///< code xref to, idx: target address
#define NALT_CREF_FROM       'x'     ///< code xref from, idx: source address
#define NALT_DREF_TO         'D'     ///< data xref to, idx: target address
#define NALT_DREF_FROM       'd'     ///< data xref from, idx: source address
//@}

/// \defgroup N_TAG Netnode graph tags
/// Tag values to store graph info
//@{
#define NSUP_GR_INFO         'g'     ///< group node info: color, ea, text
#define NALT_GR_LAYX         'p'     ///< group layout ptrs, hash: md5 of 'belongs'
#define NSUP_GR_LAYT         'l'     ///< group layouts, idx: layout pointer
//@}

/// See ::net_patch
#define PATCH_TAG 'P'
/// Node with information about patched bytes.
/// altval(ea)<-(oldval).
/// charval(ea, PATCH_TAG)==1 => byte has been patched.
idaman netnode ida_export_data net_patch;

/// Node with information about imported modules.
/// \note Please use enum_import_names() to work with imports!
/// supval(i) -> module name; altval(i) -> module node.
/// altval(-1) -> number of modules.
/// the module node is:
///   - supval(ea) -> function name
///   - altval(ord) -> import ea
///   - for modules that import the same ordinal multiple times:
///     altval(ea, 'O') -> ordinal
idaman netnode ida_export_data import_node;

/// \name Helper macros
//@{
#define _N_PASTE(x,y)   x ## y
#define N_PASTE(x,y)    _N_PASTE(x,y)
#define NSUP_TYPE(name,type,code,size)                                  \
inline ssize_t N_PASTE(get_,name)(ea_t ea, type *buf, size_t bufsize)   \
        { return netnode(ea).supval(code, buf, bufsize); }              \
inline void N_PASTE(set_,name)(ea_t ea,const type *oi)                  \
        { netnode(ea).supset(code,oi,size); }                           \
inline void N_PASTE(del_,name)(ea_t ea) { netnode(ea).supdel(code); }

#define NSUP_CHAR(name,code)                                            \
inline ssize_t N_PASTE(get_,name)(ea_t ea, char *buf, size_t bufsize)   \
        { return netnode(ea).supstr(code, buf, bufsize); }              \
inline void N_PASTE(set_,name)(ea_t ea,const char *oi)                  \
        { netnode(ea).supset(code,oi); }                                \
inline void N_PASTE(del_,name)(ea_t ea) { netnode(ea).supdel(code); }

#define NSUP_VTYPE(name,type,code)                                      \
inline ssize_t N_PASTE(get_,name)(ea_t ea, type *buf, size_t bufsize)   \
        { return netnode(ea).supval(code, buf, bufsize); }              \
inline void N_PASTE(set_,name)(ea_t ea,const type *oi,int size)         \
        { netnode(ea).supset(code,oi,size); }                           \
inline void N_PASTE(del_,name)(ea_t ea) { netnode(ea).supdel(code); }

#define NSUP_BLOB(name,type,code)                                       \
inline type *N_PASTE(get_,name)(ea_t ea,type *buf,size_t *bufsize)      \
        { return (type *)netnode(ea).getblob(buf,bufsize,code,stag); }  \
inline void N_PASTE(set_,name)(ea_t ea,const type *oi,size_t size)      \
        { netnode(ea).setblob(oi,size,code,stag); }                     \
inline void N_PASTE(del_,name)(ea_t ea) { netnode(ea).delblob(code,stag); }

#define NALT_TYPE(get,set,del,type,code)                                                                              \
inline type get(ea_t ea) { type x; return netnode(ea).supval(code, &x, sizeof(x), atag) > 0 ? type(x-1) : type(-1); } \
inline void set(ea_t ea,type x) { x++; netnode(ea).supset(code, &x, sizeof(x), atag); }                               \
inline void del(ea_t ea) { netnode(ea).supdel(code, atag); }

#define NSUP_STRUCT(name,code)  NSUP_TYPE(name,N_PASTE(name,_t),code,sizeof(N_PASTE(name,_t)))
#define NSUP_STRING(name,code)  NSUP_CHAR(name,code)

#define NSUP_VAR(name,code,t)   NSUP_VTYPE(name,t,code)
#define NALT_EA(    get,set,del,code) NALT_TYPE(get,set,del,ea_t,  code)
#define NALT_UINT32(get,set,del,code) NALT_TYPE(get,set,del,uint32,code)
#define NALT_UINT16(get,set,del,code) NALT_TYPE(get,set,del,uint16,code)
#define NALT_UINT8( get,set,del,code) NALT_TYPE(get,set,del,uint8, code)
//@}

//--------------------------------------------------------------------------
//      C O N V E N I E N C E   F U N C T I O N S
//--------------------------------------------------------------------------

/// \name Wide values
/// Up to 32bit value for wide (more than 8-bit) byte processors.
/// Use higher level functions:
///   - get_full_byte()
///   - get_full_word()
///   - get_full_long()
//@{
NALT_UINT32(get_wide_value,set_wide_value,del_wide_value,NALT_WIDE)
//@}

/// \name Structure ID
/// Structure ID for structures in structure definitions.
/// Use higher level function get_opinfo()
//@{
NALT_EA(get_strid,_set_strid,_del_strid, NALT_STRUCT)
//@}

/// \name xrefpos
//@{
/// Position of cursor in the window with cross-references to the address.
/// Used by the user-interface.
struct xrefpos_t
{
  ea_t ea;
  char type;
};
NSUP_STRUCT(xrefpos, NSUP_XREFPOS)
//@}

/// \defgroup AFL_ Additional flags for the location
/// All 32-bits of the main flags (bytes.hpp) are used up.
/// Additional flags keep more information about addresses.
/// DO NOT use these flags directly unless there is absolutely no way.
/// They are too low level and may corrupt the database.
//@{
#define AFL_LINNUM      0x00000001L     ///< has line number info
#define AFL_USERSP      0x00000002L     ///< user-defined SP value
#define AFL_PUBNAM      0x00000004L     ///< name is public (inter-file linkage)
#define AFL_WEAKNAM     0x00000008L     ///< name is weak
#define AFL_HIDDEN      0x00000010L     ///< the item is hidden completely
#define AFL_MANUAL      0x00000020L     ///< the instruction/data is specified by the user
#define AFL_NOBRD       0x00000040L     ///< the code/data border is hidden
#define AFL_ZSTROFF     0x00000080L     ///< display struct field name at 0 offset when displaying an offset.
                                        ///< example:
                                        ///<   \v{offset somestruct.field_0}
                                        ///< if this flag is clear, then
                                        ///<   \v{offset somestruct}
#define AFL_BNOT0       0x00000100L     ///< the 1st operand is bitwise negated
#define AFL_BNOT1       0x00000200L     ///< the 2nd operand is bitwise negated
#define AFL_LIB         0x00000400L     ///< item from the standard library.
                                        ///< low level flag, is used to set
                                        ///< #FUNC_LIB of ::func_t
#define AFL_TI          0x00000800L     ///< has typeinfo? (#NSUP_TYPEINFO)
#define AFL_TI0         0x00001000L     ///< has typeinfo for operand 0? (#NSUP_OPTYPES)
#define AFL_TI1         0x00002000L     ///< has typeinfo for operand 1? (#NSUP_OPTYPES+1)
#define AFL_LNAME       0x00004000L     ///< has local name too (#FF_NAME should be set)
#define AFL_TILCMT      0x00008000L     ///< has type comment? (such a comment may be changed by IDA)
#define AFL_LZERO0      0x00010000L     ///< toggle leading zeroes for the 1st operand
#define AFL_LZERO1      0x00020000L     ///< toggle leading zeroes for the 2nd operand
#define AFL_COLORED     0x00040000L     ///< has user defined instruction color?
#define AFL_TERSESTR    0x00080000L     ///< terse structure variable display?
#define AFL_SIGN0       0x00100000L     ///< code: toggle sign of the 1st operand
#define AFL_SIGN1       0x00200000L     ///< code: toggle sign of the 2nd operand
#define AFL_NORET       0x00400000L     ///< for imported function pointers: doesn't return.
                                        ///< this flag can also be used for any instruction
                                        ///< which halts or finishes the program execution
#define AFL_FIXEDSPD    0x00800000L     ///< sp delta value is fixed by analysis.
                                        ///< should not be modified by modules
#define AFL_ALIGNFLOW   0x01000000L     ///< the previous insn was created for alignment purposes only
#define AFL_USERTI      0x02000000L     ///< the type information is definitive.
                                        ///< (comes from the user or type library)
#define AFL_RETFP       0x04000000L     ///< function returns a floating point value
#define AFL_USEMODSP    0x08000000L     ///< insn modifes SP and uses the modified value
                                        ///< example: pop [rsp+N]
#define AFL_NOTCODE     0x10000000L     ///< autoanalysis should not create code here
//@}

/// \name Work with additional location flags
/// See \ref AFL_
//@{
inline void   set_aflags0(ea_t ea, uint32 flags){ netnode(ea).altset(NALT_AFLAGS,flags); }
inline uint32 get_aflags0(ea_t ea)              { return flags_t(netnode(ea).altval(NALT_AFLAGS)); }
inline void   del_aflags0(ea_t ea)              { netnode(ea).altdel(NALT_AFLAGS); }
idaman void   ida_export set_aflags(ea_t ea, uint32 flags);
idaman void   ida_export set_abits(ea_t ea,uint32 bits);
idaman void   ida_export clr_abits(ea_t ea,uint32 bits);
idaman uint32 ida_export get_aflags(ea_t ea);
idaman void   ida_export del_aflags(ea_t ea);

/// Used to define 3 functions to work with a bit:
///   - int  test(ea_t ea);   // test if the bit is set
///   - void set(ea_t ea);    // set bit
///   - void clear(ea_t ea);  // clear bit
#define IMPLEMENT_AFLAG_FUNCTIONS(bit, test, set, clear)            \
inline bool test(ea_t ea)   { return (get_aflags(ea) & bit) != 0; } \
inline void set(ea_t ea)    { set_abits(ea, bit); }                 \
inline void clear(ea_t ea)  { clr_abits(ea, bit); }

/// See #IMPLEMENT_AFLAG_FUNCTIONS
#define IMPL__IS_AFLAG_FUNCS(bit, name) \
 IMPLEMENT_AFLAG_FUNCTIONS(bit, is_ ## name, set_ ## name, clr_ ## name)
/// See #IMPLEMENT_AFLAG_FUNCTIONS
#define IMPL_HAS_AFLAG_FUNCS(bit, name) \
 IMPLEMENT_AFLAG_FUNCTIONS(bit, has_ ## name, set_has_ ## name, clr_has_ ## name)

IMPLEMENT_AFLAG_FUNCTIONS(AFL_HIDDEN,   is_hidden_item, hide_item, unhide_item)
IMPLEMENT_AFLAG_FUNCTIONS(AFL_NOBRD,    is_hidden_border, hide_border, unhide_border)
IMPLEMENT_AFLAG_FUNCTIONS(AFL_USEMODSP, uses_modsp, set_usemodsp, clr_usemodsp)

IMPL__IS_AFLAG_FUNCS(AFL_ZSTROFF,  zstroff)
IMPL__IS_AFLAG_FUNCS(AFL_BNOT0,    _bnot0)
IMPL__IS_AFLAG_FUNCS(AFL_BNOT1,    _bnot1)
IMPL__IS_AFLAG_FUNCS(AFL_LIB,      libitem)
IMPL_HAS_AFLAG_FUNCS(AFL_TI,       ti)
IMPL_HAS_AFLAG_FUNCS(AFL_TI0,      ti0)
IMPL_HAS_AFLAG_FUNCS(AFL_TI1,      ti1)
IMPL_HAS_AFLAG_FUNCS(AFL_LNAME,    lname)
IMPL__IS_AFLAG_FUNCS(AFL_TILCMT,   tilcmt)
IMPL__IS_AFLAG_FUNCS(AFL_USERSP,   usersp)
IMPL__IS_AFLAG_FUNCS(AFL_LZERO0,   lzero0)
IMPL__IS_AFLAG_FUNCS(AFL_LZERO1,   lzero1)
IMPL__IS_AFLAG_FUNCS(AFL_COLORED,  colored_item)
IMPL__IS_AFLAG_FUNCS(AFL_TERSESTR, terse_struc)
IMPL__IS_AFLAG_FUNCS(AFL_SIGN0,    _invsign0)
IMPL__IS_AFLAG_FUNCS(AFL_SIGN1,    _invsign1)
IMPL__IS_AFLAG_FUNCS(AFL_NORET,    noret)
IMPL__IS_AFLAG_FUNCS(AFL_FIXEDSPD, fixed_spd)
IMPL__IS_AFLAG_FUNCS(AFL_ALIGNFLOW,align_flow)
IMPL__IS_AFLAG_FUNCS(AFL_USERTI,   userti)
IMPL__IS_AFLAG_FUNCS(AFL_RETFP,    retfp)
IMPL__IS_AFLAG_FUNCS(AFL_NOTCODE,  notcode)
//@}


/// Change visibility of item at given ea

inline void set_visible_item(ea_t ea, bool visible)
{
  if ( visible )
    unhide_item(ea);
  else
    hide_item(ea);
}

/// Test visibility of item at given ea

inline bool is_visible_item(ea_t ea) { return !is_hidden_item(ea); }


/// Is instruction visible?

inline bool is_finally_visible_item(ea_t ea)
 { return (inf.s_cmtflg & SW_SHHID_ITEM) != 0 || is_visible_item(ea); }


/// \name Source line numbers
/// They are sometimes present in object files.
//@{
NALT_EA(get_linnum0,set_linnum0, del_linnum0, NALT_LINNUM)
idaman void   ida_export set_source_linnum(ea_t ea, uval_t lnnum);
idaman uval_t ida_export get_source_linnum(ea_t ea);
idaman void   ida_export del_source_linnum(ea_t ea);
//@}

/// \name Absolute segment base address
/// These functions may be used if necessary.
//@{
NALT_EA(get_absbase,set_absbase, del_absbase, NALT_ABSBASE)
//@}

/// \name Enum id (first operand)
/// Use higher level function get_enum_id()
//@{
NALT_EA(get_enum_id0,set_enum_id0,del_enum_id0,NALT_ENUM0)
//@}

/// \name Enum id (second operand)
/// Use higher level function get_enum_id()
//@{
NALT_EA(get_enum_id1,set_enum_id1,del_enum_id1,NALT_ENUM1)
//@}

/// \name Purged bytes
/// Number of bytes purged from the stack when a function is called indirectly
/// get_ind_purged() may be used if necessary.
/// Use set_purged() to modify this value (do not use set_ind_purged())
//@{
NALT_EA(get_ind_purged,set_ind_purged,del_ind_purged,NALT_PURGE)
//@}

/// \name Get type of string
/// Use higher level function get_opinfo().
//@{
NALT_UINT32(get_str_type,set_str_type,del_str_type,NALT_STRTYPE)
//@}

/// \defgroup ASCSTR_ String type codes
//@{
#define ASCSTR_C        ASCSTR_TERMCHR ///< C-style ASCII string
#define ASCSTR_TERMCHR  0              ///< Character-terminated ASCII string.
                                       ///< The termination characters are kept in
                                       ///< the next bytes of string type.
#define ASCSTR_PASCAL   1              ///< Pascal-style ASCII string (one byte length prefix)
#define ASCSTR_LEN2     2              ///< Pascal-style, two-byte length prefix
#define ASCSTR_UNICODE  3              ///< Unicode string (UTF-16)
#define ASCSTR_UTF16    3              ///< same
#define ASCSTR_LEN4     4              ///< Pascal-style, four-byte length prefix
#define ASCSTR_ULEN2    5              ///< Pascal-style Unicode, two-byte length prefix
#define ASCSTR_ULEN4    6              ///< Pascal-style Unicode, four-byte length prefix
#define ASCSTR_UTF32    7              ///< four-byte Unicode codepoints
#define ASCSTR_LAST     7              ///< Last string type
//@}

/// \name Work with string type codes
/// See \ref ASCSTR_
//@{
inline char idaapi get_str_type_code(uval_t strtype) { return char(strtype); }
inline char get_str_term1(int32 strtype) { return char(strtype>>8); }
inline char get_str_term2(int32 strtype) { return char(strtype>>16); }
                                // if the second termination character is
                                // '\0', then it doesn't exist.
inline bool is_unicode(int32 strtype)
{
  char code = get_str_type_code(strtype);
  return code == ASCSTR_UNICODE
      || code == ASCSTR_ULEN2
      || code == ASCSTR_ULEN4;
}
inline bool is_pascal(int32 strtype)
{
  char code = get_str_type_code(strtype);
  return code == ASCSTR_PASCAL
      || code == ASCSTR_LEN2
      || code >= ASCSTR_LEN4;
}
//@}

/// Get index of the string encoding for this string
inline uchar idaapi get_str_encoding_idx(int32 strtype) { return uchar(strtype>>24); }

#define STRENC_DEFAULT 0x00  ///< use default encoding for this type (see get_default_encoding_idx())
#define STRENC_NONE    0xFF  ///< force no-conversion encoding

/// \name Alignment value
/// (should be power of 2)
/// These functions may be used if necessary.
//@{
NALT_UINT32(get_alignment,set_alignment,del_alignment,NALT_ALIGN)
//@}

/// \name Instruction/Data background color
//@{
NALT_UINT32(_get_item_color,_set_item_color,_del_item_color,NALT_COLOR)
idaman void      ida_export set_item_color(ea_t ea, bgcolor_t color);
idaman bgcolor_t ida_export get_item_color(ea_t ea);      // returns DEFCOLOR if no color
idaman void      ida_export del_item_color(ea_t ea);
//@}

//----------------------------------------------------------------------
/// \name Regular comment
/// low level, don't use - use get_cmt()
//@{
NSUP_STRING(nalt_cmt,NSUP_CMT)
//@}

/// \name Repeatable comment
/// low level, don't use - use get_cmt()
//@{
NSUP_STRING(nalt_rptcmt,NSUP_REPCMT)
//@}

/// \name Forced operands
/// low level, don't use - use get_forced_operand()
//@{
NSUP_STRING(fop1,NSUP_FOP1)
NSUP_STRING(fop2,NSUP_FOP2)
NSUP_STRING(fop3,NSUP_FOP3)
NSUP_STRING(fop4,NSUP_FOP4)
NSUP_STRING(fop5,NSUP_FOP5)
NSUP_STRING(fop6,NSUP_FOP6)
//@}

/// \name Manual insn
/// low level, don't use - use get_manual_insn()
//@{
NSUP_BLOB(manual_insn0,char,NSUP_MANUAL)
//@}

/// \name Graph group
/// low level, don't use - use mutable_graph_t::get_graph_groups()
//@{
NSUP_BLOB(graph_groups0,uchar,NSUP_GROUP)
//@}

//--------------------------------------------------------------------------
/// \name Jump tables
//@{
/// Information about jump tables
struct jumptable_info_t
{
  ea_t table;
  asize_t size;
};
NSUP_STRUCT(jumptable_info,NSUP_JINFO)
//@}

//--------------------------------------------------------------------------
/// \name Array representation
//@{
/// Describes how to display an array
struct array_parameters_t
{
  int32 flags;
#define AP_ALLOWDUPS    0x00000001L     ///< use 'dup' construct
#define AP_SIGNED       0x00000002L     ///< treats numbers as signed
#define AP_INDEX        0x00000004L     ///< display array element indexes as comments
#define AP_ARRAY        0x00000008L     ///< create as array (this flag is not stored in database)
#define AP_IDXBASEMASK  0x000000F0L     ///< mask for number base of the indexes
#define   AP_IDXDEC     0x00000000L     ///< display indexes in decimal
#define   AP_IDXHEX     0x00000010L     ///< display indexes in hex
#define   AP_IDXOCT     0x00000020L     ///< display indexes in octal
#define   AP_IDXBIN     0x00000030L     ///< display indexes in binary

  int32 lineitems;                      ///< number of items on a line
  int32 alignment;                      ///< -1 - don't align.
                                        ///< 0  - align automatically.
                                        ///< else item width
};
NSUP_STRUCT(array_parameters,NSUP_ARRAY)
//@}

//--------------------------------------------------------------------------
/// Information about a switch statement
struct switch_info_t
{
  ushort flags;                 ///< \ref SWI_
/// \defgroup SWI_ Switch info flags
/// Used by switch_info_t::flags
//@{
#define SWI_SPARSE      0x01    ///< sparse switch (value table present)
                                ///< otherwise lowcase present
#define SWI_V32         0x02    ///< 32-bit values in table
#define SWI_J32         0x04    ///< 32-bit jump offsets
#define SWI_VSPLIT      0x08    ///< value table is split (only for 32-bit values)
#define SWI_DEFAULT     0x10    ///< default case is present
#define SWI_END_IN_TBL  0x20    ///< switchend in table (default entry)
#define SWI_JMP_INV     0x40    ///< jumptable is inversed. (last entry is
                                ///< for first entry in values table)
#define SWI_SHIFT_MASK  0x180   ///< use formula (element<<shift) + elbase to find jump targets
#define SWI_ELBASE      0x200   ///< elbase is present (if not and shift!=0, endof(jumpea) is used)
#define SWI_JSIZE       0x400   ///< jump offset expansion bit
#define SWI_VSIZE       0x800   ///< value table element size expansion bit
#define SWI_SEPARATE    0x1000  ///< create an array of individual elements (otherwise separate items)
#define SWI_SIGNED      0x2000  ///< jump table entries are signed
#define SWI_CUSTOM      0x4000  ///< custom jump table. \ph{create_switch_xrefs} will be
                                ///< called to create code xrefs for the table.
                                ///< it must return 2.
                                ///< custom jump table must be created by the module
                                ///< (or see #SWI2_STDTBL)
#define SWI_EXTENDED    0x8000  ///< this is a ::switch_info_ex_t
//@}

  /// See #SWI_SHIFT_MASK.
  /// possible answers: 0..3.
  int get_shift(void) const { return ((flags & SWI_SHIFT_MASK) >> 7); }

  /// See #SWI_SHIFT_MASK
  void set_shift(int shift)
  {
    flags &= ~SWI_SHIFT_MASK;
    flags = ushort(flags | ((shift & 3) << 7));
  }

  int get_jtable_element_size(void) const
  { // this brain damaged logic is needed for compatibility with old versions
    int code = flags & (SWI_J32|SWI_JSIZE);
    if ( code == 0 )
      return 2;
    if ( code == SWI_J32 )
      return 4;
    if ( code == SWI_JSIZE )
      return 1;
    return 8;
  }
  void set_jtable_element_size(int size)
  {
    flags &= ~SWI_J32|SWI_JSIZE;
    if ( size == 4 ) { flags |= SWI_J32; return; }
    if ( size == 1 ) { flags |= SWI_JSIZE; return; }
    if ( size == 8 ) { flags |= SWI_J32|SWI_JSIZE; return; }
    if ( size != 2 ) abort();
  }
  int get_vtable_element_size(void) const
  {
    int code = flags & (SWI_V32|SWI_VSIZE);
    if ( code == 0 )
      return 2;
    if ( code == SWI_V32 )
      return 4;
    if ( code == SWI_VSIZE )
      return 1;
    return 8;
  }
  void set_vtable_element_size(int size)
  {
    flags &= ~SWI_V32|SWI_VSIZE;
    if ( size == 4 ) { flags |= SWI_V32; return; }
    if ( size == 1 ) { flags |= SWI_VSIZE; return; }
    if ( size == 8 ) { flags |= SWI_V32|SWI_VSIZE; return; }
    if ( size != 2 ) abort();
  }
  ushort ncases;                ///< number of cases (excluding default)
  ea_t jumps;                   ///< jump table start address
  union
  {
    ea_t values;                ///< values table address (if #SWI_SPARSE is set)
    uval_t lowcase;             ///< the lowest value in cases
  };
  ea_t defjump;                 ///< default jump address (#BADADDR if not used)
  ea_t startea;                 ///< start of the switch idiom
};

/// Extended information about a switch statement
struct switch_info_ex_t : public switch_info_t
{
  size_t cb;                    ///< sizeof(this)
  int flags2;                   ///< \ref SWI2_
/// \defgroup SWI2_ Extended switch info flags
/// Used by switch_info_ex_t::flags2
//@{
#define SWI2_INDIRECT    0x0001 ///< value table elements are used as indexes into the jump table
#define SWI2_SUBTRACT    0x0002 ///< table values are subtracted from the elbase instead of being added
#define SWI2_HXNOLOWCASE 0x0004 ///< lowcase value should not be used by the decompiler (internal flag)
#define SWI2_STDTBL      0x0008 ///< use standard table formatting (only xrefs are customized)
//@}

  int jcases;                   ///< number of entries in the jump table (SWI2_INDIRECT)
  bool is_indirect(void)  const { return (flags & SWI_EXTENDED) != 0 && (flags2 & SWI2_INDIRECT) != 0; }
  bool is_subtract(void)  const { return (flags & SWI_EXTENDED) != 0 && (flags2 & SWI2_SUBTRACT) != 0; }
  bool is_nolowcase(void) const { return (flags & SWI_EXTENDED) != 0 && (flags2 & SWI2_HXNOLOWCASE) != 0; }
  int get_jtable_size(void) const { return is_indirect() ? jcases : ncases; }
  sval_t ind_lowcase;
  sval_t get_lowcase(void) const { return is_indirect() ? ind_lowcase : lowcase; }
  ea_t elbase;                  ///< element base
  int regnum;                   ///< the switch expression as a register number
                                ///< of the instruction at 'startea'. -1 means 'unknown'
  char regdtyp;                 ///< size of the switch expression register as dtyp
  void set_expr(int r, char dt) { regnum = r; regdtyp = dt; }
  uval_t custom;                ///< information for custom tables (filled and used by modules)
  switch_info_ex_t(void) { clear(); }
  void clear(void)
  {
    memset(this, 0, sizeof(switch_info_ex_t));
    cb = sizeof(switch_info_ex_t);
    flags = SWI_EXTENDED;
    jumps = BADADDR;
    defjump = BADADDR;
    startea = BADADDR;
    regnum = -1;
  }
};

/// \name Switch info Ex
/// See ::switch_info_ex_t, xref.hpp for related functions
//@{
NSUP_STRUCT(switch_info_ex,NSUP_SWITCH)
//@}

/// \name Switch parent
/// Address which holds the switch info (::switch_info_t). Used at the jump targets.
//@{
NALT_EA(get_switch_parent,set_switch_parent,del_switch_parent, NALT_SWITCH)
//@}

/// \name Custom data types
//@{
/// Information about custom data types
struct custom_data_type_ids_t
{
  int16 dtid;           ///< data type id
  int16 fids[6];        ///< data format ids
};
idaman int  ida_export get_custom_data_type_ids(ea_t ea, custom_data_type_ids_t *cdis, size_t bufsize);
idaman void ida_export set_custom_data_type_ids(ea_t ea, const custom_data_type_ids_t *cdis);
inline void idaapi del_custom_data_type_ids(ea_t ea) { netnode(ea).supdel(NSUP_CUSTDT); }
//@}

typedef uchar reftype_t;  ///< see \ref reftype_
/// \defgroup reftype_ Types of references
/// References are represented in the following form:
///
///         \v{target + tdelta - base}
///
/// If the target is not present, then it will be calculated using
///
///         \v{target = operand_value - tdelta + base}
///
/// The target must be present for LOW and HIGH reference types
//@{
const reftype_t
  REF_OFF8   = 0,         ///< 8bit full offset
  REF_OFF16  = 1,         ///< 16bit full offset
  REF_OFF32  = 2,         ///< 32bit full offset
  REF_LOW8   = 3,         ///< low 8bits of 16bit offset
  REF_LOW16  = 4,         ///< low 16bits of 32bit offset
  REF_HIGH8  = 5,         ///< high 8bits of 16bit offset
  REF_HIGH16 = 6,         ///< high 16bits of 32bit offset
  REF_VHIGH  = 7,         ///< high \ph{high_fixup_bits} of 32bit offset
  REF_VLOW   = 8,         ///< low  \ph{high_fixup_bits} of 32bit offset
  REF_OFF64  = 9,         ///< 64bit full offset
  REF_LAST = REF_OFF64;
//@}

/// Get REF_... constant from size
/// Supported sizes: 1,2,4,8,16
/// For other sizes returns reftype(-1)

idaman reftype_t ida_export get_reftype_by_size(size_t size);

/// Information about a reference
struct refinfo_t
{
  ea_t    target;                 ///< reference target (#BADADDR-none)
  ea_t    base;                   ///< base of reference
  adiff_t tdelta;                 ///< offset from the target
  uint32  flags;                  ///< \ref REFINFO_
/// \defgroup REFINFO_ Reference info flags
/// Used by refinfo_t::flags
//@{
#define REFINFO_TYPE      0x000F  ///< reference type
#define REFINFO_RVAOFF    0x0010  ///< based reference (rva)
                                  ///< refinfo_t::base will be forced to get_imagebase()
                                  ///< such a reference is displayed with the \ash{a_rva} keyword
#define REFINFO_PASTEND   0x0020  ///< reference past an item
                                  ///< it may point to an nonexistent address
                                  ///< do not destroy alignment dirs
#define REFINFO_CUSTOM    0x0040  ///< a custom reference
                                  ///< the kernel will call \ph{notify}(ph.custom_offset, ....
                                  ///< that can change all arguments used for calculations.
                                  ///< This flag is useful for custom fixups
#define REFINFO_NOBASE    0x0080  ///< don't create the base xref
                                  ///< implies that the base can be any value
                                  ///< nb: base xrefs are created only if the offset base
                                  ///< points to the middle of a segment
#define REFINFO_SUBTRACT  0x0100  ///< the reference value is subtracted from the base value instead of (as usual) being added to it
#define REFINFO_SIGNEDOP  0x0200  ///< the operand value is sign-extended (only supported for REF_OFF8/16/32/64)
//@}

  reftype_t type(void)    const { return reftype_t(flags & REFINFO_TYPE); }
  bool no_base_xref(void) const { return (flags & REFINFO_NOBASE) != 0; }
  bool is_pastend(void)   const { return (flags & REFINFO_PASTEND) != 0; }
  bool is_rvaoff(void)    const { return (flags & REFINFO_RVAOFF) != 0; }
  bool is_custom(void)    const { return (flags & REFINFO_CUSTOM) != 0; }
  bool is_subtract(void)  const { return (flags & REFINFO_SUBTRACT) != 0; }
  bool is_signed(void)    const { return (flags & REFINFO_SIGNEDOP) != 0; }

  void set_type(reftype_t t) { flags &= ~REFINFO_TYPE; flags |= t; }

  // init the structure with some default values
  // reft_and_flags should be REF_xxx optionally ORed with some REFINFO_xxx flags
  void init(uint32 reft_and_flags, ea_t _base = 0, ea_t _target = BADADDR, adiff_t _tdelta = 0)
  {
    flags = reft_and_flags;
    base = _base;
    target = _target;
    tdelta = _tdelta;
  }

  // internal use
  ea_t _get_target(adiff_t opval) const;
  ea_t _get_value(ea_t target) const;
  adiff_t _get_opval(adiff_t opval) const;
};

/// Manage a custom refinfo type
struct custom_refinfo_handler_t
{
  int32 cbsize;                 ///< size of this structure
  const char *name;             ///< Format name, must be unique
  const char *desc;             ///< Refinfo description to use in Ctrl-R dialog
  int props;                    ///< properties (currently 0)

  ea_t (idaapi *calc_basevalue)(
        ea_t from,
        refinfo_t &ri,
        adiff_t opval,
        ea_t target);

  ea_t (idaapi *calc_target)(
        ea_t from,
        refinfo_t &ri,
        adiff_t opval);

  int (idaapi *gen_expr)(       // returns: 1 - buf filled as simple expression
        ea_t ea,                //          2 - buf filled as complex expression
        int opnum,              //          3 - apply standard processing (with - possible - changed values)
        refinfo_t *ri,          //      other - can't convert to offset expression
        ea_t from,
        adiff_t *opval,
        char *buf,
        size_t bufsize,
        char *format,           // buffer for the format (if retcode==3)
        size_t formatsize,
        ea_t *target,
        ea_t *fullvalue,
        int getn_flags);
};
typedef qvector<const custom_refinfo_handler_t *> custom_refinfo_handlers_t; ///< vector of refinfo handlers


/// Register a new custom refinfo type.

idaman int ida_export register_custom_refinfo(const custom_refinfo_handler_t *crh);


/// Unregister a new custom refinfo type.

idaman bool ida_export unregister_custom_refinfo(int crid);


/// Get refinfo handlers

idaman int ida_export get_custom_refinfos(const custom_refinfo_handler_t ***infos);

#define MAXSTRUCPATH  32        ///< maximal inclusion depth of unions

/// Information for structure offsets.
/// ids[0] contains the id of the structure.
/// ids[1..len-1] contain ids of the structure members used in the structure offset
/// expression.
/// len is the length of the path, i.e. the number of elements in 'ids'
struct strpath_t
{
  int len;
  tid_t ids[MAXSTRUCPATH]; // for union member ids
  adiff_t delta;
};

/// See opinfo_t::ec
struct enum_const_t
{
  tid_t tid;
  uchar serial;
};

/// Additional information about an operand type
union opinfo_t
{
  refinfo_t ri;              ///< for offset members
  tid_t tid;                 ///< for struct, etc. members
  strpath_t path;            ///< for stroff
  int32 strtype;             ///< for strings (\ref ASCSTR_)
  enum_const_t ec;           ///< for enums
  custom_data_type_ids_t cd; ///< for custom data
};

/// \name Get/Set refinfo
/// n may be 0, 1, 2, #OPND_MASK.
/// #OPND_OUTER may be used too.
/// Don't use these functions, see get_opinfo(), set_opinfo()
//@{
idaman int ida_export set_refinfo_ex(ea_t ea, int n, const refinfo_t *ri);  // 1-ok, 0-bad refinfo
idaman int ida_export set_refinfo(ea_t ea, int n,
          reftype_t type, ea_t target=BADADDR, ea_t base=0, adiff_t tdelta=0);
idaman int ida_export get_refinfo(ea_t ea, int n, refinfo_t *ri);        // 1-ok, 0-no refinfo
idaman int ida_export del_refinfo(ea_t ea, int n);
//@}

//--------------------------------------------------------------------------
/// \name Structure paths
/// Structure paths for unions and structures with unions (strpath)
/// a structure path is an array of id's.
/// the first id is the id of the structure itself.
/// additional id's (if any) specify which member of a union we should select
/// the maximal size of array is #MAXSTRUCPATH.
/// strpaths are used to determine how to display structure offsets.
//@{
idaman void ida_export write_struc_path(netnode node, int idx, const tid_t *path, int plen, adiff_t delta);
idaman int  ida_export read_struc_path(netnode node, int idx, tid_t *path, adiff_t *delta);  // returns plen
void del_struc_path(netnode node, int idx, const tid_t *path, int plen);

#define DEFINE_PATH_FUNCS(name, code)                                \
inline int  N_PASTE(get_,name)(ea_t ea, tid_t *path, adiff_t *delta) \
 { return read_struc_path(netnode(ea), code, path, delta); }         \
inline void N_PASTE(set_,name)(ea_t ea, const tid_t *path, int plen, adiff_t delta) \
 { write_struc_path(netnode(ea), code, path, plen, delta); }         \
inline void N_PASTE(del_,name)(ea_t ea, const tid_t *path, int plen) \
 { del_struc_path(netnode(ea), code, path, plen); }

DEFINE_PATH_FUNCS(stroff0, NSUP_STROFF0)
DEFINE_PATH_FUNCS(stroff1, NSUP_STROFF1)
//@}

//--------------------------------------------------------------------------
/// \name Segment translation
/// low level segment translation functions.
/// please use functions from segment.hpp.
//@{
NSUP_VAR(_segtrans, NSUP_SEGTRANS, ea_t)
//@}

//--------------------------------------------------------------------------
// type information (ti) storage
// up to 256 operands are supported for ti.

typedef uchar type_t;
typedef uchar p_list;
class tinfo_t;

/// \name Types
/// Work with function/data types
/// These functions may be used if necessary.
//@{
idaman bool ida_export get_tinfo2(ea_t ea, tinfo_t *tif);
idaman bool ida_export set_tinfo2(ea_t ea, const tinfo_t *tif);
inline void idaapi del_tinfo2(ea_t ea) { set_tinfo2(ea, NULL); }
//@}

/// \name Operand types
/// These functions may be used if necessary.
//@{
idaman bool ida_export get_op_tinfo2(ea_t ea, int n, tinfo_t *tif);
idaman bool ida_export set_op_tinfo2(ea_t ea, int n, const tinfo_t *tif);
inline void idaapi del_tinfo2(ea_t ea, int n) { set_op_tinfo2(ea, n, NULL); }
//@}

//------------------------------------------------------------------------//
/// \defgroup RIDX_ Rootnode indexes:
//@{

// supvals
#define RIDX_FILE_FORMAT_NAME        1     ///< file format name for loader modules
#define RIDX_SELECTORS               2     ///< 2..63 are for selector_t blob (see init_selectors())
#define RIDX_GROUPS                 64     ///< segment group information (see init_groups())
#define RIDX_H_PATH                 65     ///< C header path
#define RIDX_C_MACROS               66     ///< C predefined macros
#define RIDX_SMALL_IDC_OLD          67     ///< Instant IDC statements (obsolete)
#define RIDX_NOTEPAD                68     ///< notepad blob, occupies 1000 indexes (1MB of text)
#define RIDX_INCLUDE              1100     ///< assembler include file name
#define RIDX_SMALL_IDC            1200     ///< Instant IDC statements, blob
#define RIDX_DUALOP_GRAPH         1300     ///< Graph text representation options
#define RIDX_DUALOP_TEXT          1301     ///< Text text representation options
#define RIDX_MD5                  1302     ///< MD5 of the input file
#define RIDX_IDA_VERSION          1303     ///< version of ida which created the database
#define RIDX_AUTO_PLUGINS         1304     ///< comma separated list of plugins to run
                                           ///< (immediately after opening the database).
                                           ///< if a plugin specified here can not be
                                           ///< loaded, the database can not be opened.
                                           ///< debugger plugins automatically launch debugging.

#define RIDX_STR_ENCODINGS        1305     ///< a list of encodings for the program strings
#define RIDX_SRCDBG_PATHS         1306     ///< source debug paths, occupies 20 indexes
#define RIDX_SELECTED_EXTLANG     1327     ///< last selected extlang name (from the execute script box)
#define RIDX_DBG_BINPATHS         1328     ///< debug binary paths, occupies 20 indexes

// altvals
#define RIDX_ALT_VERSION        uval_t(-1) ///< initial version of database
#define RIDX_ALT_CTIME          uval_t(-2) ///< database creation timestamp
#define RIDX_ALT_ELAPSED        uval_t(-3) ///< seconds database stayed open
#define RIDX_ALT_NOPENS         uval_t(-4) ///< how many times the database is opened
#define RIDX_ALT_CRC32          uval_t(-5) ///< input file crc32
#define RIDX_ALT_IMAGEBASE      uval_t(-6) ///< image base
#define RIDX_ALT_IDSNODE        uval_t(-7) ///< ids modnode id (for import_module)
//@}

//--------------------------------------------------------------------------
/// Get full path of the input file

inline ssize_t idaapi get_input_file_path(char *buf, size_t bufsize)
{
  return RootNode.valstr(buf, bufsize);
}


/// Get file name only of the input file

idaman ssize_t ida_export get_root_filename(char *buf, size_t bufsize);

/// Set full path of the input file

inline void set_root_filename(const char *file) { RootNode.set(file); }


/// Get input file crc32 stored in the database.
/// it can be used to check that the input file has not been changed.

inline uint32 idaapi retrieve_input_file_crc32(void) { return uint32(RootNode.altval(RIDX_ALT_CRC32)); }


/// Get input file md5

inline bool idaapi retrieve_input_file_md5(uchar hash[16]) { return RootNode.supval(RIDX_MD5, hash, 16) == 16; }


/// Get name of the include file

inline ssize_t idaapi get_asm_inc_file(char *buf, size_t bufsize) { return RootNode.supstr(RIDX_INCLUDE, buf, bufsize); }

/// Set name of the include file

inline bool idaapi set_asm_inc_file(const char *file) { return RootNode.supset(RIDX_INCLUDE, file); }


/// Get image base address

inline ea_t idaapi get_imagebase(void) { return RootNode.altval(RIDX_ALT_IMAGEBASE); }

/// Set image base address

inline void idaapi set_imagebase(ea_t base) { RootNode.altset(RIDX_ALT_IMAGEBASE, base); }


/// Get ids modnode

inline netnode idaapi get_ids_modnode(void) { return RootNode.altval(RIDX_ALT_IDSNODE); }

/// Set ids modnode

inline void idaapi set_ids_modnode(netnode id) { RootNode.altset(RIDX_ALT_IDSNODE, id); }


/// Get auto plugins, works with comma separated list of plugins

inline ssize_t idaapi get_auto_plugins(char *buf, size_t bufsize) { return RootNode.supstr(RIDX_AUTO_PLUGINS, buf, bufsize); }

/// Set auto plugins, works with comma separated list of plugins

inline bool idaapi set_auto_plugins(const char *list, size_t listsize=0) { return RootNode.supset(RIDX_AUTO_PLUGINS, list, listsize); }


/// Get debugger input file name/path (see #LFLG_DBG_NOPATH)

inline ssize_t dbg_get_input_path(char *buf, size_t bufsize)
{
  if ( (inf.lflags & LFLG_DBG_NOPATH) != 0 )
    return get_root_filename(buf, bufsize);
  else
    return get_input_file_path(buf, bufsize);
}

//------------------------------------------------------------------------//
/// \name String encodings
/// Encoding names can be a codepage names (CP1251, windows-1251),
/// charset name (Shift-JIS, UTF-8), or just codepage number (866, 932).
/// NB: not all platforms support all encodings
/// user-accessible encodings are counted from 1
/// (index 0 is reserved)
//@{

/// Get total number of encodings (counted from 0)

idaman int          ida_export get_encodings_count();


/// Get encoding name for specific index (1-based).
/// \return NULL if idx is out of bounds

idaman const char * ida_export get_encoding_name(int idx);


/// Add a new encoding (e.g. "utf-8").
/// \return its index (1-based)
/// if it's already in the list, return its index

idaman int          ida_export add_encoding(const char *encoding);


/// Delete an encoding (1-based)

idaman bool         ida_export del_encoding(int idx);


/// Change name for an encoding (1-based)

idaman bool         ida_export change_encoding_name(int idx, const char *encoding);


/// Get default encoding index for a specific string type.
/// 0 means no specific encoding is set - byte values are displayed without conversion.

idaman int          ida_export get_default_encoding_idx(int32 strtype);

/// set default encoding for a string type
/// idx can be 0 to disable encoding conversion

idaman bool         ida_export set_default_encoding_idx(int32 strtype, int idx);


/// Get encoding name for this strtype

inline const char *idaapi encoding_from_strtype(int32 strtype)
{
  uchar enc = get_str_encoding_idx(strtype);
  if ( enc == 0 )
    enc = get_default_encoding_idx(strtype);
  return get_encoding_name(enc); // will return NULL if enc is 0
}
//@}

//------------------------------------------------------------------------//
/// \name Functions to work with imports
//@{

/// Get number of import modules

idaman uint ida_export get_import_module_qty();


/// Get import module name.
/// \retval true   ok
/// \retval false  bad index

idaman bool ida_export get_import_module_name(int mod_index, char *buf, size_t bufsize);


/// Callback for enumerating imports.
/// \param ea     import address
/// \param name   import name (NULL if imported by ordinal)
/// \param ord    import ordinal (0 for imports by name)
/// \param param  user parameter passed to enum_import_names()
/// \retval 1  ok
/// \retval 0  stop enumeration

typedef int idaapi import_enum_cb_t(ea_t ea, const char *name, uval_t ord, void *param);


/// Enumerate imports from specific module.
/// \retval  1     finished ok
/// \retval -1     error
/// \retval other  callback return value (<=0)

idaman int ida_export enum_import_names(int mod_index, import_enum_cb_t *callback, void *param=NULL);
//@}


/// Check consistency of name records, return number of bad ones

idaman int ida_export validate_idb_names();

#ifndef NO_OBSOLETE_FUNCS
#define SWI_SHIFT1      0x80    // use formula (element*2 + elbase)
                                // to find jump targets (obsolete)
NSUP_STRUCT(switch_info,NSUP_SWITCH)
idaman DEPRECATED bool ida_export get_ti(ea_t ea, type_t *buf, size_t bufsize, p_list *fnames, size_t fnsize);
idaman DEPRECATED bool ida_export set_ti(ea_t ea, const type_t *ti, const p_list *fnames); // see apply_type()
inline DEPRECATED void idaapi del_ti(ea_t ea) { del_tinfo2(ea); }
#define typeinfo_t opinfo_t
idaman DEPRECATED bool ida_export get_op_tinfo(ea_t ea, int n, qtype *type, qtype *fnames);
idaman DEPRECATED bool ida_export set_op_tinfo(ea_t ea, int n, const type_t *ti, const p_list *fnames);
inline DEPRECATED void idaapi del_tinfo(ea_t ea, int n) { set_op_tinfo2(ea, n, NULL); }
idaman DEPRECATED bool ida_export get_op_ti(ea_t ea, int n, type_t *buf, size_t bufsize, p_list *fnames, size_t fnsize);
idaman DEPRECATED bool ida_export set_op_ti(ea_t ea, int n, const type_t *ti, const p_list *fnames);
inline DEPRECATED void idaapi del_ti(ea_t ea, int n) { set_op_tinfo2(ea, n, NULL); }
#endif

#ifndef SWIG


//--------------------------------------------------------------------------
/// \name Ignore micro
/// netnode to keep information about various kinds of instructions
//@{
extern netnode ignore_micro;

#define IM_NONE   0     // regular instruction
#define IM_PROLOG 1     // prolog instruction
#define IM_EPILOG 2     // epilog instruction
#define IM_SWITCH 3     // switch instruction

inline void init_ignore_micro(void) { ignore_micro.create("$ ignore micro"); }
inline void term_ignore_micro(void) { ignore_micro = BADNODE; }
inline char get_ignore_micro(ea_t ea) { return ignore_micro.charval(ea, 0); }
inline bool should_ignore_micro(ea_t ea) { return get_ignore_micro(ea) != IM_NONE; }
inline void set_ignore_micro(ea_t ea, uchar im_type) { ignore_micro.charset(ea, im_type, 0); }
inline void clr_ignore_micro(ea_t ea) { ignore_micro.chardel(ea, 0); }
inline void mark_prolog_insn(ea_t ea) { set_ignore_micro(ea, IM_PROLOG); }
inline void mark_epilog_insn(ea_t ea) { set_ignore_micro(ea, IM_EPILOG); }
inline void mark_switch_insn(ea_t ea) { set_ignore_micro(ea, IM_SWITCH); }
inline bool is_prolog_insn(ea_t ea) { return get_ignore_micro(ea) == IM_PROLOG; }
inline bool is_epilog_insn(ea_t ea) { return get_ignore_micro(ea) == IM_EPILOG; }
inline bool is_switch_insn(ea_t ea) { return get_ignore_micro(ea) == IM_SWITCH; }
inline ea_t next_marked_insn(ea_t ea) { return ignore_micro.charnxt(ea, 0); }
//@}
#endif // SWIG



#if !defined(NO_OBSOLETE_FUNCS) || defined(VARLOCS_SOURCE)
idaman DEPRECATED bool ida_export get_tinfo(ea_t ea, qtype *type, qtype *fields); // use get_tinfo2
idaman DEPRECATED bool ida_export set_tinfo(ea_t ea, const type_t *ti, const p_list *fnames); // use set_tinfo2
inline DEPRECATED void idaapi del_tinfo(ea_t ea) { set_tinfo2(ea, NULL); }
#endif

#ifndef BYTES_SOURCE    // undefined bit masks so no one can use them directly
#undef AFL_LINNUM
#undef AFL_USERSP
#undef AFL_PUBNAM
#undef AFL_WEAKNAM
#undef AFL_HIDDEN
#undef AFL_MANUAL
#undef AFL_NOBRD
#undef AFL_ZSTROFF
#undef AFL_BNOT0
#undef AFL_BNOT1
#undef AFL_LIB
#undef AFL_TI
#undef AFL_TI0
#undef AFL_TI1
#undef AFL_LNAME
#undef AFL_TILCMT
#undef AFL_LZERO0
#undef AFL_LZERO1
#undef AFL_COLORED
#undef AFL_TERSESTR
#undef AFL_SIGN0
#undef AFL_SIGN1
#undef AFL_NORET
#undef AFL_FIXEDSPD
#undef NALT_ENUM
#undef NALT_WIDE
#undef NALT_SWITCH
#undef NALT_STRUCT
#undef NALT_XREFPOS
#undef NALT_AFLAGS
#undef NALT_LINNUM
#undef NALT_ABSBASE
#undef NALT_ENUM0
#undef NALT_ENUM1
#undef NALT_PURGE
#undef NALT_STRTYPE
#undef NALT_ALIGN
#undef NALT_COLOR
#undef NSUP_CMT
#undef NSUP_REPCMT
#undef NSUP_FOP1
#undef NSUP_FOP2
#undef NSUP_JINFO
#undef NSUP_ARRAY
#undef NSUP_OMFGRP
#undef NSUP_FOP3
#undef NSUP_SWITCH
#undef NSUP_REF0
#undef NSUP_REF1
#undef NSUP_REF2
#undef NSUP_OREF0
#undef NSUP_OREF1
#undef NSUP_OREF2
#undef NSUP_STROFF0
#undef NSUP_STROFF1
#undef NSUP_SEGTRANS
#undef NSUP_FOP4
#undef NSUP_FOP5
#undef NSUP_FOP6
#undef NSUP_REF3
#undef NSUP_REF4
#undef NSUP_REF5
#undef NSUP_OREF3
#undef NSUP_OREF4
#undef NSUP_OREF5
#undef NSUP_MANUAL
#undef NSUP_FTAILS
#undef NSUP_GROUP
#endif

#pragma pack(pop)
#endif // NALT_HPP
