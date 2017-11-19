#ifndef _NPOOLUTI_HPP_
#define _NPOOLUTI_HPP_
#include "upgrade.hpp"
#include "resword.hpp"

extern uint32 errload;
void load_msg(const char *format, ...) AS_PRINTF(1, 2);
const char *mk_diag(uchar mode, char str[128]);
void BadRef(ea_t ea, const char *to, ushort id, uchar mode);
void mark_access(ea_t ea, ushort acc);

extern ushort *tsPtr;
extern uchar  *smBuf, *annBuf;

void  *myAlloc(uint size);
uchar *sm_realloc(uint size);
uchar *annotation_realloc(uint size);
bool  getblob(uval_t ind, void *p, uval_t sz);
uchar set_parent_object(void);

extern uint32 FileSize;
uint32 read4(void);
ushort read2(void);
uchar  read1(void);
void readData(void *data, uint32 size);
void skipData(uint32 size);
NORETURN void errtrunc(void);

uchar LoadUtf8(ushort index, const_desc_t *co);
void  Parser(ushort index, const_desc_t *co);
extern uchar loadMode;

//-----------------------------------------------------------------------
static inline void StoreOpis(uint index, const const_desc_t &opis)
{
  ConstantNode.supset(index, &opis, sizeof(opis));
}

//-----------------------------------------------------------------------------
void xtrnSet(uint cin, const_desc_t *co, uint xip,
             char *str, size_t strsize, bool full, uchar rmod=3);
void SetName(ushort name, ea_t ea, ushort access, uval_t number, uchar rmod=3);
void set_lv_name(ushort name, ea_t ea, uchar rmod=3);
void xtrnRef(ea_t ea, const const_desc_t &opis);
void xtrnRef_dscr(ea_t ea, const_desc_t *opis, uchar met=0);

void deltry(uint bg, uint ic, uint ui, const const_desc_t &pco);
segment_t *_add_seg(int caller);
void resizeLocVars(void);

//-----------------------------------------------------------------------------
#define ARQ_CODE    0
#define ARQ_FIELD   1
#define ARQ_METHOD  2
#define ARQ_FILE    3
#define ARQ_CHECK   4
const char *CopyAttrToFile(const char *astr, uint32 size, ushort id);

//-----------------------------------------------------------------------------
extern char *_spcnamechar;
void make_NameChars(uchar on_load);

//------------------
static void inline endLoad_NameChar(void)
{
  _spcnamechar[2] = '\0';     // end load base (remove '()')
}

//------------------
static void inline enableExt_NameChar(void)
{
  *_spcnamechar = '.';  //j_field_dlm;  // (for searches)
}

//------------------
static void inline disableExt_NameChar(void)
{
  *_spcnamechar = '\0';
}

//-----------------------------------------------------------------------
struct _STROP_
{
  ushort size;
  ushort flags;
};

// new flags at VER15
#define _OP_NOSIGN    0x0001  // not signature (always +_OP_NODSCR)
#define _OP_METSIGN   0x0002  // method signature: <:>(...)ret
#define _OP_CLSSIGN   0x0004  // class signature:  <:>super{iface}
//#define _OP_          0x0008
//#define _OP_          0x0010
#define _OP_JSMRES_   0x0020  // name reserved in jasmin (asm support)
// end of new flags
#define _OP_ONECLS    0x0040  // descriptor has class reference
#define _OP_FULLNM    0x0080  // field have '.', '/' or [ => no FM name
#define _OP_NOFNM     0x0100  // can only descriptor. Not name
#define _OP_VALPOS    0x0200  // has posit for call descriptor
#define _OP_NODSCR    0x0400  // not descriptor
//#define _OP_NULL_     0x0800  // has simbols 0
//#define _OP_NAT0_     0x1000  // has simbols disabled in Xlat-table
//#define _OP_WIDE_     0x2000  // has simbols >= 0x100
#define _OP_BADFIRST  0x1000  // first char in string is badStart for ident
#define _OP_UNICHARS  0x2000  // have valid unicode characters
#define _OP_UTF8_     0x4000  //  Utf8 String
#define _OP_EXTSYM_   0x8000    // contain (!qisprint(english) && !isJavaIdent())
// ver12 bits
//#define _OP_UNICODE_  0x8000  //  Unicode String  (removed? from standard)
//for jasmin reserved words checking
#define _OP_NOWORD  uint32(0xFFFF & ~(_OP_NOSIGN|_OP_ONECLS|_OP_NODSCR|_OP_UTF8_))

// low bits used as temporary in VER12
         // _OP_NULL_ | _OP_NAT0_ | _OP_WIDE_

CASSERT((UPG12_EXTMASK >> 16) == 0x7000
     && (UPG12_CLRMASK >> 16) == 0xF03F
     && (UPG12_BADMASK >> 16) == 0x8000
     && (UPG12_EXTSET  >> 16) == _OP_EXTSYM_);

//-----------------------------------------------------------------------------
#endif
