#ifndef __ELF_H__
#define __ELF_H__

#include <map>

#include <diskio.hpp>
#include <fixup.hpp>

#pragma pack(push, 4)

// gcc does not allow to initialize indexless arrays for some reason
// put an arbitrary number here. the same with visual c++
#if defined(__GNUC__) || defined(_MSC_VER)
#define MAXRELSYMS 64
#else
#define MAXRELSYMS
#endif

typedef Elf64_Shdr elf_shdr_t;
typedef Elf64_Phdr elf_phdr_t;
struct elf_sym_t: public Elf64_Sym
{
  elf_sym_t()
  {
    st_name  = 0;
    st_info  = 0;
    st_other = 0;
    st_shndx = 0;
    st_value = 0;
    st_size  = 0;
  }
};
typedef Elf64_Dyn  elf_dyn_t;
typedef Elf64_Rel  elf_rel_t;
typedef Elf64_Rela elf_rela_t;

class reader_t;
struct sym_rel;
typedef uint32 elf_sym_idx_t;

typedef uint32 elf_shndx_t;
typedef qvector<elf_shdr_t> elf_shdrs_t;
typedef qvector<elf_phdr_t> elf_phdrs_t;

//----------------------------------------------------------------------------
struct elf_ehdr_t : public Elf64_Ehdr
{
  elf_shndx_t real_shnum;     // number of entries in the SHT
                              // (may be greater than 0xFF00)
  elf_shndx_t real_shstrndx;  // section name string table section index
                              // (may be greater than 0xFF00)

  bool has_pht() const { return e_phoff != 0; }
  void set_no_pht()
  {
    e_phoff = 0;
    e_phnum = 0;
  }

  bool has_sht() const { return e_shoff != 0; }
  void set_no_sht()
  {
    e_shoff = 0;
    e_shnum = 0;
    real_shnum = 0;
  }
  bool is_valid_shndx(elf_shndx_t idx) const
  {
    return idx < real_shnum;
  }

  bool has_shstrtab() const { return real_shstrndx != 0; }
};

//----------------------------------------------------------------------------
// rel_data_t holds whatever relocation information appears to be common
// to most ELF relocation "algorithms", as defined in the per-CPU
// addenda.
// Note: Most comments below were picked from the abi386.pdf file.
struct rel_data_t
{
  // Relocation type: R_<processor>_<reloc-type>.
  uint32 type;

  // abi386.pdf: This means the place (section offset or address) of
  // the storage unit being relocated (computed using r_offset).
  ea_t   P;

  // abi386.pdf: This means the value of the symbol whose index
  // resides in the relocation entry.
  uval_t S;

  // S, plus addend
  ea_t Sadd;

  // Whether the 'reloc' parameter passed to 'proc_rel()'
  // is a REL, or a RELA (the actual reloc entry object
  // itself will always be a elf_rela_t instance).
  enum rel_entry_t
  {
    re_rel,
    re_rela
  };
  rel_entry_t rel_entry;
  bool is_rel() const { return rel_entry == re_rel; }
  bool is_rela() const { return !is_rel(); }
};


//--------------------------------------------------------------------------
enum slice_type_t
{
  SLT_INVALID = 0,
  SLT_SYMTAB  = 1,
  SLT_DYNSYM  = 2,
  SLT_WHOLE   = 3,
};
struct symrel_idx_t
{
  symrel_idx_t() : type(SLT_INVALID), idx(0) {}
  symrel_idx_t(slice_type_t t, elf_sym_idx_t i) : type(t), idx(i) {}

  slice_type_t type;
  elf_sym_idx_t idx;

  bool operator==(const symrel_idx_t &other) const
  {
    return other.type == type
        && other.idx  == idx;
  }
  bool operator<(const symrel_idx_t &other) const
  {
    return type < other.type ? true:
           type > other.type ? false:
           idx < other.idx;
  }
};

//----------------------------------------------------------------------------
struct got_access_t
{
  // the name _GLOBAL_OFFSET_TABLE_
  static const char gtb_name[];

  // is the given symbol the _GLOBAL_OFFSET_TABLE_?
  static bool is_symbol_got(const sym_rel &sym, const char *name);

  got_access_t()
    : start_ea(0) {}

  // Get the start address of the GOT.
  // If no GOT currently exists, and 'create' is true, one will
  // be created in a segment called ".got".
  // If no GOT exists or an error occurred while creating .got segment,
  // the function returns 0.
  ea_t get_start_ea(reader_t &reader, bool create = false);

  //
  void set_start_ea(ea_t ea) { start_ea = ea; }

  // get .got segment using the storage of well-known sections.
  // If it didn't exist and the flag `create' is set then create an empty
  // ".got" segment with the given initial size.
  // Set the flag `create' if such segment is just created.
  // If .got segment doesn't exist or an error occurred while creating it,
  // the function returns NULL.
  segment_t *get_got_segment(
          reader_t &reader,
          bool *create,
          uint32 init_size = 0) const;

  // Some relocations, such as ARM's R_ARM_TLS_IE32, require that a got entry
  // be present in the linked file, in order to point to that entry.
  // However, when we are loading a simple relocatable ELF object file,
  // there's no GOT present. This is problematic because,
  // although we _could_ be taking a shortcut and patch the fixup to refer
  // to the extern:__variable directly, it is semantically different.
  // As as example, when we meet:
  //   LDR    R3, #00000000                     ; R_ARM_TLS_IE32; Offset in GOT to __libc_errno
  // generating:
  //   LDR    R3, [__libc_errno_tls_offset]
  // is not the same as:
  //   LDR    R3, [address, in got, of libc_errno_tls_offset]
  //
  // This is obviously the last formatting that's correct, as we don't
  // even *know* what the address of __libc_errno_tls_offset is; we just
  // know where to go and look for it.
  //
  // The solution is to create a .got section anyway, and allocate an entry
  // in there with the name of the symbol, suffixed with '_tpoff'.
  //
  // - reader  : The elf reader.
  // - sym     : The symbol. We create the one entry for each symbol of
  //             each GOT-type.
  // - suffix  : A suffix, to be added to the symbol name. We consider
  //             the suffix as a GOT-type of the entry. It is sometimes
  //             necessary to create multiple entries for the symbol.
  //             E.g., '_tpoff', '_ptr', ...
  // - created : The flag indicating the allocation of the new entry.
  // - n       : The number of allocated entries.
  // - returns : An address in the .got segment.
  //             0 is returned in the case of error.
  ea_t allocate_entry(
        reader_t &reader,
        const sym_rel &sym,
        const char *suffix,
        bool *created = NULL,
        uval_t n = 1);

  //
  // Get the ea in the GOT section, corresponding
  // the the 'A' addend.
  //
  // * If the file already had a GOT section, then
  //   the returned ea is simply got_segment->start_ea + A.
  // * On the other hand, if this file had no GOT
  //   this calls #allocate_got_entry().
  //
  // - reader  : The elf reader
  // - A       : The 'addend' (i.e., displacement) in the GOT.
  //             Ignored if the original file had *no* GOT.
  // - sym     : The symbol.
  //             Ignored if the original file *did* have a GOT.
  // - suffix  : A suffix, to be added to the symbol name. E.g., '_tpoff', '_ptr', ...
  //             Ignored if the original file *did* have a GOT.
  //
  // - returns : An address in the GOT segment, possibly creating one.
  //             0 is returned in the case of error.
  ea_t get_or_allocate_entry(
        reader_t &reader,
        uval_t A,
        const sym_rel &sym,
        const char *suffix);

private:
  ea_t start_ea;
  // used only when original file has no GOT.
  // an unique id of the symbol's GOT entry
  struct symrel_id_t
  {
    symrel_idx_t idx;   // symbol
    const char *suffix; // subtype of the GOT-entry
    symrel_id_t(symrel_idx_t idx_, const char *suffix_)
      : idx(idx_), suffix(suffix_) {}
    bool operator<(const symrel_id_t &rhs) const
    {
      return idx < rhs.idx ? true:
             !(idx == rhs.idx) ? false:
             strcmp(suffix, rhs.suffix) < 0;
    }
  };
  std::map<symrel_id_t,ea_t> allocated_entries;
};


//----------------------------------------------------------------------------
struct dynamic_info_t;
struct reloc_tools_t
{
  // dynamic information
  const dynamic_info_t *di;
  // GOT accessor/creator.
  got_access_t got;

  reloc_tools_t(const dynamic_info_t *di_)
    : di(di_),
      got() {}
};

//--------------------------------------------------------------------------
// GOT support for the relocatable files
// index of the _GLOBAL_OFFSET_TABLE_ symbol
extern symrel_idx_t got_sym_idx;
// allocate GOT-entry and return it in `got_entry_ea'
bool process_GOT(
        ea_t *got_ea,
        ea_t *got_entry_ea,
        reader_t &reader,
        ea_t P,
        ea_t S,
        adiff_t A,
        const sym_rel *symbol,  // not NULL
        reloc_tools_t *tools);

//--------------------------------------------------------------------------
namespace tls_relocs_t
{
  // generic TLS relocs
  enum type_t
  {
    BAD,
    NTPOFF,   // @ntpoff(x) (x86) or @tpoff(x) (x64), calculates the
              // negative TLS offset relative to the TLS block end.
    DTPOFF,   // @dtpoff(x), calculates the TLS offset relative to the
              // TLS block.
    PTPOFF,   // $x@tpoff (x86 only), calculates the _positive_ TLS
              // offset relative to the TLS block end.
    DTPMOD,   // @dtpmod(x), calculates the object identifier of the
              // object containing a TLS symbol.
    GOTGD,    // @tlsgd(x) (x86) or @tlsgd(%rip) (x64), allocates two
              // contiguous entries in the GOT to hold a `tls_index'
              // structure, uses the offset of the first entry.
    GOTLD,    // @tlsldm(x) (x86) or @tlsld(%rip) (x64), allocates two
              // contiguous entries in the GOT to hold a `tls_index'
              // structure, uses the offset of the first entry. The
              // `ti_tlsoffset' field of the `tls_index' is set to 0.
    GOTIE,    // @gotntpoff(x) (x86) or @gottpoff(%rip) (x64), allocates
              // an entry in the GOT, uses the offset of this entry. The
              // entry holds a variable offset in the initial TLS block.
              // This negative offset is relative to the TLS blocks end.
    GOTIEA,   // @indntpoff(x) (x86), like GOTIE but uses the absolute
              // GOT slot address.
    GOTIEP,   // @tpoff(x) (x86 only), allocates an entry in the GOT,
              // uses the offset of this entry. The entry holds a
              // variable offset in the initial TLS block. This
              // _positive_ offset is relative to the TLS blocks end.
  };
};
bool process_TLS(
        tls_relocs_t::type_t type,  // NTPOFF, DTPOFF, PTPOFF, DTPMOD
        bool is64,
        reader_t &reader,
        ea_t P,
        ea_t S,
        adiff_t A,
        const sym_rel *symbol); // NULL - the zero symbol
// allocate GOT-entry and return it in `got_entry_ea'
bool process_TLS_GOT(
        ea_t *got_ea,
        ea_t *got_entry_ea,
        tls_relocs_t::type_t type,  // GOT...
        reader_t &reader,
        ea_t P,
        ea_t S,
        adiff_t A,
        const sym_rel *symbol,
        reloc_tools_t *tools);
// get fixup for PTPOFF generic TLS reloc,
// it returns FIXUP_CUSTOM if this reloc isn't supported
fixup_type_t get_ptpoff_reltype();

//--------------------------------------------------------------------------
struct proc_def_t
{
#define E_RELOC_PATCHING  (const char *)1
#define E_RELOC_UNKNOWN   (const char *)2
#define E_RELOC_UNIMPL    (const char *)3
#define E_RELOC_UNTESTED  (const char *)4
#define E_RELOC_NOSYM     (const char *)5
#define E_RELOC_LAST      (const char *)6
  ea_t _UNUSED1_gtb_ea;
  // Relocator function.
  // Note: symbol might be NULL
  const char *(*proc_rel)(
        reader_t &reader,
        const rel_data_t &rel_data,
        const sym_rel *symbol,
        const elf_rela_t *reloc,
        reloc_tools_t *tools);
  // Patcher function
  // There are 4 passes distinguishable by function args plt, gotps:
  // 0. ELF_BUG_GOT     got, got
  // 1. ELF_RPL_PTEST   plt, NULL - check ".plt" section
  // 2. pass 2          plt, gotplt
  // 3. ELF_RPL_GL      NULL, segment_t *
  size_t (*proc_patch)(
        reader_t &reader,
        const elf_shdr_t *plt,
        const void *gotps,
        reloc_tools_t *tools);
  const char * (*proc_flag)(reader_t &reader, uint32 &e_flags);
  const char *stubname;
  // called for processor-specific section types
  int (*proc_sec_ext)(reader_t &reader, Elf64_Shdr *sh);
  int (*proc_sym_ext)(reader_t &reader, sym_rel *st, const char *name);
  // called for each dynamic tag. It returns NULL to continue with a
  // standard tag processing, or "" to finish tag processing, or the
  // description of the tag to show.
  const char * (*proc_dyn_ext)(reader_t &reader, const Elf64_Dyn *dyn);
  bool (*proc_file_ext)(reader_t &reader, ushort filetype);
  // called after header loading (before load_pht/load_simage)
  void (*proc_start_ext)(reader_t &reader, elf_ehdr_t &header);
  bool (*proc_post_process)(reader_t &reader);

  int (*proc_sym_init)(reader_t &reader);
  enum sym_handling_t
  {
    normal = 0,
    skip
  };
  sym_handling_t (*proc_sym_handle) (reader_t &reader,
                                     sym_rel &sym,
                                     const char *symname);
  ushort patch_mode;
  uint32 r_drop;
  uint32 r_gotset;      // relocation type: GOT
  uint32 r_err;         // relocation type: usually R_xxx_JUMP_SLOT
  uint32 r_chk;         // relocation type: usually R_xxx_GLOB_DAT
  uint32 relsyms[MAXRELSYMS]; // relocation types which must be to loaded symbols

  // called from a function should_load_segment for _every_ section.
  // It returns 'false' to skip loading of the given section.
  bool (*proc_sect_check) (reader_t &reader,
                           const elf_shdr_t &sh,
                           elf_shndx_t idx,
                           const qstring &name);
  // called before the segment creation. It may set <sa> to the ea at
  // which a given section should be loaded. In the other case the
  // default segment ea computation is used. Also it may return 'false'
  // to skip creation of a segment for this section.
  bool (*proc_sect_handle) (reader_t &reader,
                            const elf_shdr_t &sh,
                            const qstring &name,
                            ea_t &sa);
  const char * (*calc_procname) (uint32 *e_flags, reader_t &reader, const char *procname);

  // order in which relocations should be applied. A name denotes a section
  // to which we are applying relocations. NULL means all other sections.
  enum { MAXRELORDERS = 5 };
  const char *relsecord[MAXRELORDERS];

  // for some 64-bit architectures e_entry holds not a real entry point
  // but a function descriptor
  // E.g. 64-bit PowerPC ELF Application Binary Interface Supplement 1.9
  // section 4.1. ELF Header
  // "The e_entry field in the ELF header holds the address of a function
  // descriptor. This function descriptor supplies both the address of the
  // function entry point and the initial value of the TOC pointer
  // register."
  // this callback should translate this address to the real entry.
  ea_t (*proc_entry_handle) (const reader_t &reader, ea_t entry);

  // types of supported special segments
  enum spec_type_t
  {
    SPEC_XTRN,
    SPEC_COMM,
    SPEC_ABS,
    SPEC_TLS,
    NSPEC_SEGMS
  };
  // additional reserved indexes of special segments (see MIPS)
  uint16 additional_spec_secidx[NSPEC_SEGMS];

  // TLS support of the static access model (0 - no static model)
  // TP - static thread pointer, TCB - thread control block
  // variant I (if tls_tcb_size < 0):
  // +---+---+-----------------------
  // |TCB|xxx|
  // +---+---+-----------------------
  // ^ TP    ^ TLS offset of modules
  // variant 2 (if tls_tcb_size > 0):
  // +----------------------+---+---+
  // |                      |xxx|TCB|
  // +----------------------+---+---+
  // ^ TLS offset of modules    ^ TP
  int tls_tcb_size;
  int tls_tcb_align;  // if bit 0 set then store TP at the start of TCB

  // the sequence of callbacks during the call of elf_load_file()
  // proc_file_ext
  // proc_start_ext
  //   proc_sect_check*   (for each section before load)
  //   proc_sec_ext*      (for each section with unknown type)
  //   proc_sect_handle*  (for each section before defining segment)
  // proc_dyn_ext*        (for each dynamic tag)
  // proc_flag*           (for each flag from header.e_flags)
  // proc_sym_init*       (for each symbol table)
  //   proc_sym_ext*      (for each symbol from unknown section)
  //   proc_sym_handle*   (for each symbol)
  // proc_rel*            (for each relocation)
  // proc_patch*          (up to 4 times, see above)
  // proc_entry_handle*   (for init_ea, fini_ea, header.e_entry)
  // proc_post_process

  bool in_relsyms(uint32 r_type)
  {
    for ( int i=0; i < MAXRELSYMS; ++i )
    {
      if ( relsyms[i] == 0 )
        break;
      if ( relsyms[i] == r_type )
        return true;
    }
    return false;
  }

  bool section_in_relsecord(const qstring &name)
  {
    for ( int i = 0; i < MAXRELORDERS; ++i )
    {
      if ( relsecord[i] == NULL )
        return false;
      if ( name == relsecord[i] )
        return true;
    }
    return false;
  }
};
//----------------------------------------------------------------------------
// skip sections without flags like .comment/.debug/.line
bool std_sect_check(
        reader_t &reader,
        const elf_shdr_t &sh,
        elf_shndx_t idx,
        const qstring &name);

//----------------------------------------------------------------------------
// create a new segment where a previous segment ended (at the top).
// Allocate new selector for the new segment. If the flag use_cursel is
// set then use currently allocated segment selector and allocate a new
// one after creation.
segment_t *create_segment_at_top(
        const reader_t &reader,
        uchar type,
        const char *name,
        asize_t size,
        uchar align,
        bool use_cursel = false);
// for the relocation object file calculate a start address of the
// segment where previous segment ended (at the top). For executable or
// shared objects this function returns the address from <sh>.
ea_t get_default_segment_ea(const reader_t &reader, const elf_shdr_t &sh);

//----------------------------------------------------------------------------
struct sym_rel;
class symrel_cache_t
{
public:

  symrel_cache_t()
    : storage(),
      dynsym_index(0) {}

  static void check_type(slice_type_t t)
  {
    QASSERT(20098, t > SLT_INVALID && t <= SLT_WHOLE);
  }

  elf_sym_idx_t slice_size(slice_type_t t) const { return elf_sym_idx_t(slice_end(t) - slice_start(t)); }
  const sym_rel &get(slice_type_t t, elf_sym_idx_t idx) const { return storage[slice_start(t) + idx]; }
  sym_rel &get(slice_type_t t, elf_sym_idx_t idx) { return storage[slice_start(t) + idx]; }
  sym_rel &append(slice_type_t t);

  void qclear(uint64 room)
  {
    // the number in the section header may be too big (see
    // pc_bad_nyms_elf.elf) so we limit it
    if ( room > 65536 )
      room = 65536;
    storage.qclear();
    storage.reserve(room);
  }

  symrel_idx_t get_idx(const sym_rel *symbol) const;

  // this method is used in pattern/pelf.cpp
  struct ptr_t : public symrel_idx_t
  {
    ptr_t() : symrel_idx_t(), symbols(NULL) {}
    ptr_t(symrel_cache_t *s, symrel_idx_t i)
      : symrel_idx_t(i),
        symbols(s) {}
    symrel_cache_t *symbols;
    sym_rel &deref() const { return symbols->get(type, idx); }
  };
  ptr_t get_ptr(const sym_rel &sym)
  {
    return ptr_t(this, get_idx(&sym));
  }

private:
  qvector<sym_rel> storage;
  size_t dynsym_index;
  size_t slice_start(slice_type_t t) const;
  size_t slice_end(slice_type_t t) const;
};

//--------------------------------------------------------------------------
// relocation speed
struct sym_rel
{
  mutable char *original_name;
  char *name;           // temporary for NOTYPE only
  elf_sym_t original;
  uint64 size;
  uval_t value;         // absolute value or addr
  elf_shndx_t sec;      // index of the section to which this symbol
                        // applies. For special sections it is 0 (see
                        // original.st_shndx).
  uchar bind;           // binding
  char type;            // type (-1 - not defined,
                        // -2 UNDEF SYMTAB symbol which probably is
                        //    the same as the DYNSYM symbol,
                        // -3 to add an additional comment to relocs to
                        //    unloaded symbols)
  uchar flags;

  sym_rel()
  : original_name(NULL),
    name(NULL),
    original(),
    size(0),
    value(0),
    sec(0),
    bind(0),
    type(0),
    flags(0) {}

  ~sym_rel()
  {
    clear_name();
    if ( original_name != NULL )
      qfree(original_name);
  }

  sym_rel(const sym_rel &r)
  {
    memcpy(this, &r, sizeof(r));
    if ( name != NULL )
      name = qstrdup(name);
    if ( original_name != NULL )
      original_name = qstrdup(original_name);
  }

  sym_rel &operator=(const sym_rel &r)
  {
    if ( this == &r )
      return *this;
    this->~sym_rel();
    new (this) sym_rel(r);
    return *this;
  }

  void swap(sym_rel &r)
  {
    qswap(*this, r);
  }

  void clear_name()
  {
    if ( name != NULL )
    {
      qfree(name);
      name = NULL;
    }
  }

  void set_section_index(const reader_t &reader);
  bool defined_in_special_section() const
  {
    CASSERT(SHN_HIRESERVE == 0xFFFF);
    // assert: original.st_shndx <= SHN_HIRESERVE
    return sec == 0 && original.st_shndx >= SHN_LORESERVE;
  }
  // for debug purpose
  const char *get_section_str(char *buf, size_t bufsize) const
  {
    if ( defined_in_special_section() )
      qsnprintf(buf, bufsize, "%04X", uint(original.st_shndx));
    else
      qsnprintf(buf, bufsize, "%u", sec);
    return buf;
  }

  bool overlaps(elf_shndx_t section_index, uint64 offset) const
  {
    return sec == section_index
        && offset >= value
        && offset <  value + size;
  }

  void set_name(const qstring &n)
  {
    set_name(n.c_str());
  }

  void set_name(const char *n)
  {
    clear_name();
    if ( n != NULL && n[0] != '\0' )
      name = qstrdup(n);
    else
      name = NULL;
  }

  ea_t get_ea(const reader_t &reader, ea_t _debug_segbase=0) const;

  const char *get_original_name(reader_t &reader) const;

  void set_flag(uchar flag) { flags |= flag; }
  bool has_flag(uchar flag) const { return (flags & flag) != 0; }
  void clr_flag(uchar flag) { flags &= ~flag; }
};
DECLARE_TYPE_AS_MOVABLE(sym_rel);

//--------------------------------------------------------------------------
inline symrel_idx_t symrel_cache_t::get_idx(const sym_rel *symbol) const
{
  qvector<sym_rel>::const_iterator beg = storage.begin();
  if ( symbol == NULL || symbol < beg || symbol > storage.end() )
    return symrel_idx_t();
  size_t idx = symbol - beg;
  if ( idx < dynsym_index )
    return symrel_idx_t(SLT_SYMTAB, elf_sym_idx_t(idx));
  else
    return symrel_idx_t(SLT_DYNSYM, elf_sym_idx_t(idx - dynsym_index));
}

//--------------------------------------------------------------------------
// ids-loading
struct implib_name
{
  char        *name;
  implib_name *prev;
};

//----------------------------------------------------------------------------
void idaapi set_reloc(
        const reader_t &reader,
        ea_t P,                  // The ea of the data to be modified.
        ea_t target_ea,          // The ea that the instruction would point to,
                                 // if it were interpreted by the CPU.
        uval_t patch_data,       // The data to be inserted at 'P'. Depending on whether
                                 // 'type' is a 64-bit fixup type or not, either the
                                 // first 32-bits, or the full 64 bits of 'data' will be
                                 // put in the database. Of course, this patch data
                                 // must hold the possible instruction bits, if they
                                 // are interleaved w/ the address data
                                 // (e.g., R_ARM_THM_MOVW_ABS_NC, ...).
        adiff_t displ,
        fixup_type_t type,       // The type of the relocation, see fixup.hpp's FIXUP_*.
                                 // It may be standard or custom.
        uval_t offbase = 0,      // base of the relative fixup
        uint32 flags = 0,        // The flags of the relocation, see fixup.hpp's FIXUPF_*.
                                 // You can specify additional flags:
#define FIXUPF_ELF_DO_NOT_PATCH 0x80000000 // do not patch at all
#define FIXUPF_ELF_FIXUP_PATCH  0x40000000 // do not use patch_data, patch
                                           // using patch_fixup_value()
#define FIXUPF_ELF_DISPLACEMENT 0x20000000 // set displacement flag
                                           // (even rel_mode == 1)
#define FIXUPF_ELF_SET_RELATIVE 0x10000000 // set fixup base
                                           // (even offbase == 0)
        adiff_t fixup_offset=0); // offset of the fixup relative to P

//----------------------------------------------------------------------------
// this function patch the relocatable field using patch_fixup_value()
// and store the fixup.
// It set the displacement taking in account the addend, the fact that
// the symbol is external or it is a section.
// It uses static variables `rel_mode' and `prgend'.
void set_reloc_fixup(
        const reader_t &reader,
        ea_t P,                    // ea of the reloc
        ea_t S,                    // symbol of the reloc
        adiff_t A,                 // addend of the reloc
        fixup_type_t type,         // type of the fixup to store (see set_reloc().type)
        bool do_not_patch = false, // do not patch at all
        uval_t offbase = 0,        // base of the relative fixup
        adiff_t fixup_offset = 0); // offset of the fixup relative to P

void set_reloc_cmt(ea_t ea, int cmt);
#define RCM_PIC   0
#define RCM_ATT   1
#define RCM_COPY  2
#define RCM_TLS   3
#define RCM_IREL  4
void set_thunk_name(
        ea_t ea,
        ea_t name_ea,
        const char *prefix = ".",
        const char *postfix = "");
void overflow(ea_t fixaddr, ea_t ea);
void handle_mips_dsym(reader_t &reader, const sym_rel &symrel, elf_sym_idx_t isym, const char *name);

#define CASE_NAME(n) case n: return # n
const char *get_reloc_name(const reader_t &reader, int type);

// FIXME this is wrong! it will be replaced by process_TLS()
// It is assumed the 'in_out_offset' is relative to the start of
// the TLS block at runtime. Since those blocks have the following layout:
// +---------------+
// |               |
// |     .tdata    |
// |               |
// +---------------+
// |               |
// |     .tbss     |
// |               |
// +---------------+
// we'll associate 'in_out_offset' to either the '.tdata' segment,
// or the '.tbss' one, depending on whether it overflows
// .tdata or not.
//
// As a side-effect, note that the value pointed to by 'in_out_offset' will
// be different after this function returns, in case it lands into '.tbss'.
// (it will be: in_out_offset_after = in_out_offset - segment_size(".tdata"))
ea_t get_tls_ea_by_offset(uint32 *in_out_offset);
ea_t unwide_ea(ea_t ea, const char *diagn);
void parse_attributes(reader_t &reader, uint32 offset, size_t size);
int  elf_machine_2_proc_module_id(reader_t &reader);

//--------------------------------------------------------------------------
extern proc_def_t elf_alpha;
extern proc_def_t elf_arc;
extern proc_def_t elf_arcompact;
extern proc_def_t elf_arm;
extern proc_def_t elf_aarch64;
extern proc_def_t elf_avr;
extern proc_def_t elf_c166;
extern proc_def_t elf_fr;
extern proc_def_t elf_h8;
extern proc_def_t elf_hp;
extern proc_def_t elf_i960;
extern proc_def_t elf_ia64;
extern proc_def_t elf_m16c;
extern proc_def_t elf_m32r;
extern proc_def_t elf_m68k;
extern proc_def_t elf_mc12;
extern proc_def_t elf_mips;
extern proc_def_t elf_mn10200;
extern proc_def_t elf_mn10300;
extern proc_def_t elf_pc;
extern proc_def_t elf_ppc;
extern proc_def_t elf_ppc64;
extern proc_def_t elf_sh;
extern proc_def_t elf_sparc;
extern proc_def_t elf_st9;
extern proc_def_t elf_v850;
extern proc_def_t elf_x64;
extern proc_def_t elf_tricore;

//--------------------------------------------------------------------------
extern boolvec_t sh_overlaps;

//--------------------------------------------------------------------------
extern bool unpatched;
extern ea_t prgend;
extern uval_t debug_segbase;
extern char rel_mode;   // 1 - STT_SECTION
                        // 0 - !STT_SECTION
                        //-1 - STT_NOTYPE or undefined

// user parameters. these definitions and the input form are interdependent
// if you change the 'dialog_form' string, change these definitions too!
// Also note the environment variable IDA_ELF_PATCH_MODE in hints-files!
#define ELF_USE_PHT   0x0001 // Force using of PHT instead of SHT;
                             // this is a copy of the `use_pht' flag;
                             // this bit may be set in IDA_ELF_PATCH_MODE;
#define ELF_RPL_PLP   0x0002 // Replace PIC form of 'Procedure Linkage Table' to non PIC form
#define ELF_RPL_PLD   0x0004 // Direct jumping from PLT (without GOT) irrespective of its form
#define ELF_RPL_GL    0x0008 // Convert PIC form of loading '_GLOBAL_OFFSET_TABLE_[]' of address
#define ELF_RPL_UNL   0x0010 // Obliterate auxiliary bytes in PLT & GOT for 'final autoanalysis'
#define ELF_RPL_GOTX  0x0020 // Convert PIC form of name@GOT
#define ELF_AT_LIB    0x0040 // Mark 'allocated' objects as library-objects (MIPS only)
#define ELF_BUG_GOT   0x0080 // Force conversion of all GOT entries to offsets
#define ELF_LD_CHNK   0x0100 // Load huge segments by chunks
#define ELF_BS_DBG    0x0200 // Create base for debugging
#define ELF_FORM_MASK 0x0FFF // Mask for 'dialog_form' options

// noform bits
#define ELF_DIS_GPLT  0x4000 // disable search got reference in plt
#define ELF_DIS_OFFW  0x8000 // can present offset bypass segment's

#define ELF_RPL_PTEST  (ELF_RPL_PLP | ELF_RPL_PLD | ELF_RPL_UNL)

#define FLAGS_CMT(bit, text)  if ( e_flags & bit )  \
                              {                     \
                                e_flags &= ~bit;    \
                                return text;        \
                              }

//--------------------------------------------------------------------------
inline uval_t make64(uval_t oldval, uval_t newval, uval_t mask)
{
  return (oldval & ~mask) | (newval & mask);
}

//--------------------------------------------------------------------------
inline uint32 make32(uint32 oldval, uint32 newval, uint32 mask)
{
  return (oldval & ~mask) | (newval & mask);
}

#define MASK(x) ((uval_t(1) << x) - 1)

const uval_t M32 = uint32(-1);
const uval_t M24 = MASK(24);
const uval_t M16 = MASK(16);
const uval_t M8  = MASK(8);

inline uval_t extend_sign(uval_t value, uint bits)
{
  uval_t mask = make_mask<uval_t>(bits);
  return (value & left_shift<uval_t>(1, bits-1)) != 0
       ? value | ~mask
       : value & mask;
}

#undef MASK

#pragma pack(pop)

//----------------------------------------------------------------------------
struct dynamic_linking_tables_t
{
  dynamic_linking_tables_t()
    : offset(0),
      addr(0),
      size(0),
      link(0) {}

  dynamic_linking_tables_t(size_t _o, ea_t _a, size_t _s, elf_shndx_t _l)
    : offset(_o),
      addr(_a),
      size(_s),
      link(_l) {}

  bool is_valid() const { return offset != 0; }

  size_t offset;
  ea_t addr;
  size_t size;
  elf_shndx_t link;
};

//----------------------------------------------------------------------------
class dynamic_linking_tables_provider_t
{
public:
  dynamic_linking_tables_provider_t()
    : dlt() {}
  const dynamic_linking_tables_t &get_dynamic_linking_tables_info() const { return dlt; }
  bool has_valid_dynamic_linking_tables_info() const { return dlt.is_valid(); }
  void set_dynlink_table_info(size_t offset, ea_t addr, size_t size, int link)
  {
    dlt = dynamic_linking_tables_t(offset, addr, size, link);
  }

private:
  dynamic_linking_tables_t dlt;
};

//----------------------------------------------------------------------------
enum dynamic_info_type_t
{
  DIT_STRTAB,
  DIT_SYMTAB,
  DIT_REL,
  DIT_RELA,
  DIT_PLT,
  DIT_HASH,
  DIT_GNU_HASH,
  DIT_PREINIT_ARRAY,
  DIT_INIT_ARRAY,
  DIT_FINI_ARRAY,
  DIT_TYPE_COUNT,
};

//----------------------------------------------------------------------------
// various information parsed from the .dynamic section or DYNAMIC segment
struct dynamic_info_t
{
  dynamic_info_t()
  {
    memset(this, 0, sizeof(dynamic_info_t));
  }

  void initialize(const reader_t &reader);

  struct entry_t
  {
    entry_t() { clear(); }
    bool is_valid() const { return offset > 0 && size != 0; }
    int64 offset;
    uint64 addr;
    uint64 size;
    uint16 entsize;

    void clear()
    {
      offset = 0;
      addr = 0;
      size = 0;
      entsize = 0;
    }

    void guess_size(const sizevec_t &offsets)
    {
      size = BADADDR;
      for ( int i = 0; i < offsets.size(); i++ )
      {
        size_t off = offsets[i];
        if ( offset != 0 && off > offset )
          size = qmin(size, off - offset);
      }
      if ( size == BADADDR )
        size = 0;
    }
  } entries[DIT_TYPE_COUNT];

  entry_t &strtab() { return entries[DIT_STRTAB]; }
  entry_t &symtab() { return entries[DIT_SYMTAB]; }
  entry_t &rel() { return entries[DIT_REL]; }
  entry_t &rela() { return entries[DIT_RELA]; }
  entry_t &plt() { return entries[DIT_PLT]; }
  entry_t &hash() { return entries[DIT_HASH]; }
  entry_t &gnu_hash() { return entries[DIT_GNU_HASH]; }
  entry_t &preinit_array() { return entries[DIT_PREINIT_ARRAY]; }
  entry_t &init_array() { return entries[DIT_INIT_ARRAY]; }
  entry_t &fini_array() { return entries[DIT_FINI_ARRAY]; }

  const entry_t &rel() const { return entries[DIT_REL]; }
  const entry_t &rela() const { return entries[DIT_RELA]; }
  const entry_t &plt() const { return entries[DIT_PLT]; }

  uint32 plt_rel_type; // type of entries in the PLT relocation table (DT_RELENT)

  static const char *d_un_str(const reader_t &reader, int64 d_tag, int64 d_un);
  static const char *d_tag_str(const reader_t &reader, int64 d_tag);
  static const char *d_tag_str_ext(const reader_t &reader, int64 d_tag);

  // Fill a "fake" header, typically to be used w/
  // a buffered_input_t.
  bool fill_section_header(
          elf_shdr_t *sh,
          dynamic_info_type_t type) const;
};

//----------------------------------------------------------------------------
// Well-known sections
enum wks_t
{
  WKS_BSS = 1,
  WKS_BORLANDCOMMENT,
  WKS_COMMENT,
  WKS_DATA,
  WKS_DYNAMIC,
  WKS_DYNSYM,
  WKS_GOT,
  WKS_GOTPLT,
  WKS_HASH,
  WKS_INTERP,
  WKS_NOTE,
  WKS_PLT,
  WKS_RODATA,
  WKS_SYMTAB,
  WKS_TEXT,
  WKS_OPD,
  WKS_SYMTAB_SHNDX,
  WKS_DYNSYM_SHNDX,
  WKS_PLTGOT,
  WKS_LAST
};

class section_headers_t : public dynamic_linking_tables_provider_t
{
  elf_shdrs_t headers;
  uint32 wks_lut[WKS_LAST];
  reader_t *reader;
  bool initialized;
  bool got_is_original;   // Was .got section present in the input file?
  dynamic_info_t::entry_t strtab;

  friend class reader_t;

  section_headers_t(reader_t *_r)
    : reader(_r), initialized(false), got_is_original(false), strtab()
  {
    memset(wks_lut, 0, sizeof(wks_lut));
  }
  void assert_initialized() const
  {
    QASSERT(20099, initialized);
  }
public:
  const elf_shdr_t *getn(elf_shndx_t index) const;
  const elf_shdr_t *get_wks(wks_t wks) const
  {
    elf_shndx_t index = get_index(wks);
    return index == 0 ? NULL : getn(index);
  }
  const elf_shdr_t *get(uint32 sh_type, const char *name) const;

#define CONST_THIS CONST_CAST(const section_headers_t*)(this)
#define NCONST_SHDR(x) CONST_CAST(elf_shdr_t *)(x)
  elf_shdr_t *getn(elf_shndx_t index) { return NCONST_SHDR(CONST_THIS->getn(index)); }
  elf_shdr_t *get_wks(wks_t wks) { return NCONST_SHDR(CONST_THIS->get_wks(wks)); }
  elf_shdr_t *get(uint32 sh_type, const char *name) { return NCONST_SHDR(CONST_THIS->get(sh_type, name)); }
#undef CONST_THIS
#undef NCONST_SHDR

  // Look for '.rel.<section_name>', or '.rela.<section_name>'.
  const elf_shdr_t *get_rel_for(elf_shndx_t index, bool *is_rela = NULL) const;
  elf_shndx_t get_index(wks_t wks) const;
  void set_index(wks_t wks, elf_shndx_t index);
  int add(const elf_shdr_t &);
  void clear() // FIXME: This shouldn't be part of the public API
  {
    headers.clear();
    memset(wks_lut, 0, sizeof(wks_lut));
  }
  bool empty() const { return headers.empty(); }
  void resize(size_t size) { headers.resize(size); } // FIXME: This shouldn't be part of the public API
  bool get_name(qstring *out, elf_shndx_t index) const;
  bool get_name(qstring *out, const elf_shdr_t*) const;
  bool get_name(qstring *out, const elf_shdr_t &sh) const { return get_name(out, &sh); }
  elf_shdrs_t::const_iterator begin() const { return headers.begin(); }
  elf_shdrs_t::const_iterator end  () const { return headers.end(); }
  elf_shdrs_t::iterator begin() { return headers.begin(); }
  elf_shdrs_t::iterator end  () { return headers.end(); }

  const char *sh_type_str(uint32 sh_type) const;

  bool is_got_original(void) const { return got_is_original; }
  void set_got_original(void) { got_is_original = true; }

  // Get the size of the section. That is, the minimum between
  // what is advertized (sh_size) and the number of bytes between
  // this, and the next section.
  uint64 get_size_in_file(const elf_shdr_t &sh) const;

  // Read the section contents into the 'out' byte vector.
  // This doesn't blindly rely on sh.sh_size, but will use
  // get_size_in_file() instead.
  // Also, the position of the linput_t will be preserved.
  void read_file_contents(bytevec_t *out, const elf_shdr_t &sh) const;
};

//----------------------------------------------------------------------------
class program_headers_t : public dynamic_linking_tables_provider_t
{
  elf_phdrs_t pheaders;
  ea_t image_base;
  reader_t *reader;
  bool initialized;
public:
  program_headers_t(reader_t *_r)
    : image_base(BADADDR), reader(_r), initialized(false)
  {
  }
  elf_phdrs_t::const_iterator begin() const { return pheaders.begin(); }
  elf_phdrs_t::const_iterator end  () const { return pheaders.end(); }
  elf_phdrs_t::iterator begin() { return pheaders.begin(); }
  elf_phdrs_t::iterator end  () { return pheaders.end(); }
  elf_phdr_t *get(uint32 index) { assert_initialized(); return &pheaders[index]; }
  ea_t get_image_base() const { return image_base; }
  void set_image_base(ea_t ea) { image_base = ea; }
  inline size_t size() const { return pheaders.size(); }
  void resize(size_t sz) { pheaders.resize(sz); } // FIXME: This shouldn't be part of the pu
  const char *p_type_str(uint32 p_type) const;

  // Get the size of the segment. That is, the minimum between
  // what is advertized (p_filesz) and the number of bytes between
  // this, and the next segment.
  uint64 get_size_in_file(const elf_phdr_t &p) const;

  // Read the segment contents into the 'out' byte vector.
  // This doesn't blindly rely on p.p_size, but will use
  // get_size_in_file() instead.
  // Also, the position of the linput_t will be preserved.
  void read_file_contents(bytevec_t *out, const elf_phdr_t &p) const;

private:
  friend class reader_t;
  void assert_initialized() const { QASSERT(20100, initialized); }
};

//----------------------------------------------------------------------------
// Note Section
// Sections of type SHT_NOTE and program header elements of type PT_NOTE

// entry
struct elf_note_t
{
  qstring name;   // entry owner or originator
  qstring desc;   // descriptor
  uint32 type;    // interpretation of descriptor

  // fill entry and return new start offset
  static bool unpack(elf_note_t *entry, uint32 *start, const bytevec_t &buf, bool mf);

private:
  static bool unpack_sz(uint32 *r, uint32 *start, const bytevec_t &buf, bool mf);
  static bool unpack_strz(qstring *out, const bytevec_t &buf, uint32 start, uint32 len);
};
typedef qvector<elf_note_t> elf_notes_t;

// entry originators and types
#define NT_NAME_GNU "GNU"
#define NT_GNU_BUILD_ID 3

class notes_t
{
public:
  notes_t(reader_t *_r) :
    reader(_r),
    initialized(false)
  {}

  elf_notes_t::const_iterator begin() const { return notes.begin(); }
  elf_notes_t::const_iterator end  () const { return notes.end(); }
  void clear(void) { notes.clear(); }
  void add(const bytevec_t &buf);

  // convinient functions

  // Build ID
  bool get_build_id(qstring *out);

private:
  reader_t *reader;
  elf_notes_t notes;
  bool initialized;

  friend class reader_t;
  void assert_initialized() const { QASSERT(20082, initialized); }
};

//----------------------------------------------------------------------------
class arch_specific_t
{
public:
  virtual ~arch_specific_t() {}
  virtual void on_start_symbols(reader_t &/*reader*/) {}
  virtual void on_symbol_read(reader_t &/*reader*/, sym_rel &/*sym*/) {}
};

//----------------------------------------------------------------------------
//-V:reader_t:730 Not all members of a class are initialized inside the constructor
class reader_t
{
public:
  // Type definitions
  // DOCME
  enum unhandled_section_handling_t
  {
    ush_none = 0,
    ush_load,
    ush_skip
  };

  /*
   * The list of notifications to which the user of the reader
   * can react.
   * It is documented as follows:
   *  1) a short description of the notification, and possibly a hint
   *     on how it should be considered/treated.
   *  2) the list of arguments, to be consumed in a vararg fashion.
   */
  enum errcode_t
  {
    /*
     * The "class" of the ELF module is not properly defined. It
     * should really be one of (ELFCLASS32, ELFCLASS64).
     * We will fallback to the ELFCLASS32 class.
     *   - uint8: the ELF class, as defined in the file.
     */
    BAD_CLASS = 1,

    /*
     * The size of the ELF header conflicts with what was expected.
     *   - uint16: the size of the ELF header, as defined in the file
     *             (i.e., eh_ehsize)
     *   - uint16: the expected size.
     */
    BAD_EHSIZE,

    /*
     * The byte ordering is not properly defineed. It should
     * really be one of (ELFDATA2LSB, ELFDATA2MSB).
     * We will fallback to the ELFDATA2LSB ordering.
     *   - uint8: the byte ordering, as defined in the file.
     */
    BAD_ENDIANNESS,

    /*
     * The ELF module defines there are Program Header entries,
     * but it defines an entry size to be of an odd size.
     * We will fallback to the default size for program header
     * entries, which depends on the "class" of this ELF module.
     *   - uint16: the size of a program header entry, as defined in
     *     the file.
     *   - uint16: the expected size (to which we will fallback).
     */
    BAD_PHENTSIZE,

    /*
     * The ELF module either:
     * 1) defines an offset for the Program Header entries data but a
     *    count of 0 entries, or
     * 2) defines no offset for the Program Header entries data but a
     *    count of 1+ entries.
     * We will not use the program header table.
     *   - uint16: the number of entries, as defined in the file.
     *   - uint64: the offset for the entries data.
     */
    BAD_PHLOC,

    /*
     * The ELF module defines there are Section Header entries,
     * but it defines an entry size to be of an odd size.
     * We will fallback to the default size for section header
     * entries, which depends on the "class" of this ELF module.
     *   - uint16: the size of a section header entry, as defined in
     *     the file.
     *   - uint16: the expected size (to which we will fallback).
     */
    BAD_SHENTSIZE,

    /*
     * The ELF module:
     * 1) defines an offset for the Section Header entries data but a
     *    count of 0 entries, or
     * 2) defines no offset for the Section Header entries data but a
     *    count of 1+ entries, or
     * 3) defines too many entries, which would cause an EOF to occur
     *    while reading those.
     * We will not use the section header table.
     *   - uint32: the number of entries, as defined in the file.
     *   - uint64: the offset for the entries data.
     *   - int64 : the size of the file.
     */
    BAD_SHLOC,

    /*
     * The reader has encountered an unhandled section.
     *   - uint16     : The index of the section header.
     *   - Elf64_Shdr*: A pointer to the section header structure.
     * If handled, this notification should return a
     * "unhandled_section_handling_t", specifying how the
     * reader should proceed with it.
     */
    UNHANDLED_SECHDR,

    /*
     * The reader has encountered an unhandled section,
     * which even the reader instance user couldn't handle.
     *   - uint16     : The index of the section header.
     *   - Elf64_Shdr*: A pointer to the section header structure.
     */
    UNKNOWN_SECHDR,

    /*
     * The reader has spotted that the section's address
     * in memory (i.e., sh_addr) is not aligned on the
     * specified alignment (i.e., sh_addralign).
     *   - uint16     : The index of the section header.
     *   - Elf64_Shdr*: A pointer to the section header structure.
     */
    BAD_SECHDR_ALIGN,

    /*
     * The section header 0 is supposed to be SHT_NULL. But it wasn't.
     */
    BAD_SECHDR0,

    /*
     * The type of file (e_type) appears to be ET_CORE, and the
     * machine is SPARC. Those files usually have wrong SHT's. We
     * will rather opt for the PHT view.
     */
    USING_PHT_SPARC_CORE,

    /*
     * TLS definitions occured more than once in the file.
     */
    EXCESS_TLS_DEF,

    /*
     * The section with the given name is being redefined.
     *   - const char *: The name of the section
     */
    SECTION_REDEFINED,

    /*
     * While parsing the dynamic_info_t, the reader spotted
     * an invalid value for the DT_PLTREL entry.
     *   - uint32: The 'value' of that entry.
     */
    BAD_DYN_PLT_TYPE,

    /*
     * One of the symbols in the symbols tables has a bad binding.
     *   - unsigned char: The binding.
     */
    BAD_SYMBOL_BINDING,

    /*
     * The ELF module has a Section Header String Table index, but
     * it is out-of-bounds.
     *   - uint32: the section header string table index;
     *   - uint16: the number of section header entries;
     */
    BAD_SHSTRNDX,

    /*
     * The ELF module has Program Header entries, which means it's
     * ready to be loaded as a process image, but claims it is of
     * type ET_REL which makes it a relocatable object file.
     */
    CONFLICTING_FILE_TYPE,

    LAST_WARNING = CONFLICTING_FILE_TYPE,

    /*
     * Couldn't read as many bytes as required.
     * This is a fatal issue, and should be treated as such.
     *  - size_t: expected bytes.
     *  - size_t: actually read.
     *  - int32 : position in file when reading was initiated.
     */
    ERR_READ,

    LAST_ERROR = ERR_READ
  };

  // Data members
  program_headers_t pheaders;
  section_headers_t sections;
  symrel_cache_t symbols;
  dynamic_info_t::entry_t sym_strtab;  // for SYMTAB
  dynamic_info_t::entry_t dyn_strtab;  // for DYNSYM

  struct standard_sizes_in_file_t
  {
    int ehdr;
    int phdr;
    int shdr;

    struct
    {
      uint sym;
      int dyn;
      int rel;
      int rela;
    } entries;

    struct
    {
      uint sym;         // DT_SYMENT
      uint rel;         // DT_RELENT
      uint rela;        // DT_RELAENT
    } dyn;

    struct
    {
      int elf_addr;
      int elf_off;
      int elf_xword;
      int elf_sxword;
    } types;
  } stdsizes;

private:
  linput_t *li;
  int64 sif; // ELF start in file
  uint64 filesize;
  // Handle an error. If this function returns false, the reader will stop.
  bool (*handle_error)(const reader_t &reader, errcode_t notif, ...);
  elf_ehdr_t header;

  struct mapping_t
  {
    uint64 offset;
    uint64 size;
    uint64 ea;
  };
  qvector<mapping_t> mappings;

  arch_specific_t *arch_specific;
  adiff_t load_bias; // An offset to apply to the ea's
                     // when loading the program in memory.
  // real endianness and bitness of the file
  // some loaders (e.g. Linux) ignore values in the ident header
  // so we set the effective ones here
  bool eff_msb;
  bool eff_64;          // is elf64?
  bool seg_64;          // segments are 32bit or 64bit?

  bool check_ident();
public:
  reader_t(linput_t *_li, int64 _start_in_file = 0);
  ~reader_t()
  {
    delete arch_specific;
  }
  void set_linput(linput_t *_li) { li = _li; }
  linput_t *get_linput() const { return li; }
  void set_load_bias(adiff_t lb) { load_bias = lb; }
  adiff_t get_load_bias() const { return load_bias; }

  bool is_warning(errcode_t notif) const;
  bool is_error(errcode_t notif) const;
  ssize_t prepare_error_string(char *buf, size_t bufsize, reader_t::errcode_t notif, va_list va) const;

  void set_handler(bool (*_handler)(const reader_t &reader, errcode_t notif, ...));

  int read_addr(void *buf) const;
  int read_off(void *buf) const;
  int read_xword(void *buf) const;
  int read_sxword(void *buf) const;
  int read_word(uint32 *buf) const;
  int read_half(uint16 *buf) const;
  int read_byte(uint8  *buf) const;
  int read_symbol(elf_sym_t *buf) const;
  int safe_read(void *buf, size_t size, bool apply_endianness = true) const;

  bool read_ident(); // false - bad elf file

  // Is the file a valid relocatable file? That is, it must have
  // the ET_REL ehdr e_type, and have a proper section table.
  bool is_valid_rel_file() const
  {
    return sections.initialized && !sections.empty() && get_header().e_type == ET_REL;
  }
  const elf_ident_t &get_ident() const { return header.e_ident; }

  bool read_header();
        elf_ehdr_t &get_header () { return header; }
  const elf_ehdr_t &get_header () const { return header; }

  bool read_section_headers();
  bool read_program_headers();
  bool read_notes(notes_t *notes);

  // Android elf files can have a prelink.
  // If such a prelink was found, this will return 'true' and
  // '*base' will be set to that prelink address.
  bool read_prelink_base(uint32 *base);

  int64 get_start_in_file() const { return sif; }

  // Seek to section header #index.
  // (Note that this does not seek to the section's contents!)
  bool seek_to_section_header(elf_shndx_t index)
  {
    uint64 pos = header.e_shoff + uint64(index) * uint64(header.e_shentsize);
    if ( pos < header.e_shoff )
      return false;
    if ( seek(pos) == -1 )
      return false;
    return true;
  }

  // read the section header from the current position
  // (should be called after seek_to_section_header)
  bool read_section_header(elf_shdr_t *sh);

  // Seek to program header #index.
  // (Note that this does not seek to the segment's contents!)
  bool seek_to_program_header(uint32 index)
  {
    uint64 pos = header.e_phoff + uint64(index) * uint64(header.e_phentsize);
    if ( pos < header.e_phoff )
      return false;
    if ( seek(pos) == -1 )
      return false;
    return true;
  }

  // Get the current position, in the elf module (which could
  // start at an offset different than 0 in the file).
  int64 tell() const { return qltell(li) - sif; }
  int64 size() const { return filesize - sif; }

  // Seek in the elf module, at the given position. If the elf module has an
  // offset in the file, it will be added to 'pos' to compose the final
  // position in file.
  qoff64_t seek(int64 pos) const { return qlseek(li, sif+pos); }

  //
  elf_sym_idx_t rel_info_index(const elf_rel_t &r)  const;
  elf_sym_idx_t rel_info_index(const elf_rela_t &r) const;
  uint32 rel_info_type(const elf_rel_t &r)  const;
  uint32 rel_info_type(const elf_rela_t &r) const;

  void add_mapping(const elf_phdr_t &p);
  // Searches all defined mappings for one that would
  // encompass 'ea'. Returns -1 if not found.
  int64 file_offset(uint64 ea) const;
  // Searches all defined mappings for one that would
  // encompass file offset 'offset'. Returns BADADDR if not found.
  ea_t file_vaddr(uint64 offset) const;

  elf_shndx_t get_shndx_at(uint64 offset) const;

  // string tables
  void set_sh_strtab(
          dynamic_info_t::entry_t &strtab,
          const elf_shdr_t &strtab_sh,
          bool replace);
  void set_di_strtab(
          dynamic_info_t::entry_t &strtab,
          const dynamic_info_t::entry_t &strtab_di);
  bool get_string_at(qstring *out, uint64 offset) const;
  bool get_name(
          qstring *out,
          const dynamic_info_t::entry_t &strtab,
          uint32 name_idx) const;
  bool get_name(qstring *out, slice_type_t slice_type, uint32 name_idx) const;

  // Sets the dynamic info
  typedef qvector<elf_dyn_t> dyninfo_tags_t;
  bool read_dynamic_info_tags(
          dyninfo_tags_t *dyninfo_tags,
          const dynamic_linking_tables_t &dlt);
  bool parse_dynamic_info(
          dynamic_info_t *dyninfo,
          const dyninfo_tags_t &dyninfo_tags);

  arch_specific_t *get_arch_specific() const { return arch_specific; }

  // Human-friendly representations of
  // header (or ident) values.
  const char *file_type_str()    const;
  const char *os_abi_str()       const;
  const char *machine_name_str() const;

  // effective endianness
  bool is_msb() const { return eff_msb; }
  // effective bitness (elf32 or elf64)
  bool is_64() const { return eff_64; }
  // effective bitness for segments
  int get_seg_bitness() const { return seg_64 ? 2 : 1; }
};

/* extern reader_t reader; */

//----------------------------------------------------------------------------
struct input_status_t
{
  input_status_t(const reader_t &_reader)
    : reader(_reader),
      pos(reader.tell())
  {
  }

  qoff64_t seek(int64 new_pos)
  {
    return reader.seek(new_pos);
  }

  ~input_status_t()
  {
    reader.seek(pos);
  }
private:
  const reader_t &reader;
  int64 pos;
  input_status_t();
};

//----------------------------------------------------------------------------
template<typename T> class buffered_input_t
{
  reader_t &reader;
  uint64 offset;
  uint64 count;
  size_t isize; // entry size

  T buffer[256];
  uint64 read;  // number of items we already read from the input
  uint32 cur;   // ptr to the next item in 'buffer' to be served
  uint32 end;   // number of items in 'buffer'

public:
  buffered_input_t(reader_t &_reader, const elf_shdr_t &section)
    : reader(_reader),
      offset(section.sh_offset),
      count (0),
      isize (section.sh_entsize),
      read  (0),
      cur   (0),
      end   (0)
  {
    if ( section.sh_entsize != 0 )
    {
      uint64 sz = reader.sections.get_size_in_file(section);
      count = sz / section.sh_entsize;
    }
  }
  buffered_input_t(
          reader_t &_reader,
          uint64 _offset,
          uint64 size,
          size_t entsize)
    : reader(_reader),
      offset(_offset),
      count (size / entsize),
      isize (entsize),
      read  (0),
      cur   (0),
      end   (0) {}

  bool next(T *&storage)
  {
    if ( cur >= end )
    {
      uint64 left = count - read;
      if ( !left )
        return false;

      if ( left > qnumber(buffer) )
        left = qnumber(buffer);

      cur = 0;
      if ( read == 0 )
        start_reading();
      end = read_items(left);
      if ( end == 0 )
        return false;
      read += end;
    }

    if ( cur >= end )
      return false;

    storage = &buffer[cur];
    cur++;
    return true;
  }

private:
  buffered_input_t();
  ssize_t read_items(size_t max)
  {
    size_t i = 0;
    if ( is_mul_ok<uint64>(read, isize) && is_mul_ok(max, isize) )
    {
      input_status_t save_excursion(reader);
      if ( save_excursion.seek(offset + (read * isize)) != -1 )
        for ( ; i < max; i++ )
          if ( !read_item(buffer[i]) )
            break;
    }
    return i;
  }

  bool read_item(T &);
  void start_reading() {}
};

#endif
