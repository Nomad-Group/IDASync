#ifndef MACHO_COMMON_H
#define MACHO_COMMON_H

#include <netnode.hpp>
#include <diskio.hpp>

#define IDA_SEG_DATA    SEG_DATA
#define __inline__ inline

#ifndef __MAC__
#  define __DARWIN_UNIX03 1
#endif

#if !__DARWIN_UNIX03
#define __eax            eax
#define __ebx            ebx
#define __ecx            ecx
#define __edx            edx
#define __edi            edi
#define __esi            esi
#define __ebp            ebp
#define __esp            esp
#define __ss             ss
#define __eflags         eflags
#define __eip            eip
#define __cs             cs
#define __ds             ds
#define __es             es
#define __fs             fs
#define __gs             gs
#define __rax            rax
#define __rbx            rbx
#define __rcx            rcx
#define __rdx            rdx
#define __rdi            rdi
#define __rsi            rsi
#define __rbp            rbp
#define __rsp            rsp
#define __rflags         rflags
#define __rip            rip
#define __r8             r8
#define __r9             r9
#define __r10            r10
#define __r11            r11
#define __r12            r12
#define __r13            r13
#define __r14            r14
#define __r15            r15
#define __r              r
#define __sp             sp
#define __lr             lr
#define __pc             pc
#define __cpsr           cpsr
#define __fpu_reserved   fpu_reserved
#define __fpu_fcw        fpu_fcw
#define __fpu_fsw        fpu_fsw
#define __fpu_ftw        fpu_ftw
#define __fpu_fop        fpu_fop
#define __fpu_ip         fpu_ip
#define __fpu_cs         fpu_cs
#define __fpu_rsrv1      fpu_rsrv1
#define __fpu_rsrv2      fpu_rsrv2
#define __fpu_rsrv3      fpu_rsrv3
#define __fpu_rsrv4      fpu_rsrv4
#define __fpu_stmm0      fpu_stmm0
#define __fpu_stmm1      fpu_stmm1
#define __fpu_stmm2      fpu_stmm2
#define __fpu_stmm3      fpu_stmm3
#define __fpu_stmm4      fpu_stmm4
#define __fpu_stmm5      fpu_stmm5
#define __fpu_stmm6      fpu_stmm6
#define __fpu_stmm7      fpu_stmm7
#define __fpu_xmm0       fpu_xmm0
#define __fpu_xmm1       fpu_xmm1
#define __fpu_xmm2       fpu_xmm2
#define __fpu_xmm3       fpu_xmm3
#define __fpu_xmm4       fpu_xmm4
#define __fpu_xmm5       fpu_xmm5
#define __fpu_xmm6       fpu_xmm6
#define __fpu_xmm7       fpu_xmm7
#define __fpu_dp         fpu_dp
#define __fpu_ds         fpu_ds
#define __fpu_mxcsr      fpu_mxcsr
#define __fpu_mxcsrmask  fpu_mxcsrmask
#define __fpu_reserved   fpu_reserved
#define __fpu_reserved1  fpu_reserved1
#define __rc             rc
#define __precis         precis
#define __undfl          undfl
#define __ovrfl          ovrfl
#define __zdiv           zdiv
#define __denorm         denorm
#define __invalid        invalid
#define __busy           busy
#define __c3             c3
#define __tos            tos
#define __c2             c2
#define __c1             c1
#define __c0             c0
#define __errsumm        errsumm
#define __stkflt         stkflt
#define __trapno         trapno
#define __err            err
#define __faultvaddr     faultvaddr
#define __darwin_mmst_reg mmst_reg
#define __darwin_xmm_reg  xmm_reg
#endif

#if __MF__
#ifndef __BIG_ENDIAN__
#define __BIG_ENDIAN__ 1
#endif
#else
#ifndef __LITTLE_ENDIAN__
#define __LITTLE_ENDIAN__ 1
#endif
#endif

#ifdef __NT__
#ifndef __ppc__
#define __i386__ 1
#endif
#define __attribute__(x)
#endif

#ifdef __LINUX__
 //#define _BSD_I386__TYPES_H_
#define _DARWIN_C_SOURCE
#endif

#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach-o/reloc.h>
#include <mach-o/i860/reloc.h>
#include <mach-o/m88k/reloc.h>
#include <mach-o/ppc/reloc.h>
#include <mach-o/hppa/reloc.h>
#include <mach-o/sparc/reloc.h>
#include <mach-o/arm/reloc.h>
#include <mach-o/arm64/reloc.h>
#include <mach-o/x86_64/reloc.h>
#include <mach-o/nlist.h>

// these definitions are processor specific but are redefined in header files
// we undefine and never use them
#undef THREAD_STATE_NONE
#undef VALID_THREAD_STATE_FLAVOR
#undef MACHINE_THREAD_STATE
#undef MACHINE_THREAD_STATE_COUNT
#undef THREAD_STATE_MAX

#include <mach/i386/thread_status.h>
#undef THREAD_STATE_NONE
#undef VALID_THREAD_STATE_FLAVOR
#undef MACHINE_THREAD_STATE
#undef MACHINE_THREAD_STATE_COUNT
#undef THREAD_STATE_MAX

#define __arm__ 1
#include <mach/arm/thread_status.h>
#undef __arm__
#undef THREAD_STATE_NONE
#undef VALID_THREAD_STATE_FLAVOR
#undef MACHINE_THREAD_STATE
#undef MACHINE_THREAD_STATE_COUNT
#undef THREAD_STATE_MAX

CASSERT(sizeof(uint64_t) == 8);

#define SWAP_SHORT     swap16
#define SWAP_LONG      swap32
#define SWAP_LONG_LONG swap64
inline double SWAP_DOUBLE(double d)
{
  CASSERT(sizeof(uint64) == sizeof(double));
  uint64 x = swap64(*(uint64*)&d);
  return *(double *)&x;
}

#ifdef __LINUX__
inline uint64_t swap64(uint64_t x)
{
  // This is supposed to call pro.a's llong.cpp's swap64(ulonglong),
  // and thus _not_ endlessly recurse on itself --and maybe it does
  // in IDA-- but in some other tools, this is causing a problem.
  // For example, in EFD, we'd get segfaults because of
  // stack overflows.
  return make_ulonglong(swap32(high((ulonglong) x)), swap32(low((ulonglong) x)));
  /* return swap64((ulonglong)x); */
}
#endif

#define LC_ROUTINES_VALUE LC_ROUTINES_64
#define LC_ROUTINES_NAME "LC_ROUTINES_64"

#define MACHO_NODE "$ macho"    // supval(0) - mach_header
#define MACHO_ALT_IMAGEBASE nodeidx_t(-1)
#define MACHO_ALT_UUID      nodeidx_t(-2)
#define local static
#define MAX_DEPTH 1024

//copy memory with range checking and auto sizing
template<class T> bool safecopy(const char *&begin, const char *end, T *dest)
{
  if ( end <= begin || (end - begin) < sizeof(T) )
  {
    memset(dest, 0, sizeof(T));
    begin = end;
    return false;
  }
  memcpy((char*)dest, begin, sizeof(T));
  begin += sizeof(T);
  return true;
}

//advance the pointer with range and overflow checking
inline bool safeskip(const char *&begin, const char *end, size_t amount)
{
  if ( end <= begin || (end - begin) < amount )
  {
    begin = end;
    return false;
  }
  begin += amount;
  return true;
}

void use_ppc_thread_state(const char *begin, const char *end, int mf);
void print_ppc_thread_state(const char *begin, const char *end, int mf);

typedef qvector<struct section_64> secvec_t;
typedef qvector<struct segment_command_64> segcmdvec_t;
typedef qvector<struct nlist_64> nlistvec_t;
typedef qvector<struct relocation_info> relocvec_t;
typedef qvector<struct dylib_module_64> mod_table_t;
typedef qvector<struct dylib_table_of_contents> tocvec_t;
typedef qvector<struct dylib_reference> refvec_t;
typedef qstrvec_t dyliblist_t;

#define VISIT_COMMAND(name)   virtual int visit_##name       (const struct name##_command *, const char *, const char *)    { return 0; }
#define VISIT_COMMAND64(name) virtual int visit_##name##_64  (const struct name##_command_64 *, const char *, const char *) { return 0; }

// callbacks for visit_load_commands()
struct macho_lc_visitor_t
{
  // called for all load commands
  // lc: swapped load_command
  // begin, end: pointers to raw (unswapped) command
  // returns
  //  0: call specific callback
  //  1: stop enumeration
  //  2: don't call specific callback and continue
  virtual int visit_any_load_command(const struct load_command *,  const char *, const char *) { return 0; };

  // unknown load command
  // return nonzero to stop enumeration
  // NB: lc is swapped
  virtual int visit_unknown_load_command(const struct load_command *,  const char *, const char *) { return 0; };

  // the following functions get cmd already in native byte order (at least headers)
  // begin and end are pointers to raw, unswapped data
  // virtual int visit_XX  (const struct XX_command *cmd, char *begin, char *end)    { return 0; };

  // LC_SYMTAB
  VISIT_COMMAND(symtab);
  // LC_SYMSEG
  VISIT_COMMAND(symseg);
  // LC_THREAD, LC_UNIXTHREAD
  VISIT_COMMAND(thread);
  // LC_IDFVMLIB, LC_LOADFVMLIB
  VISIT_COMMAND(fvmlib);
  // LC_IDENT
  VISIT_COMMAND(ident);
  // LC_FVMFILE
  VISIT_COMMAND(fvmfile);
  // LC_DYSYMTAB
  VISIT_COMMAND(dysymtab);
  // LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_ID_DYLIB, LC_REEXPORT_DYLIB, LC_LAZY_LOAD_DYLIB
  VISIT_COMMAND(dylib);
  // LC_ID_DYLINKER, LC_LOAD_DYLINKER
  VISIT_COMMAND(dylinker);
  // LC_PREBOUND_DYLIB
  VISIT_COMMAND(prebound_dylib);
  // LC_ROUTINES
  VISIT_COMMAND(routines);
  // LC_SUB_FRAMEWORK
  VISIT_COMMAND(sub_framework);
  // LC_SUB_UMBRELLA
  VISIT_COMMAND(sub_umbrella);
  // LC_SUB_CLIENT
  VISIT_COMMAND(sub_client);
  // LC_SUB_LIBRARY
  VISIT_COMMAND(sub_library);
  // LC_TWOLEVEL_HINTS
  VISIT_COMMAND(twolevel_hints);
  // LC_PREBIND_CKSUM
  VISIT_COMMAND(prebind_cksum);

  // LC_ROUTINES_64
  VISIT_COMMAND64(routines);

  // LC_UUID
  VISIT_COMMAND(uuid);
  // LC_RPATH
  VISIT_COMMAND(rpath);
  // LC_CODE_SIGNATURE, LC_SEGMENT_SPLIT_INFO, LC_FUNCTION_STARTS, LC_DATA_IN_CODE
  // LC_DYLIB_CODE_SIGN_DRS
  VISIT_COMMAND(linkedit_data);
  // LC_ENCRYPTION_INFO
  VISIT_COMMAND(encryption_info);
  // LC_DYLD_INFO, LC_DYLD_INFO_ONLY
  VISIT_COMMAND(dyld_info);
  // LC_VERSION_MIN_MACOSX, LC_VERSION_MIN_IPHONEOS
  VISIT_COMMAND(version_min);
  // LC_SOURCE_VERSION
  VISIT_COMMAND(source_version);
  // LC_MAIN
  VISIT_COMMAND(entry_point);

  virtual int visit_segment(const segment_command *,    const char *, const char *) { return 0; }
  virtual int visit_segment(const segment_command_64 *, const char *, const char *) { return 0; }

  // even though they're not strictly load commands, we also parse sections for convenience
  virtual int visit_section(const struct section *,    const char *, const char *) { return 0; }
  virtual int visit_section(const struct section_64 *, const char *, const char *) { return 0; }
};

struct macho_reloc_visitor_t
{
  // magic values for section number
  enum
  {
    mach_reloc_external = -2,
    mach_reloc_local = -1,
  };
  // callback for visit_relocs()
  virtual void visit_relocs(ea_t baseea, const relocvec_t &relocs, int section_no) = 0;
};

struct dyld_info_visitor_t
{
  // visit a rebase location
  // type: type of rebasing (REBASE_TYPE_XXX)
  virtual int visit_rebase(uint64_t /*address*/, uchar /*type*/) { return 0; }

  enum bind_kind_t
  {
    bind_kind_normal = 0,
    bind_kind_weak   = 1,
    bind_kind_lazy   = 2,
  };

  // visit a bind location
  // bind_kind: which of bind directories are we walking
  // type: bind type (BIND_TYPE_XXX)
  // flags: BIND_SYMBOL_FLAGS_xxx
  // addend: value added to symbol's address
  // name: symbol name
  virtual int visit_bind(bind_kind_t /*bind_kind*/, uint64_t /*address*/, uchar /*type*/, uchar /*flags*/,
    int64_t /*libOrdinal*/, int64_t /*addend*/, const char * /*name*/) { return 0; }

  // visit an exported name
  // flags: EXPORT_SYMBOL_FLAGS_XXX
  virtual int visit_export(uint64_t /*address*/, uint32 /*flags*/, const char * /*name*/) { return 0; }
};

struct function_starts_visitor_t
{
  // visit a function start
  virtual int visit_start(uint64_t /*address*/) { return 0; }
};

struct shared_region_visitor_t
{
  enum region_kind_t
  {
    region_kind_ptr32 = 1, // 32-bit pointer
    region_kind_ptr64 = 2, // 64-bit pointer
    region_kind_ppchi16 = 3, // ppc hi16
    region_kind_imp32 = 4, // 32-bit offset to IMPORT
  };

  virtual int visit_region(region_kind_t /* kind */, uint64_t /*address*/) { return 0; }
};

class macho_file_t
{
  // input file reference
  linput_t *li;
  bool should_close_linput;
  // fat header (for fat files)
  fat_header fheader;
  // infos about available architecures
  qvector<fat_arch> fat_archs;
  // offset of main file in the stream
  size_t start_offset;
  // offset of the selected subfile
  size_t mach_offset;
  // size of the selected subfile
  size_t mach_size;
  // mach header + load commands
  // NB: non-swapped
  bytevec_t mach_header_data;
  // do we need to swap endianness?
  bool mf;
  // is file 64-bit?
  bool m64;
  // header of currently selecte file (swapped)
  mach_header_64 mh;
  // list of load commands in the header
  // pointers point into mach_header_data
  qvector<const load_command *> load_commands;
  // list of segment command (swapped)
  segcmdvec_t mach_segcmds;
  // list of section infos (swapped)
  secvec_t    mach_sections;
  // seg2section[i] = index of the first section of segment i in the mach_sections array
  intvec_t    seg2section;
  // list of dylibs (swapped)
  dyliblist_t mach_dylibs;
  // module table (swapped)
  mod_table_t mach_modtable;
  // toc (swapped)
  tocvec_t mach_toc;
  // reference table
  refvec_t mach_reftable;
  // are mach_sections and mach_segcmds valid?
  bool parsed_section_info;
  // expected base address (vmaddr of the segment that includes the mach header)
  ea_t base_addr;

  //load array of relocs from file with range checking and endianness swapping
  bool load_relocs(uint32 reloff, uint32 nreloc, relocvec_t &relocs, const char *descr);

  bool parse_fat_header();
  bool parse_load_commands(bool silent=false);
  void parse_section_info();

  uint64_t segStartAddress(int segIndex);
  bool visit_rebase_opcodes(const bytevec_t &data, dyld_info_visitor_t &v);
  bool visit_bind_opcodes(dyld_info_visitor_t::bind_kind_t bind_kind, const bytevec_t &data, dyld_info_visitor_t &v);
  bool processExportNode(
        const uchar *start,
        const uchar *p,
        const uchar *end,
        char *symname,
        int symnameoff,
        size_t symnamelen,
        dyld_info_visitor_t &v,
        int level=0);
  bool visit_export_info(const bytevec_t &data, dyld_info_visitor_t &v);


public:
  macho_file_t(linput_t *_li, size_t _start_offset = 0)
    : li(_li), should_close_linput(false), start_offset(_start_offset),
      mach_offset(-1), mach_size(0),  parsed_section_info(false),
      base_addr(BADADDR) {}
  ~macho_file_t(void)
  {
    if ( should_close_linput )
      close_linput(li);
  }

  // check if file begins either with fat header or mach header
  // must be called first
  bool parse_header();

  // get fat header
  // returns false if it's not a fat file
  bool get_fat_header(fat_header *fh);

  // get number of subfiles in a fat file
  // 0 means it's a not fat file
  size_t get_fat_subfiles() { return fat_archs.size(); }

  // get fat_arch structure for subfile n
  bool get_fat_arch(uint n, fat_arch *fa);

  // set subfile for the following functions
  // 0 works for non-fat files
  // filesize: limit reads to this size; if 0, use linput's size
  bool set_subfile(uint n, size_t filesize = 0, bool silent=false);

  // select subfile of a specific cpu type (and subtype)
  // cpusubtype of 0 matches any subtype
  bool select_subfile(cpu_type_t cputype, cpu_subtype_t cpusubtype = (cpu_subtype_t)0);

  // if the current submodule is an ar library, select a module from it and switch to it
  bool select_ar_module(size_t offset, size_t size);

  // get mach header for the current subfile
  const mach_header_64 &get_mach_header();

  bool is64() const { return m64; }
  bool ismf() const { return mf; }

  size_t get_subfile_offset() const { return mach_offset; }
  size_t get_subfile_size()   const { return mach_size; }

  enum subfile_type_t
  {
    SUBFILE_UNKNOWN,
    SUBFILE_MACH,
    SUBFILE_MACH_64,
    SUBFILE_AR
  };
  subfile_type_t get_subfile_type(uint n, size_t filesize=0);

  // Move the linput_t to the beginning of the n-th subfile.
  //
  // If this is not a FAT file, this will
  // rewind the linput_t to the beginning of the file
  // (plus a potential start_offset).
  //
  // returns true if successful, false otherwise.
  bool seek_to_subfile(uint n, size_t filesize = 0);

  // enumerate load commands and call visitor on each
  // return true if visitor returned a non-zero
  bool visit_load_commands(macho_lc_visitor_t &v);

  // get segments and sections info
  const segcmdvec_t& get_segcmds();
  const secvec_t&    get_sections();
  size_t             get_seg2section(size_t segidx) const { return seg2section[segidx]; }

  // get segment by index
  bool get_segment(size_t segIndex, segment_command_64 *pseg);
  // get section by segment index and virtual address inside section
  bool get_section(size_t segIndex, uint64_t vaddr, section_64 *psect);

  // find segment by name
  bool get_segment(const char *segname, segment_command_64 *pseg = NULL);
  // get section by segment name and section name
  bool get_section(const char *segname, const char *sectname, section_64 *psect = NULL);
  // get section contents by segment name and section name
  bool get_section(const char *segname, const char *sectname, bytevec_t &data, bool in_mem = false);

  // get list of dylibs (LC_LOAD_DYLIB)
  const dyliblist_t& get_dylib_list();

  // get dylib module table
  const mod_table_t& get_module_table();

  // get dylib table of contents
  const tocvec_t& get_toc();

  // get reference table
  const refvec_t& get_ref_table();

  // get thread state (LC_THREAD/LC_UNIXTHREAD)
  void get_thread_state(const char *&begin, const char *&end);

  // get entrypoint (either from LC_MAIN, or from the thread state
  ea_t get_entry_address();

  // check if file is encrypted
  bool is_encrypted();

  // load a chunk of data from the linkedit section
  // size: number of bytes to load
  // it is updated to the actual number of bytes loaded
  bool load_linkedit_data(uint32 offset, size_t *size, void *buffer, bool in_mem = false);

  // load symbol table and string table
  void get_symbol_table_info(nlistvec_t &symbols, qstring &strings, bool in_mem = false);

  // gets the dysymtab_command from load commands
  // return false if not found
  bool get_dyst(struct dysymtab_command *dyst);

  // load indirect symbols table
  void get_indirect_symbol_table_info(qvector<uint32> &indirect_symbols);

  // enumerate relocations and call visitor on each
  void visit_relocs(macho_reloc_visitor_t &v);

  // enumerate dyld_info structures
  void visit_dyld_info(dyld_info_visitor_t &v);

  // enumerate LC_FUNCTION_STARTS data
  void visit_function_starts(function_starts_visitor_t &v);

  // enumerate LC_SEGMENT_SPLIT_INFO data
  void visit_shared_regions(shared_region_visitor_t &v);

  // get preferrable base address
  ea_t get_base() { return base_addr; }

  // return dylib ID, if present
  bool get_id_dylib(qstring *id);

  // get the linput pointer
  linput_t *get_linput(void) const { return li; }
};

//--------------------------------------------------------------------------
#define PTD_CLEAN        0
#define PTD_PARSABLE     1
#define PTD_DEFREP       2
#define PTD_DEFREP_NOFWD 3

//--------------------------------------------------------------------------
enum objc2_type_value_t
{
  OBJC2_TYPE_VOID = 0,
  OBJC2_TYPE_CHAR,
  OBJC2_TYPE_SHORT,
  OBJC2_TYPE_INT,
  OBJC2_TYPE_LONG,
  OBJC2_TYPE_LONGLONG,
  OBJC2_TYPE_FLOAT,
  OBJC2_TYPE_DOUBLE,
  OBJC2_TYPE_BOOL,
  OBJC2_TYPE_CHARPTR,
  OBJC2_TYPE_ID,
  OBJC2_TYPE_CLASS,
  OBJC2_TYPE_SEL,
  OBJC2_TYPE_ARRAY,
  OBJC2_TYPE_STRUCT,
  OBJC2_TYPE_UNION,
  OBJC2_TYPE_BITFIELD,
  OBJC2_TYPE_UNK,
};

//--------------------------------------------------------------------------
struct objc2_ivar_t
{
  qstring decl;  // full declaration (type+name)
  uint32 size;   // in bits
  uint32 align;  // align shift value
  uint32 offset; // offset, as specified by the value of _OBJC_IVAR_$_ variable
  bool bad;
  bool bad_off;
  objc2_ivar_t(void) : size(0), align(0), offset(0), bad(false), bad_off(false) {}
};
typedef qvector<objc2_ivar_t> objc2_ivars_t;

//--------------------------------------------------------------------------
struct objc2_type_t
{
  qstring name;
  qstring prototype;
  objc2_type_value_t type;
  qstring array_suffix;
  int flags; // objc2_type_flags_t
  int size; // For bitfields, bit count; for arrays, item count
  int ptrcnt;
  bool had_name;
  bool empty_struct;  // struct with no fields
                      // don't add it to types unless it's used as a member
  // @"class",     @,  struct foo
  qstring typestr; // Clean representation.
  // struct class, id, struct foo
  qstring parser_typestr; // Parsable representation.
  // struct class, id, struct foo; struct foo { int bar; }
  qstring define_typestr; // Definition representation.
  // struct class, id, struct foo { int bar; }
  qstring define_nofwd_typestr; // Definition representation without forward reference.

  // for OBJC2_TYPE_ID, class name
  qstring classname;

  void append_typestr(
        const qstring &_typestr,
        const qstring &_parser_typestr,
        const qstring &_define_typestr,
        const qstring &_define_nofwd_typestr)
  {
    typestr += _typestr;
    parser_typestr += _parser_typestr;
    define_typestr += _define_typestr;
    define_nofwd_typestr += _define_nofwd_typestr;
  }

  void append_typestr(
        const qstring &_typestr,
        const qstring &_parser_typestr,
        const qstring &_define_typestr)
  {
    append_typestr(_typestr, _parser_typestr, _define_typestr, _define_typestr);
  }

  void append_typestr(const qstring &_typestr, const qstring &_parser_typestr)
  {
    append_typestr(_typestr, _parser_typestr, _parser_typestr);
  }

  void append_typestr(const qstring &_typestr)
  {
    append_typestr(_typestr, _typestr);
  }
};


struct dyld_cache_header
{
    char        magic[16];              // e.g. "dyld_v0     ppc"
    uint32_t    mappingOffset;          // file offset to first dyld_cache_mapping_info
    uint32_t    mappingCount;           // number of dyld_cache_mapping_info entries
    uint32_t    imagesOffset;           // file offset to first dyld_cache_image_info
    uint32_t    imagesCount;            // number of dyld_cache_image_info entries
    uint64_t    dyldBaseAddress;        // base address of dyld when cache was built
    uint64_t    codeSignatureOffset;    // file offset in of code signature blob
    uint64_t    codeSignatureSize;      // size of code signature blob (zero means to end of file)
    uint64_t    slideInfoOffset;        // file offset of kernel slide info
    uint64_t    slideInfoSize;          // size of kernel slide info
    uint64_t    localSymbolsOffset;     // file offset of where local symbols are stored
    uint64_t    localSymbolsSize;       // size of local symbols information
    uint8_t     uuid[16];               // unique value for each shared cache file
};

struct dyld_cache_mapping_info {
    uint64_t    address;
    uint64_t    size;
    uint64_t    fileOffset;
    uint32_t    maxProt;
    uint32_t    initProt;
};

struct dyld_cache_image_info
{
    uint64_t    address;
    uint64_t    modTime;
    uint64_t    inode;
    uint32_t    pathFileOffset;
    uint32_t    pad;
};

struct dyld_cache_slide_info
{
    uint32_t    version;        // currently 1
    uint32_t    toc_offset;
    uint32_t    toc_count;
    uint32_t    entries_offset;
    uint32_t    entries_count;
    uint32_t    entries_size;  // currently 128
    // uint16_t toc[toc_count];
    // entrybitmap entries[entries_count];
};

struct dyld_cache_local_symbols_info
{
    uint32_t    nlistOffset;        // offset into this chunk of nlist entries
    uint32_t    nlistCount;         // count of nlist entries
    uint32_t    stringsOffset;      // offset into this chunk of string pool
    uint32_t    stringsSize;        // byte count of string pool
    uint32_t    entriesOffset;      // offset into this chunk of array of dyld_cache_local_symbols_entry
    uint32_t    entriesCount;       // number of elements in dyld_cache_local_symbols_entry array
};

struct dyld_cache_local_symbols_entry
{
    uint32_t    dylibOffset;        // offset in cache file of start of dylib
    uint32_t    nlistStartIndex;    // start index of locals for this dylib
    uint32_t    nlistCount;         // number of local symbols for this dylib
};

class dyld_cache_t
{
private:
  // input file reference
  linput_t *li;
  // header
  dyld_cache_header header;
  // mappings
  qvector<dyld_cache_mapping_info> mappings;
  // image infos
  qvector <dyld_cache_image_info> image_infos;
  // image names
  qvector <qstring> image_names;

  // do we need to swap endianness?
  bool mf;
  // is file 64-bit?
  bool m64;

public:
  dyld_cache_t(linput_t *_li): li(_li) {}

  // check if file begins with a dyld cache header
  // must be called first
  bool parse_header();
  const char *get_arch();
  const qstring& get_image_name(int n) const { return image_names[n]; }
  const dyld_cache_mapping_info& get_mapping_info(int n) const { return mappings[n]; }
  const dyld_cache_image_info& get_image_info(int n) const { return image_infos[n]; }

  int get_numfiles() const { return image_infos.size(); }
  int get_nummappings() const { return mappings.size(); }
};

#endif // MACHO_COMMON_H
