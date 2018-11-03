#ifndef SYMMACHO_H
#define SYMMACHO_H

// read symbols from a Mach-O file

#include <map>

// Macho dyld information
typedef ea_t   CORE_ADDR;
typedef uint32 uint32_t;
typedef uval_t UINTPTR;

// http://www.opensource.apple.com/source/dyld/dyld-195.6/include/mach-o/dyld_images.h
// http://opensource.apple.com/source/gdb/gdb-1752/src/gdb/macosx/macosx-nat-dyld.c
struct dyld_raw_infos
{
  uint32_t version;        // 1 in Mac OS X 10.4 and 10.5
  uint32_t num_info;       // Number of elements in the following array

  /* Array of images (struct dyld_raw_info here in gdb) that are loaded
  in the inferior process.
  Note that this address may change over the lifetime of a process;
  as the array grows, dyld may need to realloc () the array.  So don't
  cache the value of info_array except while the inferior is stopped.
  This is either 4 or 8 bytes in the inferior, depending on wordsize.
  This value can be 0 (NULL) if dyld is in the middle of updating the
  array.  Currently, we'll just fail in that (unlikely) circumstance.  */

  CORE_ADDR info_array;

  /* Function called by dyld after a new dylib/bundle (or group of
  dylib/bundles) has been loaded, but before those images have had
  their initializer functions run.  This function has a prototype of

  void dyld_image_notifier (enum dyld_image_mode mode, uint32_t infoCount,
  const struct dyld_image_info info[]);

  Where mode is either dyld_image_adding (0) or dyld_image_removing (1).
  This is either 4 or 8 bytes in the inferior, depending on wordsize. */

  CORE_ADDR dyld_notify;
  uint8                           processDetachedFromSharedRegion;
  // the following fields are only in version 2 (Mac OS X 10.6, iPhoneOS 2.0) and later
  uint8                           libSystemInitialized;
  uint8                           _padding[sizeof(CORE_ADDR)-2];
  CORE_ADDR                       dyldImageLoadAddress;
  // the following field is only in version 3 (Mac OS X 10.6, iPhoneOS 3.0) and later
  CORE_ADDR                       jitInfo;
  // the following fields are only in version 5 (Mac OS X 10.6, iPhoneOS 3.0) and later
  CORE_ADDR                       dyldVersion;
  CORE_ADDR                       errorMessage;
  UINTPTR                         terminationFlags;
  // the following field is only in version 6 (Mac OS X 10.6, iPhoneOS 3.1) and later
  CORE_ADDR                       coreSymbolicationShmPage;
  // the following field is only in version 7 (Mac OS X 10.6, iPhoneOS 3.1) and later
  UINTPTR                         systemOrderFlag;
  // the following field is only in version 8 (Mac OS X 10.7, iPhoneOS 3.1) and later
  UINTPTR                         uuidArrayCount;
  CORE_ADDR                       uuidArray;      // only images not in dyld shared cache
  // the following field is only in version 9 (Mac OS X 10.7, iOS 4.0) and later
  CORE_ADDR                       dyldAllImageInfosAddress;
  // the following field is only in version 10 (Mac OS X 10.7, iOS 4.2) and later
  UINTPTR                         initialImageCount;
  // the following field is only in version 11 (Mac OS X 10.7, iOS 4.2) and later
  UINTPTR                         errorKind;
  CORE_ADDR                       errorClientOfDylibPath;
  CORE_ADDR                       errorTargetDylibPath;
  CORE_ADDR                       errorSymbol;
  // the following field is only in version 12 (Mac OS X 10.7, iOS 4.3) and later
  UINTPTR                         sharedCacheSlide;
  // the following field is only in version 13 (Mac OS X 10.9, iOS 7.0) and later
  uint8                           sharedCacheUUID[16];
  // the following field is only in version 15 (Mac OS X 10.12, iOS 10.0) and later
  CORE_ADDR                       sharedCacheBaseAddress;
};

struct dyld_raw_ranges
{
  UINTPTR sharedRegionsCount; /* how many ranges follow */
  struct
  {
    UINTPTR start;
    UINTPTR length;
  } ranges[4]; /* max regions */
};

/* A structure filled in by dyld in the inferior process.
Each dylib/bundle loaded has one of these structures allocated
for it.
Each field is either 4 or 8 bytes, depending on the wordsize of
the inferior process.  (including the modtime field - size_t goes to
64 bits in the 64 bit ABIs).  */

struct dyld_raw_info
{
  CORE_ADDR addr;               /* struct mach_header *imageLoadAddress */
  CORE_ADDR name;               /* const char *imageFilePath */
  CORE_ADDR modtime;            /* time_t imageFileModDate */
};

typedef qvector<dyld_raw_info> dyriv_t;

struct seg_info_t
{
  ea_t    start;
  size_t  size;
  qstring name;
};

typedef qvector<seg_info_t> seg_infos_t;
typedef qvector<struct nlist_64> nlists_t;

struct macho_visitor_t
{
  int flags;
#define MV_UUID             0x0001 // visit uuid
#define MV_FUNCTION_STARTS  0x0002 // visit function start eas
#define MV_SYMBOLS          0x0004 // visit symbols
#define MV_SEGMENTS         0x0008 // visit segments
#define MV_SECTIONS         0x0010 // visit sections

  macho_visitor_t(int _flags) : flags(_flags) {}

  virtual void visit_uuid(const bytevec_t & /*uuid*/) {}
  virtual void visit_function_start(ea_t /*ea*/) {}
  virtual void visit_symbol(ea_t /*ea*/, const char * /*name*/) {}
  virtual void visit_segment(ea_t /*start_ea*/, ea_t /*end_ea*/, const qstring & /*name*/, bool /*is_code*/) {}
  virtual void visit_section(ea_t /*start_ea*/, ea_t /*end_ea*/, const qstring & /*name*/, bool /*is_code*/) {}

  // called when function start info could not be found/loaded
  virtual void handle_function_start_error() {}
  // called just before a symbol is visited when cpu is CPU_TYPE_ARM
  virtual void handle_thumb(ea_t /*ea*/, const char * /*name*/, bool /*is_thumb*/) {}
};

struct macho_reader_t
{
  virtual ssize_t read(ea_t ea, void *buffer, int size) = 0;
};

linput_t *create_mem_input(ea_t start, macho_reader_t &reader);
bool parse_macho_file_ex(ea_t start, linput_t *li, macho_visitor_t &mv, int cputype);
bool parse_macho_file_pc(ea_t start, linput_t *li, macho_visitor_t &mv, bool is64);
bool parse_macho_file_arm(ea_t start, linput_t *li, macho_visitor_t &mv, bool is64);
bool is_dyld_header(ea_t base, macho_reader_t &read_mem, char *filename, size_t namesize);
bool is_dyld_header(ea_t base, macho_reader_t &read_mem, char *filename, size_t namesize, bool is64);
template<typename H> bool is_dyld_header_ex(ea_t base, macho_reader_t &reader, char *filename, size_t namesize, uint32 magic);
asize_t calc_macho_image_size_ex(linput_t *li, int cputype, ea_t *p_base = NULL);
asize_t calc_macho_image_size_pc(linput_t *li, bool is64, ea_t *p_base = NULL);
asize_t calc_macho_image_size_arm(linput_t *li, bool is64, ea_t *p_base = NULL);
bool read_macho_commands(linput_t *li, uint32 *p_off, bytevec_t &commands, int *ncmds);
bool match_macho_uuid_ex(linput_t *li, const bytevec_t &uuid, int cputype);
bool match_macho_uuid_arm(linput_t *li, const bytevec_t &uuid, bool is64);
bytevec_t calc_macho_uuid_ex(linput_t *li, int cputype);
bytevec_t calc_macho_uuid_arm(linput_t *li, bool is64);

typedef std::map<ea_t, qstring> strings_cache_t;
bool parse_macho_mem_ex(
        ea_t base,
        macho_reader_t &reader,
        macho_visitor_t &mv,
        strings_cache_t *cache,
        int cputype,
        bool shared_cache_lib);
bool parse_macho_mem_pc(
        ea_t base,
        macho_reader_t &reader,
        macho_visitor_t &mv,
        strings_cache_t *cache,
        bool is64,
        bool shared_cache_lib);
bool parse_macho_mem_arm(
        ea_t base,
        macho_reader_t &reader,
        macho_visitor_t &mv,
        strings_cache_t *cache,
        bool is64,
        bool shared_cache_lib);

// returns expected program base
ea_t parse_mach_commands(
        linput_t *li,
        uint32 off,
        const bytevec_t &load_commands,
        int ncmds,
        nlists_t *symbols,
        bytevec_t *strings,
        seg_infos_t *seg_infos = NULL,
        bool in_mem = false);

struct dyld_cache_visitor_t
{
  int flags;
#define DCV_MAPPINGS 0x1 // visit shared region mappings

  dyld_cache_visitor_t(int _flags) : flags(_flags) {}

  virtual void visit_mapping(ea_t /*start_ea*/, ea_t /*end_ea*/) {}
};

// parse the dyld shared cache header in memory
bool parse_dyld_cache_mem(ea_t base, macho_reader_t &reader, dyld_cache_visitor_t &dcv);

#endif // SYMMACHO_H
