// read symbols from a Mach-O file

#include "symelf.hpp"

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
  uint8                           _padding[2];
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

struct seg_info_t {
  ea_t    start;
  size_t  size;
  qstring name;
};

typedef qvector<seg_info_t> seg_infos_t;
typedef qvector<struct nlist_64> nlists_t;

typedef ssize_t (*read_memory_t)(ea_t ea, void *buffer, int size);
linput_t *create_mem_input(ea_t start, read_memory_t reader);
bool parse_macho(ea_t start, linput_t *li, symbol_visitor_t &sv, bool in_mem);
bool parse_macho_mem(ea_t start, read_memory_t reader, symbol_visitor_t &sv);
bool is_dyld_header(ea_t base, read_memory_t read_mem, char *filename, size_t namesize);
asize_t calc_macho_image_size(linput_t *li, ea_t *p_base = NULL);
bool read_macho_commands(linput_t *li, uint32 *p_off, bytevec_t &commands, int *ncmds);

// returns expected program base
ea_t parse_mach_commands(
        linput_t *li,
        uint32 off,
        const bytevec_t &load_commands,
        int ncmds,
        nlists_t *symbols,
        bytevec_t *strings,
        seg_infos_t* seg_infos = NULL,
        bool in_mem = false);
