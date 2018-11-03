// read Mach-O symbols

#include <pro.h>
#include <idp.hpp>
#include <kernwin.hpp>
#include <diskio.hpp>
#include "../../ldr/ar/ar.hpp"
#include "../../ldr/ar/aixar.hpp"
#include "../../ldr/ar/arcmn.cpp" // for is_ar_file
#include "../../ldr/mach-o/common.cpp"
#include "symmacho.hpp"

//lint -esym(1762, macho_file_t::select_ar_module) could be made const
bool macho_file_t::select_ar_module(size_t, size_t) { return false; }
bool macho_file_t::is_loaded_addr(uint64) const { return true; }

//--------------------------------------------------------------------------
linput_t *create_mem_input(ea_t start, macho_reader_t &reader)
{
  struct ida_local meminput_t : public generic_linput_t
  {
    ea_t start;
    macho_reader_t &reader;
    meminput_t(ea_t _start, macho_reader_t &_reader) : start(_start), reader(_reader)
    {
      // macho images in memory have indeterminate size.
      // set it to the max possible size to keep anybody from complaining.
      filesize = INT_MAX;
      blocksize = 0;
    }
    virtual ssize_t idaapi read(qoff64_t off, void *buffer, size_t nbytes)
    {
      return reader.read(start+off, buffer, nbytes);
    }
  };
  meminput_t *pmi = new meminput_t(start, reader);
  return create_generic_linput(pmi);
}

//--------------------------------------------------------------------------
static bool parse_macho_init(macho_file_t &mfile, int cputype, ea_t start, sval_t *slide)
{
  if ( !mfile.parse_header()
    || !mfile.select_subfile(cputype) )
  {
    msg("Warning: bad file or could not find a member with matching cpu type\n");
    return false;
  }

  ea_t expected_base = BADADDR;
  const segcmdvec_t &segcmds = mfile.get_segcmds();

  for ( size_t i=0; i < segcmds.size(); i++ )
  {
    const segment_command_64 &sg = segcmds[i];
    if ( is_text_segment(sg) && expected_base == BADADDR )
    {
      expected_base = sg.vmaddr;
      break;
    }
  }

  if ( expected_base == BADADDR )
    return false;

  if ( slide != NULL )
    *slide = start - expected_base;

  return true;
}

//--------------------------------------------------------------------------
static void visit_macho_segments(macho_file_t &mfile, macho_visitor_t &mv, sval_t slide)
{
  const segcmdvec_t &segcmds = mfile.get_segcmds();

  for ( size_t i=0; i < segcmds.size(); i++ )
  {
    const segment_command_64 &sg = segcmds[i];

    qstring segname(sg.segname, sizeof(sg.segname));

    mv.visit_segment(
        sg.vmaddr + slide,
        sg.vmaddr + sg.vmsize + slide,
        segname,
        (sg.flags & VM_PROT_EXECUTE) != 0 || segname == SEG_TEXT);
  }
}

//--------------------------------------------------------------------------
static void visit_macho_sections(macho_file_t &mfile, macho_visitor_t &mv, sval_t slide)
{
  const segcmdvec_t &segcmds = mfile.get_segcmds();
  const secvec_t &sections = mfile.get_sections();

  // special check for the header
  if ( segcmds.size() > 0
    && sections.size() > 0
    && streq(segcmds[0].segname, SEG_TEXT)
    && segcmds[0].vmaddr < sections[0].addr )
  {
    mv.visit_section(
        segcmds[0].vmaddr + slide,
        sections[0].addr + slide,
        "HEADER",
        false);
  }

  for ( size_t i=0; i < sections.size(); i++ )
  {
    const section_64 &sect = sections[i];

    mv.visit_section(
        sect.addr + slide,
        sect.addr + sect.size + slide,
        qstring(sect.sectname, sizeof(sect.sectname)),
        (sect.flags & (S_ATTR_PURE_INSTRUCTIONS|S_ATTR_SOME_INSTRUCTIONS)) != 0);
  }
}

//--------------------------------------------------------------------------
static void visit_macho_symbols(
        const nlistvec_t &symbols,
        const qstring &strings,
        macho_visitor_t &mv,
        sval_t slide,
        int cputype)
{
  for ( size_t i=0; i < symbols.size(); i++ )
  {
    const struct nlist_64 &nl = symbols[i];
    if ( nl.n_un.n_strx > strings.size() )
      continue;

    const char *name = &strings[nl.n_un.n_strx];
    if ( qstrlen(name) == 0 )
      continue;

    ea_t ea = nl.n_value + slide;

    // symbolic debugger symbol
    if ( nl.n_type == N_FUN || nl.n_type == N_STSYM )
    {
      mv.visit_symbol(ea, name);
      continue;
    }

    int type = nl.n_type & N_TYPE;
    switch ( type )
    {
      case N_UNDF:
      case N_PBUD:
      case N_ABS:
        break;
      case N_SECT:
      case N_INDR:
        if ( ((nl.n_type & (N_EXT|N_PEXT)) == N_EXT)    // exported
          || (type == N_SECT && nl.n_sect != NO_SECT) ) // private symbols
        {
          if ( cputype == CPU_TYPE_ARM )
            mv.handle_thumb(ea, name, (nl.n_desc & 0xF) == N_ARM_THUMB_DEF);

          mv.visit_symbol(ea, name);
        }
        break;
      default:
        break;
    }
  }
}

//--------------------------------------------------------------------------
static void visit_macho_function_starts(
        macho_file_t &mfile,
        macho_visitor_t &mv,
        sval_t slide,
        int cputype)
{
  struct ida_local symmacho_fsv_t : public function_starts_visitor_t
  {
    macho_visitor_t &mv;
    sval_t slide;
    int cputype;

    symmacho_fsv_t(macho_visitor_t &_mv, sval_t _slide, int _cputype)
      : mv(_mv), slide(_slide), cputype(_cputype) {}

    virtual int visit_start(uint64_t address)
    {
      // create a debugger-friendly address
      if ( cputype == CPU_TYPE_ARM && (address & 1) != 0 )
        address ^= 1;
      mv.visit_function_start(address + slide);
      return 0;
    }
    virtual void handle_error()
    {
      mv.handle_function_start_error();
    }
  };

  symmacho_fsv_t fsv(mv, slide, cputype);
  mfile.visit_function_starts(fsv);
}

//--------------------------------------------------------------------------
static void visit_macho_uuid(macho_file_t &mfile, macho_visitor_t &mv)
{
  uint8 uuid[16];
  if ( mfile.get_uuid(uuid) )
  {
    bytevec_t bv(uuid, sizeof(uuid));
    mv.visit_uuid(bv);
  }
}

//--------------------------------------------------------------------------
bool parse_macho_file_ex(ea_t start, linput_t *li, macho_visitor_t &mv, int cputype)
{
  sval_t slide = 0;
  macho_file_t mfile(li);

  if ( !parse_macho_init(mfile, cputype, start, &slide) )
    return false;

  if ( (mv.flags & MV_UUID) != 0 )
    visit_macho_uuid(mfile, mv);

  if ( (mv.flags & MV_FUNCTION_STARTS) != 0 )
    visit_macho_function_starts(mfile, mv, slide, cputype);

  if ( (mv.flags & MV_SEGMENTS) != 0 )
    visit_macho_segments(mfile, mv, slide);

  if ( (mv.flags & MV_SECTIONS) != 0 )
    visit_macho_sections(mfile, mv, slide);

  if ( (mv.flags & MV_SYMBOLS) != 0 )
  {
    qstring strings;
    nlistvec_t symbols;
    mfile.get_symbol_table_info(&symbols, &strings);
    visit_macho_symbols(symbols, strings, mv, slide, cputype);
  }

  return true;
}

//--------------------------------------------------------------------------
bool parse_macho_mem_ex(
        ea_t start,
        macho_reader_t &reader,
        macho_visitor_t &mv,
        strings_cache_t *cache,
        int cputype,
        bool shared_cache_lib)
{
  linput_t *li = create_mem_input(start, reader);
  if ( li == NULL )
    return false;

  linput_janitor_t janitor(li);

  sval_t slide = 0;
  macho_file_t mfile(li, 0, MACHO_HINT_MEM_IMAGE|(shared_cache_lib ? MACHO_HINT_SHARED_CACHE_LIB : 0));

  if ( !parse_macho_init(mfile, cputype, start, &slide) )
    return false;

  if ( (mv.flags & MV_UUID) != 0 )
    visit_macho_uuid(mfile, mv);

  if ( (mv.flags & MV_FUNCTION_STARTS) != 0 )
    visit_macho_function_starts(mfile, mv, slide, cputype);

  if ( (mv.flags & MV_SEGMENTS) != 0 )
    visit_macho_segments(mfile, mv, slide);

  if ( (mv.flags & MV_SECTIONS) != 0 )
    visit_macho_sections(mfile, mv, slide);

  if ( (mv.flags & MV_SYMBOLS) != 0 )
  {
    struct symtab_command st = { 0 };
    if ( !mfile.get_symtab_command(&st) )
      return false;

    nlistvec_t symbols;
    mfile.get_symbol_table(st, &symbols);

    if ( cache == NULL )
    {
      qstring strings;
      mfile.get_string_table(st, &strings);
      visit_macho_symbols(symbols, strings, mv, slide, cputype);
    }
    else
    {
      // check if this is a new string table
      strings_cache_t::const_iterator i = cache->find(st.stroff);
      if ( i == cache->end() )
      {
        qstring buf;
        mfile.get_string_table(st, &buf);
        const qstring &strings = cache->insert(std::make_pair(st.stroff, buf)).first->second;
        visit_macho_symbols(symbols, strings, mv, slide, cputype);
      }
      else
      {
        // if not, use the existing one
        visit_macho_symbols(symbols, i->second, mv, slide, cputype);
      }
    }
  }

  return true;
}

//--------------------------------------------------------------------------
bool parse_macho_file_pc(ea_t start, linput_t *li, macho_visitor_t &mv, bool is64)
{
  return parse_macho_file_ex(start, li, mv, is64 ? CPU_TYPE_X86_64 : CPU_TYPE_I386);
}

//--------------------------------------------------------------------------
bool parse_macho_file_arm(ea_t base, linput_t *li, macho_visitor_t &mv, bool is64)
{
  return parse_macho_file_ex(base, li, mv, is64 ? CPU_TYPE_ARM64 : CPU_TYPE_ARM);
}

//--------------------------------------------------------------------------
bool parse_macho_mem_pc(
        ea_t base,
        macho_reader_t &reader,
        macho_visitor_t &mv,
        strings_cache_t *cache,
        bool is64,
        bool shared_cache_lib)
{
  return parse_macho_mem_ex(
      base,
      reader,
      mv,
      cache,
      is64 ? CPU_TYPE_X86_64 : CPU_TYPE_I386,
      shared_cache_lib);
}

//--------------------------------------------------------------------------
bool parse_macho_mem_arm(
        ea_t base,
        macho_reader_t &reader,
        macho_visitor_t &mv,
        strings_cache_t *cache,
        bool is64,
        bool shared_cache_lib)
{
  return parse_macho_mem_ex(
      base,
      reader,
      mv,
      cache,
      is64 ? CPU_TYPE_ARM64 : CPU_TYPE_ARM,
      shared_cache_lib);
}

//--------------------------------------------------------------------------
bool match_macho_uuid_ex(linput_t *li, const bytevec_t &uuid, int cputype)
{
  macho_file_t mfile(li);

  return mfile.parse_header()
      && mfile.select_subfile(cputype)
      && mfile.match_uuid(uuid);
}

//--------------------------------------------------------------------------
bool match_macho_uuid_arm(linput_t *li, const bytevec_t &uuid, bool is64)
{
  return match_macho_uuid_ex(li, uuid, is64 ? CPU_TYPE_ARM64 : CPU_TYPE_ARM);
}

//--------------------------------------------------------------------------
asize_t calc_macho_image_size_ex(linput_t *li, int cputype, ea_t *p_base)
{
  if ( li == NULL )
    return 0;
  if ( p_base != NULL )
    *p_base = BADADDR;

  macho_file_t mfile(li);

  if ( !mfile.parse_header()
    || !mfile.select_subfile(cputype) )
  {
    msg("Warning: bad file or could not find a member with matching cpu type\n");
    return 0;
  }

  // load sections
  const segcmdvec_t &segcmds = mfile.get_segcmds();

  ea_t base = BADADDR;
  ea_t maxea = 0;
  for ( size_t i=0; i < segcmds.size(); i++ )
  {
    const segment_command_64 &sg = segcmds[i];
    // since mac os x scatters application segments over the memory
    // we calculate only the text segment size
    if ( is_text_segment(sg) )
    {
      if ( base == BADADDR )
        base = sg.vmaddr;
      ea_t end = sg.vmaddr + sg.vmsize;
      if ( maxea < end )
        maxea = end;
    }
  }

  asize_t size = maxea - base;
  if ( p_base != NULL )
    *p_base = base;

  return size;
}

//--------------------------------------------------------------------------
asize_t calc_macho_image_size_pc(linput_t *li, bool is64, ea_t *p_base)
{
  return calc_macho_image_size_ex(li, is64 ? CPU_TYPE_X86_64 : CPU_TYPE_I386, p_base);
}

//--------------------------------------------------------------------------
asize_t calc_macho_image_size_arm(linput_t *li, bool is64, ea_t *p_base)
{
  return calc_macho_image_size_ex(li, is64 ? CPU_TYPE_ARM64 : CPU_TYPE_ARM, p_base);
}

//--------------------------------------------------------------------------
bytevec_t calc_macho_uuid_ex(linput_t *li, int cputype)
{
  uint8 uuid[16];
  macho_file_t mfile(li);

  return mfile.parse_header()
      && mfile.select_subfile(cputype)
      && mfile.get_uuid(uuid) ? bytevec_t(uuid, sizeof(uuid)) : bytevec_t();
}

//--------------------------------------------------------------------------
bytevec_t calc_macho_uuid_arm(linput_t *li, bool is64)
{
  return calc_macho_uuid_ex(li, is64 ? CPU_TYPE_ARM64 : CPU_TYPE_ARM);
}

//--------------------------------------------------------------------------
template <typename H> bool is_dyld_header_ex(
        ea_t base,
        macho_reader_t &reader,
        char *filename,
        size_t namesize,
        uint32 magic)
{
  H mh;
  if ( reader.read(base, &mh, sizeof(mh)) != sizeof(mh) )
    return false;

  if ( mh.magic != magic || mh.filetype != MH_DYLINKER )
    return false;

  // seems to be dylib
  // find its file name
  filename[0] = '\0';
  ea_t ea = base + sizeof(mh);
  for ( int i=0; i < mh.ncmds; i++ )
  {
    struct load_command lc;
    lc.cmd = 0;
    reader.read(ea, &lc, sizeof(lc));
    if ( lc.cmd == LC_ID_DYLIB )
    {
      struct dylib_command dcmd;
      reader.read(ea, &dcmd, sizeof(dcmd));
      reader.read(ea+dcmd.dylib.name.offset, filename, namesize);
      break;
    }
    else if ( lc.cmd == LC_ID_DYLINKER )
    {
      struct dylinker_command dcmd;
      reader.read(ea, &dcmd, sizeof(dcmd));
      reader.read(ea+dcmd.name.offset, filename, namesize);
      break;
    }
    ea += lc.cmdsize;
  }
  return true;
}

//--------------------------------------------------------------------------
static bool is_dyld_header_64(ea_t base, macho_reader_t &reader, char *filename, size_t namesize)
{
  return is_dyld_header_ex<mach_header_64>(base, reader, filename, namesize, MH_MAGIC_64);
}

//--------------------------------------------------------------------------
static bool is_dyld_header_32(ea_t base, macho_reader_t &reader, char *filename, size_t namesize)
{
  return is_dyld_header_ex<mach_header>(base, reader, filename, namesize, MH_MAGIC);
}

//--------------------------------------------------------------------------
bool is_dyld_header(ea_t base, macho_reader_t &reader, char *filename, size_t namesize, bool is64)
{
  return is64
       ? is_dyld_header_64(base, reader, filename, namesize)
       : is_dyld_header_32(base, reader, filename, namesize);
}

//--------------------------------------------------------------------------
bool parse_dyld_cache_mem(
        ea_t base,
        macho_reader_t &reader,
        dyld_cache_visitor_t &dcv)
{
  linput_t *li = create_mem_input(base, reader);
  if ( li == NULL )
    return false;

  dyld_cache_t dyldcache(li);
  linput_janitor_t janitor(li);

  uint32 hflags = (dcv.flags & DCV_MAPPINGS) != 0 ? PHF_MAPPINGS : 0;

  if ( !dyldcache.parse_header(hflags) )
    return false;

  if ( (dcv.flags & DCV_MAPPINGS) != 0 )
  {
    for ( int i = 0, nmaps = dyldcache.get_nummappings(); i < nmaps; i++ )
    {
      const dyld_cache_mapping_info &mi = dyldcache.get_mapping_info(i);
      dcv.visit_mapping(mi.address, mi.address+mi.size);
    }
  }

  return true;
}
