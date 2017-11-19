
// read elf symbols

#include <fpro.h>
#include <kernwin.hpp>
#include <diskio.hpp>
#include "../../ldr/elf/elfbase.h"
#include "../../ldr/elf/elf.h"
#include "debmod.h"
#include "symelf.hpp"

#define NO_ERRSTRUCT
//#define errstruct() warning("bad input file structure")

#include "../../ldr/elf/common.cpp"
#include "../../ldr/elf/reader.cpp"

inline uint32 low(uint32 x) { return x; }

uval_t imagebase;

//--------------------------------------------------------------------------
//lint -e{1764} could be declared const ref
static int handle_symbol(
        reader_t &reader,
        int shndx,
        int _info,
        uint32 st_name,
        uval_t st_value,
        int namsec,
        symbol_visitor_t &sv)
{
  if ( shndx == SHN_UNDEF
    || shndx == SHN_LOPROC
    || shndx == SHN_HIPROC
    || shndx == SHN_ABS )
  {
    return 0;
  }

  int type = ELF_ST_TYPE(_info);
  if ( type != STT_OBJECT && type != STT_FUNC )
    return 0;

  if ( st_name == 0 )
    return 0;

  if ( imagebase != uval_t(-1) )
    st_value -= imagebase;

  qstring name;
  reader.sections.get_name(&name, namsec, st_name);
  return sv.visit_symbol(st_value, name.c_str());
}

//--------------------------------------------------------------------------
static int load_symbols(
        reader_t &reader,
        const elf_shdr_t &section,
        int namsec,
        symbol_visitor_t &sv)
{
  int code = 0;
  sym_rel *sym;
  buffered_input_t<sym_rel> symbols_input(reader, section);
  for ( int i = 0; code == 0 && symbols_input.next(sym); i++ )
  {
    if ( i == 0 ) // skip _UNDEF
      continue;

    code = handle_symbol(reader,
                         sym->original.st_shndx,
                         sym->original.st_info,
                         sym->original.st_name,
                         sym->original.st_value,
                         namsec,
                         sv);
  }
  return code;
}

//--------------------------------------------------------------------------
static bool map_pht(reader_t &reader)
{
  if ( !reader.read_program_headers() )
    return false;

  imagebase = reader.pheaders.get_image_base();
  return true;
}

//----------------------------------------------------------------------------
static bool silent_handler(const reader_t &reader, reader_t::errcode_t code, ...)
{
  return reader.is_warning(code); // resume after warnings
}

//--------------------------------------------------------------------------
static int _load_elf_symbols(linput_t *li, symbol_visitor_t &sv)
{
  reader_t reader(li);
  reader.set_handler(silent_handler);
  if ( !reader.read_ident() || !reader.read_header() )
    return -1;

  const elf_ident_t &ident = reader.get_ident();
  uint8 elf_class = ident.elf_class;
  if ( elf_class != ELFCLASS32 && elf_class != ELFCLASS64  )
    return -1;

  uint8 elf_data_ord = ident.bytesex;
  if ( elf_data_ord != ELFDATA2LSB && elf_data_ord != ELFDATA2MSB )
    return -1;

  section_headers_t &sections = reader.sections;
  dynamic_linking_tables_t dlt;

  int code = 0;
  elf_ehdr_t &header = reader.get_header();
  if ( header.e_phnum && !map_pht(reader) )
    return -1;

  if ( header.e_shnum && header.e_shentsize )
    reader.read_section_headers();

  // Try and acquire dynamic linking tables info.
  dlt = reader.sections.get_dynamic_linking_tables_info();
  if ( !dlt.is_valid() )
    dlt = reader.pheaders.get_dynamic_linking_tables_info();

  // Parse dynamic info if available
  dynamic_info_t di;
  if ( dlt.is_valid() )
  {
    if ( (sv.velf & VISIT_DYNINFO) != 0 )
    {
      int link = dlt.link;
      if ( link == 0 )
      {
        elf_shdr_t *dsh = sections.get_wks(WKS_DYNSYM);
        if ( dsh != NULL )
          link = dsh->sh_link;
      }
      class ida_local my_handler_t : public dynamic_info_handler_t
      {
        symbol_visitor_t &visitor;
        int link;
      public:
        my_handler_t(reader_t &_r, int _l, symbol_visitor_t &_sv)
          : dynamic_info_handler_t(_r),
            visitor(_sv),
            link(_l)
        {
        }

        virtual int handle(const elf_dyn_t &dyn)
        {
          qstring name;
          switch ( dyn.d_tag )
          {
            case DT_SONAME:
            case DT_RPATH:
            case DT_RUNPATH:
            case DT_NEEDED:
              reader.sections.get_name(&name, link, dyn.d_un);
              break;
          }
          return visitor.visit_dyninfo(dyn.d_tag, name.c_str(), dyn.d_un);
        };
      };
      my_handler_t handler(reader, link, sv);
      code = reader.parse_dynamic_info(dlt, di, handler);
    }
    else
    {
      reader.parse_dynamic_info(dlt, di);
    }
  }

  int interp = sections.get_index(WKS_INTERP);
  if ( interp != 0
    && (sv.velf & VISIT_INTERP) != 0 )
  {
    qstring name;
    sections.get_name(&name, interp, 0);
    code = sv.visit_interp(name.c_str());
    if ( code != 0 )
      return code;
  }

  if ( (sv.velf & VISIT_SYMBOLS) != 0 )
  {
    int symtab = sections.get_index(WKS_SYMTAB);
    int dynsym = sections.get_index(WKS_DYNSYM);
    int strtab = sections.get_index(WKS_STRTAB);
    int dynstr = sections.get_index(WKS_DYNSTR);
    if ( symtab != 0 || dynsym != 0 )
    {
      // Loading symbols
      if ( symtab != 0 )
        code = load_symbols(reader, *sections.getn(symtab), strtab, sv);
      if ( code == 0 && dynsym != 0 )
        code = load_symbols(reader, *sections.getn(dynsym), dynstr, sv);
    }
    else if ( di.symtab.size != 0 )
    {
      elf_shdr_t fake_section;
      di.fill_section_header(reader, di.symtab, fake_section);
      code = load_symbols(reader, fake_section, -1, sv);
    }
  }

  return code;
}

//--------------------------------------------------------------------------
int load_linput_elf_symbols(linput_t *li, symbol_visitor_t &sv)
{
  if ( li == NULL )
    return -1;
  int code;
  // there is thread unsafe code in elf handling, so use locks
  lock_begin();
  {
    code = _load_elf_symbols(li, sv);
  }
  lock_end();
  close_linput(li);
  return code;
}

//--------------------------------------------------------------------------
int load_elf_symbols(const char *fname, symbol_visitor_t &sv, bool remote)
{
  return load_linput_elf_symbols(open_linput(fname, remote), sv);
}
