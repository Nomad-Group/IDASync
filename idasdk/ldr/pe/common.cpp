
// unfortunately we can not include map here because vs32 bombs trying to compile efd\di.cpp
//#include <map>
#include <auto.hpp>
#include "common.h"
#include "../idaldr.h"

//------------------------------------------------------------------------
#ifdef LOADER_SOURCE // building a loader?
AS_PRINTF(1, 2) inline void pe_failure(const char *format, ...)
{
  va_list va;
  va_start(va, format);
  qstring question("AUTOHIDE REGISTRY\n");
  question.cat_vsprnt(format, va);
  question.append("\nDo you wish to continue?");
  if ( askyn_c(ASKBTN_YES, "%s", question.c_str()) != ASKBTN_YES )
  {
    loader_failure(NULL);
  }
  va_end(va);
}
#else
// for other purposes: just print the error message and continue
AS_PRINTF(1, 2) inline void pe_failure(const char *format, ...)
{
  va_list va;
  va_start(va, format);
  qvprintf(format, va);
  qprintf("\n");
  va_end(va);
}
#endif

//------------------------------------------------------------------------
inline bool pe64_to_pe(peheader_t &pe, const peheader64_t &pe64, bool silent, bool zero_bad_data)
{
  bool ok = true;
  switch ( pe64.magic )
  {
    default:
      if ( !silent )
      {
        ask_for_feedback("The input file has non-standard magic number (%x)",
          pe64.magic);
      }
      ok = false;
      /* no break */
    case MAGIC_P32:
    case MAGIC_ROM:
    case 0:
      memcpy(&pe, &pe64, sizeof(pe));
      break;
    case MAGIC_P32_PLUS:
      // Copy the constant part
      memcpy(&pe, &pe64, offsetof(peheader_t, stackres));

      // Copy after the changed part
      memcpy(&pe.loaderflags, &pe64.loaderflags,
        sizeof(pe) - qoffsetof(peheader_t, loaderflags));

      // Truncate the 64bit to 32bit
      pe.stackres  = low(pe64.stackres);
      pe.stackcom  = low(pe64.stackcom);
      pe.heapres   = low(pe64.heapres);
      pe.heapcom   = low(pe64.heapcom);
      break;
  }
  // Do various checks
  if ( !pe.is_efi()
    && (pe.objalign < pe.filealign
    || pe.filealign !=0 && (pe.filealign & (pe.filealign-1) ) != 0   // check for power of 2
    || pe.objalign  !=0 && (pe.objalign  & (pe.objalign -1) ) != 0) ) // check for power of 2
  {
    if ( !silent )
      pe_failure("Invalid file: bad alignment value specified (section alignment: %08X, file alignment: %08X)", pe.objalign, pe.filealign);
  }
  if ( pe.imagesize > 0x77000000 || pe.imagesize < pe.allhdrsize )
  {
    if ( !silent )
      pe_failure("Invalid file: bad ImageSize value %x", pe.imagesize);
  }

  if ( zero_bad_data && pe.nrvas != 0 && pe.nrvas < total_rvatab_count )
    memset(&pe.expdir + pe.nrvas, 0, total_rvatab_size - pe.nrvas * sizeof(petab_t));
  return ok;
}

//------------------------------------------------------------------------
inline bool te_to_pe(peheader_t &pe, const teheader_t &te)
{
  bool ok = true;
  memset(&pe, 0, sizeof(pe));
  pe.signature = te.signature;
  pe.machine   = te.machine;
  pe.nobjs     = te.nobjs;
  pe.magic     = pe.is_64bit_cpu() ? MAGIC_P32_PLUS : MAGIC_P32;
  pe.entry     = te.entry;
  pe.text_start = te.text_start;
  pe.allhdrsize = te.text_start + te.te_adjust();
  if ( pe.is_pe_plus() )
    pe.imagebase64 = te.imagebase64;
  else
    pe.imagebase32 = te.imagebase64;
  pe.subsys    = te.subsys;
  pe.reltab    = te.reltab;
  pe.debdir    = te.debdir;
  pe.objalign  = 1;
  pe.filealign = 1;
  return ok;
}

//------------------------------------------------------------------------
inline bool pe_loader_t::read_header(linput_t *li, off_t _peoff, bool silent, bool zero_bad_data)
{
  peoff = _peoff;
  qlseek(li, peoff);
  memset(&pe64, 0, sizeof(pe64));
  qlseek(li, peoff);
  size_t size = qlread(li, &pe64, sizeof(pe64));
  size_t minsize = pe64.magic == MAGIC_P32_PLUS
                 ? qoffsetof(peheader64_t, subsys)
                 : qoffsetof(peheader_t, subsys);
  bool ok = size > minsize
         && size <= sizeof(pe64)
         && (pe64.signature == PEEXE_ID || pe64.signature == BPEEXE_ID || pe64.signature == PLEXE_ID)
    && pe64_to_pe(pe, pe64, silent, zero_bad_data);
  if ( ok  )
  {
    //initialize imagebase for loading
    set_imagebase((ea_t)pe.imagebase());
  }
  return ok;
}

//------------------------------------------------------------------------
inline bool pe_loader_t::read_header(linput_t *li, bool silent, bool zero_bad_data)
{
  uint32 hdroff = 0;
  link_ulink = false;

  qlseek(li, hdroff);
  lread(li, &exe, sizeof(exe));
  if ( exe.exe_ident != PEEXE_ID )
  {
    if ( exe.exe_ident == TEEXE_ID )
    {
      qlseek(li, hdroff);
      lread(li, &te, sizeof(te));
      bool ok = te_to_pe(pe, te);
      if ( ok  )
      {
        //initialize imagebase for loading
        set_imagebase((ea_t)pe.imagebase());
        peoff = hdroff;
      }
      return ok;
    }
    if ( exe.exe_ident == EXE_ID || exe.exe_ident == EXE_ID2 )
    {
      char tmp[8];
      if ( qlread(li, tmp, sizeof(tmp)) == sizeof(tmp)
        && memcmp(tmp, "UniLink", 8) == 0 )
      {
        link_ulink = true;
      }
      qlseek(li, PE_PTROFF);
      lread(li, &hdroff, sizeof(hdroff));
    }
  }
  return read_header(li, hdroff, silent, zero_bad_data);
}

//------------------------------------------------------------------------
// NB! We need to walk the mapping backwards, because
// the later sections take priority over earlier ones
//
// e.g. consider
// section 0: start=1000, end=5000, pos=1000
// section 1: start=3000, end=4000, pos=5000
// for byte at RVA 3500:
// section 0 maps it from the file offset 3500
// but section 1 overrides it with the byte from file offset 5500!
//
inline ea_t pe_loader_t::map_ea(ea_t rva, const transl_t **tl)
{
  for ( ssize_t i=transvec.size()-1; i >= 0 ; i-- )
  {
    const transl_t &trans = transvec[i];
    if ( trans.start <= rva && trans.end > rva )
    {
      if ( tl != NULL )
        *tl = &trans;
      return rva-trans.start + trans.pos;
    }
  }
  return BADADDR;
}

//------------------------------------------------------------------------
inline bool pe_loader_t::vseek(linput_t *li, uint32 rva)
{
  ea_t fpos = get_linput_type(li) == LINPUT_PROCMEM ? rva : map_ea(rva);
  if ( fpos != BADADDR )
  {
    qlseek(li, fpos);
    return true;
  }
  qlseek(li, rva, SEEK_SET);
  return false;
}

//------------------------------------------------------------------------
inline char *pe_loader_t::asciiz(linput_t *li, uint32 rva, char *buf, size_t bufsize, bool *ok)
{
  bool _ok = vseek(li, rva);
  if ( !_ok && ok != NULL )
    *ok = false;
  return qlgetz(li, -1, buf, bufsize);
}

//------------------------------------------------------------------------
inline int pe_loader_t::process_sections(
        linput_t *li,
        off_t first_sec_pos,
        int nobjs,
        pe_section_visitor_t &psv)
{
  transvec.qclear();
  qvector<pesection_t> sec_headers;
  // does the file layout match memory layout?
  bool alt_align = pe.objalign == pe.filealign && pe.objalign < PAGE_SIZE;
  qlseek(li, first_sec_pos);
  validate_array_count(li, &nobjs, sizeof(pesection_t), "Number of sections");
  for ( int i=0; i < nobjs; i++ )
  {
    pesection_t &sh = sec_headers.push_back();
    lread(li, &sh, sizeof(sh));
    if ( sh.s_vaddr != uint32(sh.s_scnptr) || sh.s_vsize > sh.s_psize )
      alt_align = false;
  }
  if ( alt_align || pe.is_te() )
  {
    // according to Ivan Teblin from AVERT Labs, such files are
    // mapped by Windows as-is and not section by section
    // we mimic that behaviour
    int code = psv.load_all();
    if ( code != 0 )
      return code;
  }

  int off_align = alt_align ? pe.filealign : FILEALIGN;
  if ( pe.is_efi() || pe.is_te() )
    off_align = 1;

  uint32 max_va = 0;
  for ( int i=0; i < nobjs; i++ )
  {
    pesection_t &sh = sec_headers[i];
    uint32 scnptr = align_down(sh.s_scnptr, off_align);//pe.align_down_in_file(sh.s_scnptr);
    transl_t &tr = transvec.push_back();
    tr.start = sh.s_vaddr;
    tr.psize = sh.get_psize(pe);
    tr.end   = pe.align_up_in_file(uint32(sh.s_vaddr + tr.psize));
    tr.pos   = scnptr;
    if ( pe.is_te() )
      tr.pos += te.te_adjust();
    int code = psv.visit_section(sh, scnptr);
    if ( code != 0 )
      return code;
    if ( max_va < sh.s_vaddr + sh.s_vsize )
       max_va = sh.s_vaddr + sh.s_vsize;
  }
  if ( pe.is_te() )
    pe.imagesize = max_va;
  if ( nobjs == 0 || alt_align )
  {
    // add mapping for the header
    transl_t tr;
    tr.start = 0;
    tr.psize = qlsize(li);
    tr.end   = pe.align_up_in_file(pe.imagesize);
    tr.pos   = 0;
    // insert at the front so that it's always consulted last
    transvec.insert(transvec.begin(), tr);
  }
  return 0;
}

//------------------------------------------------------------------------
inline int pe_loader_t::process_sections(linput_t *li, pe_section_visitor_t &psv)
{
  off_t first_sec_pos = pe.is_te() ? te.first_section_pos(peoff) : pe.first_section_pos(peoff);
  return process_sections(li, first_sec_pos, pe.nobjs, psv);
}

//------------------------------------------------------------------------
inline int pe_loader_t::process_sections(linput_t *li)
{
  pe_section_visitor_t v;
  return process_sections(li, v);
}

//------------------------------------------------------------------------
// process import table for one dll
inline int pe_loader_t::process_import_table(
        linput_t *li,
        ea_t atable,
        ea_t ltable,
        pe_import_visitor_t &piv)
{
  bool is_pe_plus = pe.is_pe_plus();
  int elsize = piv.elsize = is_pe_plus ? 8 : 4;
  const uint64 mask = is_pe_plus ? IMP_BY_ORD64 : IMP_BY_ORD32;
  bool ok = true;
  int i;
  for ( i=0; ok; i++, atable += elsize )
  {
    char buf[MAXSTR];
    ea_t rva = ltable + i * elsize;
    if ( piv.withbase )
      rva -= (uval_t)pe.imagebase();
    uint32 fof = uint32(rva);
    uint64 entry = is_pe_plus ? vaint64(li, fof, &ok) : valong(li, fof, &ok);
    if ( entry == 0 )
      break;
    showAddr(atable);

    int code;
    if( (entry & mask) == 0 )   // by name
    {
      ea_t nrva = (uval_t)entry + sizeof(short);
      if ( piv.withbase )
        nrva -= (uval_t)pe.imagebase();
      fof = uint32(nrva);
      asciiz(li, fof, buf, sizeof(buf), &ok);
      if ( !win_utf2idb(buf) )
        ansi2idb(buf);
      code = piv.visit_import(atable, entry, buf);
    }
    else
    {
      // ordinals are always 32bit, even in pe64
      uint32 ord = entry & ~mask;
      code = piv.visit_import(atable, ord, NULL);
    }
    if ( code != 0 )
      return code;
  }
  return piv.leave_module(i);
}

//------------------------------------------------------------------------
// this function tries to read from a file as if it was reading from memory
// if translation not found for the given RVA then ZEROs are returned
// in addition, if it tries to read beyond a translation physical size
// the additional bytes will be returned as zeros
inline bool pe_loader_t::vmread(linput_t *li, uint32 rva, void *buf, size_t sz)
{
  // clear whole user buffer
  memset(buf, 0, sz);

  size_t may_read = sz;
  if ( get_linput_type(li) == LINPUT_PROCMEM )
  {
    qlseek(li, rva, SEEK_SET);
  }
  else
  {
    const transl_t *tr;
    ea_t fpos = map_ea(rva, &tr);

    // cannot find translation?
    if ( fpos == BADADDR )
    {
      qlseek(li, int32(rva), SEEK_SET);
      return true;
    }
    uint32 sectend = tr->pos + tr->psize; // section end
    if ( fpos >= sectend )
      return false; // data not present in the input file
    qlseek(li, fpos);

    // reading beyond section's limit?
    uint32 after_read_pos = fpos + sz;
    if ( after_read_pos < fpos )
      return false; // integer overflow
    if ( after_read_pos >= sectend )
    {
      // check if position belongs to the header and if reading beyond the limit
      if ( uint32(fpos) < pe.allhdrsize && after_read_pos > pe.allhdrsize )
        may_read = pe.allhdrsize - size_t(fpos);
      else
        may_read = sectend - fpos; // just read as much as section limit allows
    }
  }
  QASSERT(20045, ssize_t(may_read) >= 0);
  return qlread(li, buf, may_read) == (ssize_t)may_read;
}

//------------------------------------------------------------------------
// process all imports of a pe file
// returns: -1:could not read an impdir; 0-ok;
// other values can be returned by the visitor
inline int pe_loader_t::process_imports(linput_t *li, pe_import_visitor_t &piv)
{
  if ( pe.impdir.rva == 0 )
    return 0;

  if ( transvec.empty() )
    process_sections(li);

  int code = 0;
  for ( int ni=0; ; ni++ )
  {
    off_t off = pe.impdir.rva + ni*sizeof(peimpdir_t);
    peimpdir_t &id = piv.id;

    if ( !vmread(li, off, &id, sizeof(id)) )
    {
      memset(&id, 0, sizeof(id));
      // we continue if the import descriptor is within the page belonging
      // to the program
      if ( map_ea(off) == BADADDR || map_ea(off+sizeof(id)-1) == BADADDR )
      {
        code = piv.impdesc_error(off);
        if ( code != 0 )
          break;
      }
    }
    if ( id.dllname == 0 || id.looktab == 0 )
      break;
    ea_t ltable = id.table1;  // OriginalFirstThunk
    ea_t atable = id.looktab; // FirstThunk
    bool ok = true;
    char dll[MAXSTR];
    asciiz(li, id.dllname, dll, sizeof(dll), &ok);
    if ( !ok || dll[0] == '\0' )
      break;
    ansi2idb(dll);
    if ( map_ea(ltable) == BADADDR
      || ltable < pe.allhdrsize
      || pe.imagesize != 0 && ltable >= pe.imagesize )
    {
      ltable = atable;
    }
    atable += get_imagebase();
    code = piv.visit_module(dll, atable, ltable);
    if ( code != 0 )
      break;
    code = process_import_table(li, atable, ltable, piv);
    if ( code != 0 )
      break;
  }
  return code;
}

//------------------------------------------------------------------------
inline int pe_loader_t::process_delayed_imports(linput_t *li, pe_import_visitor_t &il)
{
  if ( pe.didtab.rva == 0 )
    return 0;

  if ( transvec.empty() )
    process_sections(li);

  int code = 0;
  uint32 ni = 0;
  bool ok = true;
  while ( true )
  {
    uint32 table = pe.didtab.rva + ni*uint32(sizeof(dimpdir_t));
    if ( !vseek(li, table) )
      break;
    dimpdir_t &id = il.did;
    lread(li, &id, sizeof(id));
    if ( !id.dllname )
      break;
    il.withbase = (id.attrs & DIMP_NOBASE) == 0;
    uval_t base = il.withbase ? 0 : uval_t(get_imagebase());
    ea_t atable = id.diat + base;
    ea_t ltable = id.dint;
    char dll[MAXSTR];
    uint32 off = uint32(il.withbase ? id.dllname - (ea_t)pe.imagebase() : id.dllname);
    asciiz(li, off, dll, sizeof(dll), &ok);
    if ( !ok )
      break;
    ansi2idb(dll);
    code = il.visit_module(dll, atable, ltable);
    if ( code != 0 )
      break;
    code = process_import_table(li, atable, ltable, il);
    if ( code != 0 )
      break;
    ni++;
  }
  return ok || code != 0 ? code : -1;
}

//------------------------------------------------------------------------
// process all exports of a pe file
// returns -2: could not read expdir, -1: other read errors, 0-ok,
// other values can be returned by the visitor
inline int pe_loader_t::process_exports(linput_t *li, pe_export_visitor_t &pev)
{
  if ( pe.expdir.rva == 0 )
    return 0;
  if ( transvec.empty() )
    process_sections(li);
  if ( !vseek(li, pe.expdir.rva) )
    return -2;

  // process export directory
  bool ok = true;
  char buf[MAXSTR];
  peexpdir_t ed;
  lread(li, &ed, sizeof(ed));
  asciiz(li, ed.dllname, buf, sizeof(buf), &ok);
  ansi2idb(buf);
  int code = pev.visit_expdir(ed, buf);
  if ( code != 0 )
    return code;

  // I'd like to have a better validation
  asize_t maxsize = qlsize(li) + 4096;
  if ( maxsize > pe.expdir.size )
    maxsize = pe.expdir.size;
  validate_array_count(NULL, &ed.nnames, 6, "Number of exported names",
                       pe.expdir.rva, pe.expdir.rva+maxsize);
  validate_array_count(NULL, &ed.naddrs, 4, "Number of exported addresses",
                       pe.expdir.rva, pe.expdir.rva+maxsize);

  // gather name information
  typedef std::map<int, qstring> names_t;
  names_t names;
  for ( uint32 i=0; i < ed.nnames && ok; i++ )
  {
    uint32 ordidx = vashort(li, ed.ordtab + i*sizeof(ushort), &ok);
    if ( !ok )
      break;
    ushort ord = ushort(ordidx + ed.ordbase);
    uint32 rva = valong(li, ed.namtab + i*sizeof(uint32), &ok);
    if ( !ok )
      break;
    asciiz(li, rva, buf, sizeof(buf), &ok);
    if ( !ok )
      break;
    if ( !win_utf2idb(buf) )
      ansi2idb(buf);
    names[ord] = buf;
  }

  // visit all exports
  uint32 expdir_start_rva = pe.expdir.rva;
  uint32 expdir_end_rva   = pe.expdir.rva + maxsize;
  for ( uint32 i=0; i < ed.naddrs && ok; i++ )
  {
    uint32 rva = valong(li, ed.adrtab + i*sizeof(uint32), &ok);
    if ( rva != 0 && ok )
    {
      uint32 ord = i + ed.ordbase;
      names_t::iterator p = names.find(ord);
      const char *name = p != names.end() ? p->second.c_str() : "";
      const char *forwarder = NULL;
      if ( rva >= expdir_start_rva && rva < expdir_end_rva )
      {
        asciiz(li, rva, buf, sizeof(buf), &ok);
        if ( !ok )
          break;
        char* dot = strrchr(buf, '.');
        if ( dot != NULL )
          *dot = '\0';
        ansi2idb(buf);
        if ( dot != NULL )
        {
          *dot++ = '.';
          if ( !win_utf2idb(dot) )
            ansi2idb(dot);
        }
        forwarder = buf;
      }
      code = pev.visit_export(rva, ord, name, forwarder);
      if ( code != 0 )
        return code;
    }
  }
  return ok ? 0 : -1;
}

//------------------------------------------------------------------------
inline const char *get_pe_machine_name(uint16 machine)
{
  switch ( machine )
  {
    case PECPU_80386:     return "80386";
    case PECPU_80486:     return "80486";
    case PECPU_80586:     return "80586";
    case PECPU_SH3:       return "SH3";
    case PECPU_SH3DSP:    return "SH3DSP";
    case PECPU_SH3E:      return "SH3E";
    case PECPU_SH4:       return "SH4";
    case PECPU_SH5:       return "SH5";
    case PECPU_ARM:       return "ARM";
    case PECPU_ARMI:      return "ARMI";
    case PECPU_ARMV7:     return "ARMv7";
    case PECPU_EPOC:      return "ARM EPOC";
    case PECPU_PPC:       return "PPC";
    case PECPU_PPCFP:     return "PPC FP";
    case PECPU_PPCBE:     return "PPC BE";
    case PECPU_IA64:      return "IA64";
    case PECPU_R3000:     return "MIPS R3000";
    case PECPU_R4000:     return "MIPS R4000";
    case PECPU_R6000:     return "MIPS R6000";
    case PECPU_R10000:    return "MIPS R10000";
    case PECPU_MIPS16:    return "MIPS16";
    case PECPU_WCEMIPSV2: return "MIPS WCEv2";
    case PECPU_ALPHA:     return "ALPHA";
    case PECPU_ALPHA64:   return "ALPHA 64";
    case PECPU_AMD64:     return "AMD64";
    case PECPU_ARM64:     return "ARM64";
    case PECPU_M68K:      return "M68K";
    case PECPU_MIPSFPU:   return "MIPS FPU";
    case PECPU_MIPSFPU16: return "MIPS16 FPU";
    case PECPU_EBC:       return "EFI Bytecode";
    case PECPU_AM33:      return "AM33";
    case PECPU_M32R:      return "M32R";
    case PECPU_CEF:       return "CEF";
    case PECPU_CEE:       return "CEE";
    case PECPU_TRICORE:   return "TRICORE";
  }
  return NULL;
}

