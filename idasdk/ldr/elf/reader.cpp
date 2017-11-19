
#ifndef ELF_READER_CPP
#define ELF_READER_CPP

#include <pro.h>
#include <diskio.hpp>
#include <functional>
#include <algorithm>

#include "elfbase.h"
#include "elf.h"
#include "elfr_arm.h"
#include "elfr_mip.h"
#include "elfr_ia6.h"
#include "elfr_ppc.h"

//----------------------------------------------------------------------------
ssize_t reader_t::prepare_error_string(
        char *buf,
        size_t bufsize,
        reader_t::errcode_t code,
        va_list va) const
{
  int len;
  switch ( code )
  {
    case BAD_CLASS:
      {
        int eclass = va_arg(va, int);
        len = qsnprintf(buf, bufsize,
                        "Unknown ELF class %d (should be %d for 32-bit, %d for 64-bit)",
                        eclass,
                        ELFCLASS32,
                        ELFCLASS64);
      }
      break;
    case BAD_ENDIANNESS:
      {
        int endian = va_arg(va, int);
        if ( endian != ELFDATA2LSB && endian != ELFDATA2MSB )
          len = qsnprintf(buf, bufsize,
                          "Unknown ELF byte sex %d (should be %d for LSB, %d for MSB)",
                          endian,
                          ELFDATA2LSB,
                          ELFDATA2MSB);
        else
          len = qsnprintf(buf, bufsize,
                          "Bad ELF byte sex %d for the indicated machine",
                          endian);
      }
      break;
    case BAD_EHSIZE:
      {
        int sz = va_arg(va, int);
        int fb = va_arg(va, int);
        len = qsnprintf(buf, bufsize,
                        "The ELF header entry size is invalid (%d, expected %d)",
                        sz, fb);
      }
      break;
    case BAD_PHENTSIZE:
      {
        int sz = va_arg(va, int);
        int fb = va_arg(va, int);
        len = qsnprintf(buf, bufsize,
                        "PHT entry size is invalid: %d. Falling back to %d",
                        sz, fb);
      }
      break;
    case BAD_PHLOC:
      len = qstpncpy(buf, "The PHT table size or offset is invalid", bufsize) - buf;
      break;
    case BAD_SHENTSIZE:
      len = qstpncpy(buf, "The SHT entry size is invalid", bufsize) - buf;
      break;
    case BAD_SHLOC:
      len = qstpncpy(buf, "SHT table size or offset is invalid", bufsize) - buf;
      break;
    case BAD_DYN_PLT_TYPE:
      len = qsnprintf(buf, bufsize, "Bad DT_PLTREL value (%d)", va_arg(va, int));
      break;
    case CONFLICTING_FILE_TYPE:
      len = qstpncpy(buf, "ELF file with PHT can not be ET_REL", bufsize) - buf;
      break;
    case BAD_SHSTRNDX:
      {
        uint16 idx = va_arg(va, uint);
        uint16 num = va_arg(va, uint);
        len = qsnprintf(buf, bufsize,
                        "Section header string table index %d is out of bounds (max %d)",
                        idx,
                        num-1);
      }
      break;
    case ERR_READ:
      {
        size_t d1 = va_arg(va, size_t); // size
        size_t d2 = va_arg(va, size_t); // return code
        qnotused(d1);
        qnotused(d2);
        len = qsnprintf(buf, bufsize,
                        "Bad file structure or read error (offset %" FMT_64 "u)",
                        va_arg(va, int64));
      }
      break;
    default:
      if ( is_error(code) )
        INTERR(20034);
      len = qsnprintf(buf, bufsize, "Unknown ELF warning %d",  code);
      break;
  }
  return len;
}

//----------------------------------------------------------------------------
static bool default_error_handler(const reader_t &reader, reader_t::errcode_t code, ...)
{
  va_list va;
  va_start(va, code);
  char buf[MAXSTR];
  reader.prepare_error_string(buf, sizeof(buf), code, va);
  va_end(va);

  warning("%s\n", buf);
  return reader.is_warning(code); // resume after warnings
}

//----------------------------------------------------------------------------
void sym_rel::get_original_name(reader_t &reader, qstring *out)
{
  const char *n = get_original_name(reader);
  if ( n != NULL )
    out->append(n);
}

//----------------------------------------------------------------------------
const char *sym_rel::get_original_name(reader_t &reader)
{
  if ( !original_name_lookup_performed() )
    lookup_original_name(reader);

  return original_name;
}

//----------------------------------------------------------------------------
void sym_rel::lookup_original_name(reader_t &reader)
{
  qstring storage;
  if ( reader.get_symbol_name(&storage, *this) )
    original_name = storage.extract();

  original_name_resolved = true;
}

//----------------------------------------------------------------------------
ea_t sym_rel::get_ea(const reader_t &reader, ea_t _debug_segbase) const
{
  ea_t ea = value;
  if ( reader.is_valid_rel_file() )
  {
    const elf_shdr_t *sh = reader.sections.getn(sec);
    if ( sh != NULL )
      ea += sh->sh_addr;
  }
  else
  {
    ea += _debug_segbase;
  }
  return ea;
}

//----------------------------------------------------------------------------
reader_t::reader_t(linput_t *_li, int64 _start_in_file)
    : pheaders(this), sections(this), li(_li), sif(_start_in_file),
      arch_specific(NULL), load_bias(0), eff_msb(false), eff_64(false)
{
  set_handler(default_error_handler);
  filesize = qlsize64(li);
}

//----------------------------------------------------------------------------
bool reader_t::is_warning(errcode_t code) const
{
  return code <= LAST_WARNING;
}

//----------------------------------------------------------------------------
bool reader_t::is_error(errcode_t code) const
{
  QASSERT(20035, code <= LAST_ERROR);
  return code > LAST_WARNING;
}

//-------------------------------------------------------------------------
static bool _silent_handler(const reader_t &reader, reader_t::errcode_t code, ...)
{
  return reader.is_warning(code); // resume after warnings
}

//----------------------------------------------------------------------------
void reader_t::set_handler(bool (*_handler)(const reader_t &reader, errcode_t code, ...))
{
  handle_error = _handler == NULL ? _silent_handler : _handler;
}

bool reader_t::read_ident()
{
  input_status_t save_excursion(*this, 0);
  uint64 fsize = size();
  uint64 fpos = tell();
  if ( fpos >= fsize )
    return false;
  uint64 bytes_left = fsize - fpos;
  if ( bytes_left < sizeof(elf_ident_t) )
    return false;

  memset(&header, 0, sizeof(header));

  if ( qlread(li, &header.e_ident, sizeof(elf_ident_t)) != sizeof(elf_ident_t) )
    return false;

  if ( !header.e_ident.is_valid() )
    return false;

  size_t ehdr_sz = is_64() ? sizeof(Elf64_Ehdr) : sizeof(Elf32_Ehdr);
  if ( bytes_left < ehdr_sz )
    return false;

  return true;
}

//----------------------------------------------------------------------------
int reader_t::safe_read(void *buf, size_t sz)
{
  int rc = lreadbytes(li, buf, sz, is_msb());
  if ( rc < 0 )
    handle_error(*this, ERR_READ, sz, size_t(rc), qltell64(li));
  return rc;
}

//----------------------------------------------------------------------------
int reader_t::read_addr(void *buf)
{
  return safe_read(buf, stdsizes.types.elf_addr);
}

//----------------------------------------------------------------------------
int reader_t::read_off(void *buf)
{
  return safe_read(buf, stdsizes.types.elf_off);
}

//----------------------------------------------------------------------------
int reader_t::read_xword(void *buf)
{
  return safe_read(buf, stdsizes.types.elf_xword);
}

//----------------------------------------------------------------------------
int reader_t::read_sxword(void *buf)
{
  return safe_read(buf, stdsizes.types.elf_sxword);
}

//----------------------------------------------------------------------------
int reader_t::read_word(uint32 *buf)
{
  return safe_read(buf, 4);
}

//----------------------------------------------------------------------------
int reader_t::read_half(uint16 *buf)
{
  return safe_read(buf, 2);
}

//----------------------------------------------------------------------------
int reader_t::read_byte(uint8 *buf)
{
  return safe_read(buf, 1);
}

#define IS_EXEC_OR_DYN(x) ((x) == ET_EXEC || (x) == ET_DYN)

struct linuxcpu_t
{
  uint16 machine;
  bool msb;
  bool _64;
};

static const linuxcpu_t lincpus[] = {
  { EM_386,    false, false },
  { EM_486,    false, false },
  { EM_X86_64, false, true  },
};

//----------------------------------------------------------------------------
// Linux kernel loader ignores class and endian fields for some(?) processors.
// check for such situation and set the effective endiannes/bitness
bool reader_t::check_ident()
{
  for ( unsigned i = 0; i < qnumber(lincpus); i++ )
  {
    bool matched = false;
    bool swap;
    if ( eff_msb == lincpus[i].msb
      && header.e_machine == lincpus[i].machine
      && IS_EXEC_OR_DYN(header.e_type) )
    {
      matched = true;
      swap = false;
    }
    else if ( eff_msb != lincpus[i].msb
      && swap16(header.e_machine) == lincpus[i].machine
      && IS_EXEC_OR_DYN(swap16(header.e_type)) )
    {
      matched = true;
      swap = true;
    }
    if ( matched )
    {
      if ( swap )
      {
        header.e_machine = swap16(header.e_machine);
        header.e_type    = swap16(header.e_type);
        if ( !handle_error(*this, BAD_ENDIANNESS, header.e_ident.bytesex) )
          return false;
        eff_msb = lincpus[i].msb;
      }
      // segment bitness can be different from elf bitness: apparently there
      // are some files like that in the wild (see pc_odd_bitness_64.elf)
      seg_64 = lincpus[i]._64;
      // assume elf32 for EM_386/EM_486
      if ( !seg_64 )
        eff_64 = false;
      break;
    }
  }
  return true;
}

//----------------------------------------------------------------------------
bool reader_t::read_header()
{
  // 32/64
  uint8 elf_class = get_ident().elf_class;
  if ( elf_class != ELFCLASS32
    && elf_class != ELFCLASS64 )
  {
    if ( !handle_error(*this, BAD_CLASS, elf_class) )
      return false;
  }
  // lsb/msb
  uint8 elf_do = get_ident().bytesex;
  if ( elf_do != ELFDATA2LSB
    && elf_do != ELFDATA2MSB )
  {
    if ( !handle_error(*this, BAD_ENDIANNESS, elf_do) )
      return false;
  }

  input_status_t save_excursion(*this, sizeof(elf_ident_t));

  // set the default values from ident
  eff_msb = elf_do == ELFDATA2MSB;
  eff_64  = elf_class == ELFCLASS64;
  seg_64  = eff_64;

  // Read the type and machine
#define _safe(expr) if ( (expr) < 0 ) goto FAILED
  _safe(read_half(&header.e_type));
  _safe(read_half(&header.e_machine));

  if ( !check_ident() )
    return false;

  // Define sizes
  if ( !is_64() )
  {
    stdsizes.ehdr           = sizeof(Elf32_Ehdr);
    stdsizes.phdr           = sizeof(Elf32_Phdr);
    stdsizes.shdr           = sizeof(Elf32_Shdr);
    stdsizes.entries.sym    = sizeof(Elf32_Sym);
    stdsizes.entries.dyn    = sizeof(Elf32_Dyn);
    stdsizes.entries.rel    = sizeof(Elf32_Rel);
    stdsizes.entries.rela   = sizeof(Elf32_Rela);
    stdsizes.types.elf_addr = 4;
    stdsizes.types.elf_off  = 4;
    stdsizes.types.elf_xword= 4;
    stdsizes.types.elf_sxword=4;
  }
  else
  {
    stdsizes.ehdr           = sizeof(elf_ehdr_t);
    stdsizes.phdr           = sizeof(elf_phdr_t);
    stdsizes.shdr           = sizeof(elf_shdr_t);
    stdsizes.entries.sym    = sizeof(elf_sym_t);
    stdsizes.entries.dyn    = sizeof(elf_dyn_t);
    stdsizes.entries.rel    = sizeof(elf_rel_t);
    stdsizes.entries.rela   = sizeof(elf_rela_t);
    stdsizes.types.elf_addr = 8;
    stdsizes.types.elf_off  = 8;
    stdsizes.types.elf_xword= 8;
    stdsizes.types.elf_sxword=8;
  }
  stdsizes.dyn.sym  = stdsizes.entries.sym;
  stdsizes.dyn.rel  = stdsizes.entries.rel;
  stdsizes.dyn.rela = stdsizes.entries.rela;

  // Read the rest of the header
  _safe(read_word(&header.e_version));
  _safe(read_addr(&header.e_entry));
  _safe(read_off (&header.e_phoff));
  _safe(read_off (&header.e_shoff));
  _safe(read_word(&header.e_flags));
  _safe(read_half(&header.e_ehsize));
  _safe(read_half(&header.e_phentsize));
  _safe(read_half(&header.e_phnum));
  _safe(read_half(&header.e_shentsize));
  _safe(read_half(&header.e_shnum));
  _safe(read_half(&header.e_shstrndx));
#undef _safe

  if ( header.e_ehsize != stdsizes.ehdr )
    if ( !handle_error(*this, BAD_EHSIZE, header.e_ehsize, stdsizes.ehdr) )
    {
FAILED:
      return false;
    }

  // Sanitize SHT string table index
  if ( header.e_shstrndx
    && header.e_shstrndx >= header.e_shnum )
  {
    if ( !handle_error(*this, BAD_SHSTRNDX, header.e_shstrndx, header.e_shnum) )
      goto FAILED;
    header.e_shstrndx = 0;
  }

  // Sanitize PHT parameters
  if ( header.e_phnum != 0 && header.e_phentsize != stdsizes.phdr )
  {
    if ( !handle_error(*this, BAD_PHENTSIZE, header.e_phentsize, stdsizes.phdr)
      || header.e_phentsize < stdsizes.phdr )
      goto FAILED;
  }
  if ( (header.e_phnum == 0) != (header.e_phoff == 0) )
  {
    if ( !handle_error(*this, BAD_PHLOC, header.e_phnum, header.e_phoff) )
      goto FAILED;
    header.e_phnum = 0;
  }

  // Sanitize SHT parameters
  if ( header.e_shnum != 0 && header.e_shentsize != stdsizes.shdr )
  {
    if ( !handle_error(*this, BAD_SHENTSIZE, header.e_shentsize, stdsizes.shdr)
      || header.e_shentsize < stdsizes.shdr )
    {
      header.e_shnum = 0; // do not use sht
    }
  }
  {
    uint32 sections_start  = header.e_shoff;
    uint32 sections_finish = header.e_shoff + header.e_shnum * header.e_shentsize;
    if ( (header.e_shnum == 0) != (header.e_shoff == 0)
      || sections_start  > sections_finish
      || sections_finish > size() )
    {
      if ( !handle_error(*this, BAD_SHLOC, header.e_shnum, header.e_shoff, size()) )
        goto FAILED;
      header.e_shnum = 0; // do not use sht
    }
  }

  //
  if ( (header.e_phnum != 0) && (header.e_type == ET_REL) )
  {
    if ( !handle_error(*this, CONFLICTING_FILE_TYPE, header.e_phnum, header.e_type) )
      goto FAILED;
  }

  //
  switch ( header.e_machine )
  {
    case EM_ARM:
      delete arch_specific;
      arch_specific = new arm_arch_specific_t();
      break;
    default:
      arch_specific = new arch_specific_t(); // Dummy
      break;
  }
  return true;
}

//----------------------------------------------------------------------------
bool reader_t::read_section_headers()
{
  input_status_t save_excursion(*this, header.e_shoff);
  int count = header.e_shnum;
  sections.resize(count);

  sections.initialized = true;

  for ( int i = 0; i < count; i++ )
  {
    if ( !seek_to_section_header(i) )
      return false;

    elf_shdr_t *sh = sections.getn(i);
#define _safe(expr) if ( expr < 0 ) return false;
    _safe(read_word (&sh->sh_name));
    _safe(read_word (&sh->sh_type));
    _safe(read_xword(&sh->sh_flags));
    _safe(read_addr (&sh->sh_addr));
    _safe(read_off  (&sh->sh_offset));
    _safe(read_xword(&sh->sh_size));
    _safe(read_word (&sh->sh_link));
    _safe(read_word (&sh->sh_info));
    _safe(read_xword(&sh->sh_addralign));
    _safe(read_xword(&sh->sh_entsize));
#undef _safe

    if ( sh->sh_type == SHT_DYNAMIC )
      sections.set_dynlink_table_info(sh->sh_offset, sh->sh_size, sh->sh_link);
  }

  typedef elf_shdrs_t::const_iterator const_iter;
  const_iter it  = sections.begin();
  const_iter end = sections.end();
  qstring name;
  for ( int i = 0; it != end; it++, i++ )
  {
    if ( !i ) // Skip first header
      continue;

    const elf_shdr_t &sh = *it;
    if ( sh.sh_size == 0 )
      continue;

    name.qclear();
    sections.get_name(&name, &sh);
    switch ( sh.sh_type )
    {
      case SHT_STRTAB:
        if ( name == ".strtab" )
          sections.set_index(WKS_STRTAB, i);
        else if ( name == ".dynstr" )
          sections.set_index(WKS_DYNSTR, i);
        break;

      case SHT_DYNSYM:
      case SHT_SYMTAB:
        switch ( sh.sh_type )
        {
          case SHT_SYMTAB:
            sections.set_index(WKS_SYMTAB, i);
            sections.set_index(WKS_STRTAB, sh.sh_link);
            // symcnt += (uint32)sh.sh_size;
            break;
          case SHT_DYNSYM:
            sections.set_index(WKS_DYNSYM, i);
            sections.set_index(WKS_DYNSTR, sh.sh_link);
            // symcnt += (uint32)sh.sh_size;
            break;
        }
        break;

      case SHT_PROGBITS:
        if ( name == ".interp" )
        {
          sections.set_index(WKS_INTERP, i);
          break;
        }
        else if ( name == ".got" )
        {
          sections.set_index(WKS_GOT, i);
          sections.set_got_original();
          break;
        }
        else if ( name == ".got.plt" )
        {
          sections.set_index(WKS_GOTPLT, i);
          break;
        }
        // no break
      case SHT_NOBITS:
        if ( name == ".plt" )
          sections.set_index(WKS_PLT, i);
        break;
    }
  }

  if ( !sections.get_index(WKS_GOTPLT) )
    sections.set_index(WKS_GOTPLT, sections.get_index(WKS_GOT));
  else if ( !sections.get_index(WKS_GOT) )
    sections.set_index(WKS_GOTPLT, 0);  // unsupported format

  return true;
}

//----------------------------------------------------------------------------
bool reader_t::read_program_headers()
{
  input_status_t save_excursion(*this, header.e_phoff);
  int count = header.e_phnum;
  pheaders.resize(count);

  pheaders.initialized = true;

  for ( int i = 0; i < count; i++ )
  {
    if ( !seek_to_program_header(i) )
      return false;

    elf_phdr_t *phdr = pheaders.get(i);
#define _safe(expr)                             \
    do                                          \
    {                                           \
      if ( expr < 0 )                           \
      {                                         \
        pheaders.resize(i == 0 ? 0 : i-1);      \
        return false;                           \
      }                                         \
    } while ( false )
    _safe(read_word(&phdr->p_type));
    if ( is_64() )
      _safe(read_word(&phdr->p_flags));
    _safe(read_off(&phdr->p_offset));
    _safe(read_addr(&phdr->p_vaddr));
    _safe(read_addr(&phdr->p_paddr));
    _safe(read_xword(&phdr->p_filesz));
    _safe(read_xword(&phdr->p_memsz));
    if ( !is_64() )
      _safe(read_word(&phdr->p_flags));
    _safe(read_xword(&phdr->p_align));
#undef _safe

    if ( phdr->p_type == PT_LOAD
      && phdr->p_vaddr < pheaders.get_image_base() )
      pheaders.set_image_base(phdr->p_vaddr);

    switch ( phdr->p_type )
    {
      case PT_DYNAMIC:
        {
          // in some files, p_filesz is 0, so take max of the two
          // TODO: use the size of the surrounding PT_LOAD segment,
          // since the dynamic loader does not use the size field
          size_t dsize = qmax(phdr->p_filesz, phdr->p_memsz);
          // p_offset may be wrong, always use p_vaddr
          size_t fileoff = file_offset(phdr->p_vaddr);
          pheaders.set_dynlink_table_info(fileoff, dsize, -1);
          break;
        }
      default:
        break;
    }

    add_mapping(*phdr);
  }

  return true;
}

//----------------------------------------------------------------------------
uint32 reader_t::rel_info_index(const elf_rel_t &r) const
{
  if ( is_64() )
    return ELF64_R_SYM(r.r_info);
  else
    return ELF32_R_SYM(r.r_info);
}

//----------------------------------------------------------------------------
uchar reader_t::rel_info_type(const elf_rel_t &r) const
{
  if ( is_64() )
    return ELF64_R_TYPE(r.r_info);
  else
    return ELF32_R_TYPE(r.r_info);
}

//----------------------------------------------------------------------------
uint32 reader_t::rel_info_index(const elf_rela_t &r) const
{
  if ( is_64() )
    return ELF64_R_SYM(r.r_info);
  else
    return ELF32_R_SYM(r.r_info);
}

//----------------------------------------------------------------------------
uchar reader_t::rel_info_type(const elf_rela_t &r) const
{
  if ( is_64() )
    return ELF64_R_TYPE(r.r_info);
  else
    return ELF32_R_TYPE(r.r_info);
}

//----------------------------------------------------------------------------
const char *reader_t::file_type_str() const
{
  const char *file_type = "Unknown";
  switch ( header.e_type )
  {
    case ET_NONE:     file_type = "None";                    break;
    case ET_REL:      file_type = "Relocatable";             break;
    case ET_EXEC:     file_type = "Executable";              break;
    case ET_DYN:      file_type = "Shared object";           break;
    case ET_CORE:     file_type = "Core file";               break;
    case ET_LOPROC:   file_type = "Processor specific";      break;
    case ET_HIPROC:   file_type = "Processor specific";      break;
    case ET_IRX:
      if ( header.e_machine == EM_MIPS )
        file_type = "PS2 IRX";
      break;
    case ET_PSPEXEC:
      if ( header.e_machine == EM_MIPS )
        file_type = "PSP executable";
      break;
    case ET_PS3PRX:
      if ( header.e_machine == EM_PPC64 )
        file_type = "Sony PS3 PRX file";
      break;
  }
  return file_type;
}

//----------------------------------------------------------------------------
const char *reader_t::os_abi_str() const
{
  uint8 os_abi = get_ident().osabi;
  const char *abi;
  switch ( os_abi )
  {
    case ELFOSABI_NONE:       abi = "UNIX System V ABI";                 break;
    case ELFOSABI_HPUX:       abi = "HP-UX operating system";            break;
    case ELFOSABI_NETBSD:     abi = "NetBSD";                            break;
    case ELFOSABI_LINUX:      abi = "GNU/Linux";                         break;
    case ELFOSABI_HURD:       abi = "GNU/Hurd";                          break;
    case ELFOSABI_SOLARIS:    abi = "Solaris";                           break;
    case ELFOSABI_AIX:        abi = "AIX";                               break;
    case ELFOSABI_IRIX:       abi = "IRIX";                              break;
    case ELFOSABI_FREEBSD:    abi = "FreeBSD";                           break;
    case ELFOSABI_TRU64:      abi = "TRU64 UNIX";                        break;
    case ELFOSABI_MODESTO:    abi = "Novell Modesto";                    break;
    case ELFOSABI_OPENBSD:    abi = "OpenBSD";                           break;
    case ELFOSABI_OPENVMS:    abi = "OpenVMS";                           break;
    case ELFOSABI_NSK:        abi = "Hewlett-Packard Non-Stop Kernel";   break;
    case ELFOSABI_AROS:       abi = "Amiga Research OS";                 break;
    case ELFOSABI_ARM:        abi = "ARM";                               break;
    case ELFOSABI_STANDALONE: abi = "Standalone (embedded) application"; break;
    case ELFOSABI_CELLOSLV2:
      if ( header.e_machine == EM_PPC64 )
      {
        abi = "PS3 Cell OS lv2";
        break;
      }
      // fall through
    default:                  abi = "Unknown";                           break;
  }
  return abi;
}

//----------------------------------------------------------------------------
const char *reader_t::machine_name_str() const
{
  uint32 m = get_header().e_machine;
  switch ( m )
  {
    case EM_NONE:  return "<No machine>";
    case EM_M32:   return "AT & T WE 32100";
    case EM_SPARC: return "SPARC";
    case EM_386:   return "Intel 386";
    case EM_68K:   return "Motorola 68000";
    case EM_88K:   return "Motorola 88000";
    case EM_486:   return "Intel 486";
    case EM_860:   return "Intel 860";
    case EM_MIPS:  return "MIPS";
    case EM_S370:  return "IBM System370";
    case EM_MIPS_RS3_BE:  return "MIPS R3000 Big Endian";
    case EM_PARISC:  return "PA-RISC";
    case EM_VPP550:  return "Fujitsu VPP500";
    case EM_SPARC32PLUS:  return "SPARC v8+";
    case EM_I960:  return "Intel 960";
    case EM_PPC:   return "PowerPC";
    case EM_PPC64: return "PowerPC 64";
    case EM_S390:  return "IBM S/390";
    case EM_SPU:   return "Cell BE SPU";
    case EM_CISCO7200: return "Cisco 7200 Series Router (MIPS)";
    case EM_CISCO3620: return "Cisco 3620/3640 Router (MIPS)";
    case EM_V800:  return "NEC V800";
    case EM_FR20:  return "Fujitsu FR20";
    case EM_RH32:  return "TRW RH-22";
    case EM_MCORE:  return "Motorola M*Core";
    case EM_ARM:   return "ARM";
    case EM_OLD_ALPHA:  return "Digital Alpha";
    case EM_SH:    return "SuperH";
    case EM_SPARC64:  return "SPARC 64";
    case EM_TRICORE:  return "Siemens Tricore";
    case EM_ARC:   return "ARC";
    case EM_H8300: return "H8/300";
    case EM_H8300H:return "H8/300H";
    case EM_H8S:   return "Hitachi H8S";
    case EM_H8500: return "H8/500";
    case EM_IA64:  return "Itanium IA64";
    case EM_MIPS_X:  return "Stanford MIPS-X";
    case EM_COLDFIRE:  return "Coldfire";
    case EM_6812:  return "MC68HC12";
    case EM_MMA:   return "Fujitsu MMA";
    case EM_PCP:   return "Siemens PCP";
    case EM_NCPU:  return "Sony nCPU";
    case EM_NDR1:  return "Denso NDR1";
    case EM_STARCORE:  return "Star*Core";
    case EM_ME16:  return "Toyota ME16";
    case EM_ST100: return "ST100";
    case EM_TINYJ: return "TinyJ";
    case EM_X86_64:  return "x86-64";
    case EM_PDSP:  return "PDSP";
    case EM_PDP10: return "DEC PDP-10";
    case EM_PDP11: return "DEC PDP-11";
    case EM_FX66:  return "Siemens FX66";
    case EM_ST9:   return "ST9+";
    case EM_ST7:   return "ST7";
    case EM_68HC16:return "MC68HC16";
    case EM_6811:  return "MC68HC11";
    case EM_68HC08:return "MC68HC08";
    case EM_68HC05:return "MC68HC05";
    case EM_SVX:   return "Silicon Graphics SVx";
    case EM_ST19:  return "ST19";
    case EM_VAX:   return "VAX";
    case EM_CRIS:  return "CRIS";
    case EM_JAVELIN: return "Infineon Javelin";
    case EM_FIREPATH: return "Element 14 Firepath";
    case EM_ZSP:   return "ZSP";
    case EM_MMIX:  return "MMIX";
    case EM_HUANY: return "Harvard HUANY";
    case EM_PRISM: return "SiTera Prism";
    case EM_AVR:   return "Atmel";
    case EM_FR:    return "Fujitsu FR";
    case EM_D10V:  return "Mitsubishi D10V";
    case EM_D30V:  return "Mitsubishi D30V";
    case EM_V850:  // (GNU compiler)
    case EM_NECV850: // (NEC compilers)
       return "NEC V850";
    case EM_NECV850E1:  return "NEC v850 ES/E1";
    case EM_NECV850E2:  return "NEC v850 E2";
    case EM_NECV850Ex:  return "NEC v850 ???";
    case EM_M32R:  return "M32R";
    case EM_MN10300:return "MN10300";
    case EM_MN10200:return "MN10200";
    case EM_PJ:    return "picoJava";
    case EM_OPENRISC :  return "OpenRISC";
    case EM_ARCOMPACT:  return "ARCompact";
    case EM_XTENSA:return "Xtensa";
    case EM_VIDEOCORE:  return "VideoCore";
    case EM_TMM_GPP:  return "Thompson GPP";
    case EM_NS32K: return "NS 32000";
    case EM_TPC:   return "TPC";
    case EM_SNP1K: return "SNP 1000";
    case EM_ST200: return "ST200";
    case EM_IP2K:  return "IP2022";
    case EM_MAX:   return "MAX";
    case EM_CR:    return "CompactRISC";
    case EM_F2MC16:return "F2MC16";
    case EM_MSP430:return "MSP430";
    case EM_BLACKFIN:return "ADI Blackfin";
    case EM_SE_C33:return "S1C33";
    case EM_SEP:   return "SEP";
    case EM_ARCA:  return "Arca";
    case EM_UNICORE:return "Unicore";
    case EM_EXCESS:return "eXcess";
    case EM_DXP:   return "Icera DXP";
    case EM_ALTERA_NIOS2: return "Nios II";
    case EM_CRX:   return "CRX";
    case EM_XGATE: return "XGATE";
    case EM_C166:  return "C16x/XC16x/ST10";
    case EM_M16C:  return "M16C";
    case EM_DSPIC30F: return "dsPIC30F";
    case EM_CE:    return "Freescale Communication Engine";
    case EM_M32C:  return "M32C";
    case EM_TSK3000: return "TSK3000";
    case EM_RS08:  return "RS08";
    case EM_ECOG2: return "eCOG2";
    case EM_SCORE: return "Sunplus Score";
    case EM_DSP24: return "NJR DSP24";
    case EM_VIDEOCORE3: return "VideoCore III";
    case EM_LATTICEMICO32: return "Lattice Mico32";
    case EM_SE_C17: return "C17";
    case EM_MMDSP_PLUS: return "MMDSP";
    case EM_CYPRESS_M8C: return "M8C";
    case EM_R32C:   return "R32C";
    case EM_TRIMEDIA: return "TriMedia";
    case EM_QDSP6: return "QDSP6";
    case EM_8051:  return "i8051";
    case EM_STXP7X:return "STxP7x";
    case EM_NDS32: return "NDS32";
    case EM_ECOG1X:return "eCOG1X";
    case EM_MAXQ30:return "MAXQ30";
    case EM_XIMO16:return "NJR XIMO16";
    case EM_MANIK: return "M2000";
    case EM_CRAYNV2: return "Cray NV2";
    case EM_RX:    return "RX";
    case EM_METAG: return "Imagination Technologies META";
    case EM_MCST_ELBRUS: return "MCST Elbrus";
    case EM_ECOG16:return "eCOG16";
    case EM_CR16:  return "CompactRISC 16-bit";
    case EM_ETPU:  return "Freescale ETPU";
    case EM_SLE9X: return "SLE9X";
    case EM_L1OM:  return "Intel L1OM";
    case EM_K1OM:  return "Intel K1OM";
    case EM_INTEL182: return "Intel Reserved (182)";
    case EM_AARCH64: return "ARM64";
    case EM_ARM184: return "ARM Reserved (184)";
    case EM_AVR32: return "AVR32";
    case EM_STM8:  return "STM8";
    case EM_TILE64: return "Tilera TILE64";
    case EM_TILEPRO:  return "Tilera TILEPro";
    case EM_MICROBLAZE:  return "MicroBlaze";
    case EM_CUDA:  return "CUDA";
    case EM_TILEGX:  return "Tilera TILE-Gx";
    case EM_CLOUDSHIELD:  return "CloudShield";
    case EM_COREA_1ST:  return "Core-A 1st gen";
    case EM_COREA_2ND:  return "Core-A 2nd gen";
    case EM_ARC_COMPACT2:  return "ARCompactV2";
    case EM_OPEN8:  return "Open8";
    case EM_RL78:  return "RL78";
    case EM_VIDEOCORE5:  return "VideoCore V";
    case EM_78K0R:  return "78K0R";
    case EM_56800EX:  return "Freescale 56800EX";
    case EM_BA1:  return "Beyond BA1";
    case EM_BA2:  return "Beyond BA2";
    case EM_XCORE:  return "XMOS xCORE";
    case EM_CYGNUS_POWERPC:  return "PowerPC";
    case EM_ALPHA: return "DEC Alpha";
    default:
      {
        static char buf[30];
        qsnprintf(buf, sizeof(buf), "Unknown CPU [%u]", m);
        return buf;
      }
  }
}

//----------------------------------------------------------------------------
bool reader_t::read_prelink_base(uint32 *base)
{
  int64 fsize = size();
  input_status_t save_excursion(*this, fsize - 4);
  char tag[4];
  bool ok = false;
  if ( qlread(li, tag, 4) == 4 )
  {
    if ( memcmp(tag, "PRE ", 4) == 0 )
    {
      qlseek(li, fsize - 8);
      if ( read_word(base) >= 0 )
        ok = true;
    }
  }

  return ok;
}

//----------------------------------------------------------------------------
void reader_t::get_string_at(qstring *out, uint64 offset)
{
  input_status_t save_excursion(*this, offset);
  char buffer[100];
  while ( true )
  {
    int read = qlread(li, buffer, sizeof(buffer));
    if ( read < 0 )
    {
      out->append("{truncated name}");
      break;
    }

    // Find the position of the trailing zero
    int pos;
    for ( pos = 0; pos < read && buffer[pos] != '\0'; pos++ )
      ;

    out->append(buffer, pos);
    if ( pos < sizeof(buffer) )
      break;
  }
}

//----------------------------------------------------------------------------
bool reader_t::get_symbol_name(qstring *out, const sym_rel &sym) const
{
  ushort symsec = sym.symsec;
  if ( symsec == SHN_UNDEF )
    return false;

  uint32 idx = sym.original.st_name;
  if ( idx != 0 )
  {
    out->qclear();
    if ( symsec == 0xFFFF )
    {
      sections.get_name(out, -1, idx);
    }
    else
    {
      const elf_shdr_t *symbols_section = sections.getn(symsec);
      if ( symbols_section != NULL )
        sections.get_name(out, symbols_section->sh_link, idx);
    }
    return true;
  }
  return false;
}

//----------------------------------------------------------------------------
int reader_t::parse_dynamic_info(const dynamic_linking_tables_t &dlt,
                                 dynamic_info_t &di)
{
  class dummy_handler_t : public dynamic_info_handler_t
  {
  public:
    dummy_handler_t(reader_t &_r)
      : dynamic_info_handler_t(_r) {}

    virtual int handle(const elf_dyn_t &)
    {
      return 0;
    }
  };

  dummy_handler_t dummy(*this);
  return parse_dynamic_info(dlt, di, dummy);
}

//----------------------------------------------------------------------------
int reader_t::parse_dynamic_info(
        const dynamic_linking_tables_t &dlt,
        dynamic_info_t &di,
        dynamic_info_handler_t &handler,
        bool set)
{
  di.set_status(dynamic_info_t::NOK);
  di.initialize(*this);

  typedef qvector<elf_dyn_t> dyninfo_t;
  dyninfo_t dinfo;
  if ( dlt.size == 0 )
    return -1;

  // 1) Read all 'elf_dyn_t' entries
  elf_dyn_t *d;
  const size_t isize = stdsizes.entries.dyn;
  elf_shdr_t fake_section;
  fake_section.sh_type    = SHT_DYNAMIC;
  fake_section.sh_offset  = dlt.offset;
  fake_section.sh_size    = dlt.size;
  fake_section.sh_entsize = isize;
  buffered_input_t<elf_dyn_t> dyn_input(*this, fake_section);
  while ( dyn_input.next(d) )
  {
    dinfo.push_back(*d);
    if ( d->d_tag == DT_NULL )
      break;
  }

  size_t hash_off = 0;
  // 2) parse info
  for ( int i=0; i < dinfo.size(); i++ )
  {
    const elf_dyn_t &dyn = dinfo[i];
    switch ( dyn.d_tag )
    {
      case DT_STRTAB:
        di.strtab.offset = handler.file_offset(dyn.d_un);
        continue;
      case DT_STRSZ:
        di.strtab.size = dyn.d_un;
        continue;

      case DT_SYMTAB:
        di.symtab.offset = handler.file_offset(dyn.d_un);
        continue;
      case DT_SYMENT:
        di.symtab.entsize = dyn.d_un;
        continue;

      case DT_REL:
        di.rel.offset = handler.file_offset(dyn.d_un);
        continue;
      case DT_RELENT:
        di.rel.entsize = dyn.d_un;
        continue;
      case DT_RELSZ:
        di.rel.size = dyn.d_un;
        continue;

      case DT_RELA:
        di.rela.offset = handler.file_offset(dyn.d_un);
        continue;
      case DT_RELAENT:
        di.rela.entsize = dyn.d_un;
        continue;
      case DT_RELASZ:
        di.rela.size = dyn.d_un;
        continue;

      case DT_JMPREL:
        di.plt.offset = handler.file_offset(dyn.d_un);
        continue;
      case DT_PLTRELSZ:
        di.plt.size = dyn.d_un;
        continue;
      case DT_PLTREL:
        di.plt.type = uint32(dyn.d_un);
        if ( di.plt.type != DT_REL && di.plt.type != DT_RELA )
        {
          if ( !handle_error(*this, BAD_DYN_PLT_TYPE, di.plt.type) )
            return -1;
        }
        continue;

      case DT_HASH:
        hash_off = handler.file_offset(dyn.d_un);
        continue;

      default:
        continue;

      case DT_NULL:
        break;
    }
    break;
  }

  if ( di.symtab.offset <= 0 || di.strtab.offset <= 0 )
  {
    di.symtab.size = 0;
    return 0;
  }
  size_t off = di.strtab.offset;
  if ( di.rel.offset  > di.symtab.offset ) off = qmin(di.rel.offset, off);
  if ( di.rela.offset > di.symtab.offset ) off = qmin(di.rela.offset, off);
  if ( di.plt.offset  > di.symtab.offset ) off = qmin(di.plt.offset, off);
  if ( hash_off       > di.symtab.offset ) off = qmin(hash_off, off);
  if ( off > di.symtab.offset )
    di.symtab.size = off - di.symtab.offset;
  else
    di.symtab.size = 0;

  di.set_status(dynamic_info_t::OK);

  if ( set )
    set_dynamic_info(di);

  // 3) Call handler
  int rc = 0;
  for ( int i=0; i < dinfo.size(); i++ )
  {
    rc = handler.handle(dinfo[i]);
    if ( rc != 0 )
      break;
  }
  return rc;
}

//----------------------------------------------------------------------------
void reader_t::add_mapping(const elf_phdr_t &p)
{
  mapping_t &m = mappings.push_back();
  m.offset = p.p_offset;
  m.size   = p.p_filesz;
  m.ea     = p.p_vaddr;
}

//----------------------------------------------------------------------------
int64 reader_t::file_offset(uint64 ea) const
{
  for ( int i=0; i < mappings.size(); i++ )
  {
    const mapping_t &cur = mappings[i];
    if ( cur.ea <= ea && (cur.ea + cur.size) > ea )
      return low(ea - cur.ea) + cur.offset;
  }

  return -1;
}

//----------------------------------------------------------------------------
int section_headers_t::get_section_index(const elf_shdr_t *section) const
{
  if ( section < begin() || section >= end() )
    return -1;
  else
    return section - begin();
}

//----------------------------------------------------------------------------
int section_headers_t::get_index(wks_t wks) const
{
  QASSERT(20054, wks >= WKS_BSS && wks < WKS_LAST);
  return wks_lut[int(wks)];
}

//----------------------------------------------------------------------------
void section_headers_t::set_index(wks_t wks, uint32 index)
{
  QASSERT(20055, wks >= WKS_BSS && wks < WKS_LAST);
  int i = int(wks);
  wks_lut [i] = index;
}

//----------------------------------------------------------------------------
const elf_shdr_t *section_headers_t::getn(int index) const
{
  assert_initialized();

  if ( uint32(index) >= headers.size() )
    return NULL;
  else
    return &headers[index];
}

//----------------------------------------------------------------------------
const elf_shdr_t *section_headers_t::get(uint32 sh_type, const char *name) const
{
  assert_initialized();

  qstring n2;
  for ( qvector<elf_shdr_t>::const_iterator it=begin(); it != end(); it++ )
  {
    const elf_shdr_t &cur = *it;
    if ( cur.sh_type == sh_type )
    {
      n2.qclear();
      get_name(&n2, &cur);
      if ( n2 == name )
        return &cur;
    }
  }
  return NULL;
}

//----------------------------------------------------------------------------
const elf_shdr_t *section_headers_t::get_rel_for(int index, bool *is_rela) const
{
  assert_initialized();
  if ( is_rela != NULL )
    *is_rela = false;

  QASSERT(20056, index > 0);
  for ( elf_shdrs_t::const_iterator it=begin(); it != end(); it++ )
  {
    // for REL/RELA sections, sh_info contains the index to which the relocations apply
    if ( it->sh_info == index
      && (it->sh_type == SHT_RELA || it->sh_type == SHT_REL) )
    {
      // found it
      if ( is_rela != NULL )
        *is_rela = it->sh_type == SHT_RELA;
      return it;
    }
  }
  return NULL;
}

//----------------------------------------------------------------------------
int section_headers_t::add(const elf_shdr_t &section)
{
  headers.push_back(section);
  return headers.size() - 1;
}

//----------------------------------------------------------------------------
void section_headers_t::set(wks_t wks, uint32 index)
{
  wks_lut[wks] = index;
}

//----------------------------------------------------------------------------
bool section_headers_t::get_name(qstring *out, uint32 index) const
{
  return get_name(out, &headers[index]);
}

//----------------------------------------------------------------------------
bool section_headers_t::get_name(qstring *out, const elf_shdr_t *sh) const
{
  const elf_ehdr_t &header = reader->get_header();
  uint16 names_section = header.e_shstrndx;
  return sh != NULL
      && names_section != 0
      && get_name(out, names_section, sh->sh_name);
}

//----------------------------------------------------------------------------
bool section_headers_t::get_name(
        qstring *out,
        uint16 names_section,
        uint32 offset) const
{
  uint64 off, size;
  if ( names_section == uint16(-1) )
  {
    if ( reader->has_dynamic_info() )
    {
      const dynamic_info_t &di = reader->get_dynamic_info();
      off  = di.strtab.offset;
      size = di.strtab.size;
    }
    else
    {
      off  = 0;
      size = 0;
    }
  }
  else
  {
    if ( reader->sections.empty() )
      return false;
    const elf_shdr_t *strsec = reader->sections.getn(names_section);
    if ( strsec != NULL )
    {
      off  = strsec->sh_offset;
      size = strsec->sh_size;
    }
    else
    {
      off  = 0;
      size = 0;
    }
  }

  // cisco ios files have size 0 for the string section
  if ( offset >= size && size != 0 )
    out->sprnt("bad offset %08x", low(offset + off));

  reader->get_string_at(out, offset + off);
  return true;
}

//----------------------------------------------------------------------------
const char *section_headers_t::sh_type_str(uint32 sh_type) const
{
#define NM(tp) case SHT_##tp: return #tp
#define NM2(tp, nm) case SHT_##tp: return #nm
  switch ( sh_type )
  {
    NM(NULL);
    NM(PROGBITS);
    NM(SYMTAB);
    NM(STRTAB);
    NM(RELA);
    NM(HASH);
    NM(DYNAMIC);
    NM(NOTE);
    NM(NOBITS);
    NM(REL);
    NM(SHLIB);
    NM(DYNSYM);
    NM(INIT_ARRAY);
    NM(FINI_ARRAY);
    NM(PREINIT_ARRAY);
    NM(GROUP);
    NM(SYMTAB_SHNDX);
    NM2(GNU_INCREMENTAL_INPUTS, GNU_INC_INPUT);
    NM(GNU_ATTRIBUTES);
    NM(GNU_HASH);
    NM(GNU_LIBLIST);
    NM2(SUNW_verdef,  VERDEF);
    NM2(SUNW_verneed, VERNEEDED);
    NM2(SUNW_versym,  VERSYMBOL);
    default:
      {
        uint32 m = reader->get_header().e_machine;
        if ( m == EM_ARM )
        {
          switch ( sh_type )
          {
            NM(ARM_EXIDX);
            NM(ARM_PREEMPTMAP);
            NM(ARM_ATTRIBUTES);
            NM(ARM_DEBUGOVERLAY);
            NM(ARM_OVERLAYSECTION);
          }
        }
        else if ( m == EM_MIPS )
        {
          switch ( sh_type )
          {
            NM(MIPS_LIBLIST);
            NM(MIPS_MSYM);
            NM(MIPS_CONFLICT);
            NM(MIPS_GPTAB);
            NM(MIPS_UCODE);
            NM(MIPS_DEBUG);
            NM(MIPS_REGINFO);
            NM(MIPS_IFACE);
            NM(MIPS_CONTENT);
            NM(MIPS_OPTIONS);
            NM(MIPS_DWARF);
            NM(MIPS_SYMBOL_LIB);
            NM(MIPS_EVENTS);
            NM2(DVP_OVERLAY_TABLE, MIPS_DVP_OVERLAY_TABLE);
            NM2(DVP_OVERLAY,       MIPS_DVP_OVERLAY);
            NM(MIPS_IOPMOD);
            NM(MIPS_PSPREL);
          }
        }
        else if ( m == EM_PPC64 )
        {
          switch ( sh_type )
          {
            NM2(PS3PRX_RELA, PRXRELA);
          }
        }
        break;
      }
  }
  static char buf[9];
  qsnprintf(buf, sizeof(buf), "%X", sh_type);
  return buf;
#undef NM2
#undef NM
}

//-------------------------------------------------------------------------
uint64 section_headers_t::get_size_in_file(const elf_shdr_t &sh) const
{
  if ( sh.sh_type == SHT_NOBITS )
    return 0;
  uint64 next_boundary = reader->size();
  // It may happen that we receive a section header
  // that is _not_ part of the list of original
  // section headers. E.g., when we load symbols from the
  // dynamic-provided information.
  int idx = get_section_index(&sh);
  if ( idx > -1 && (idx+1) < headers.size() )
  {
    const elf_shdr_t *next_sh = getn(idx+1);
    if ( next_sh->sh_offset >= sh.sh_offset )
      next_boundary = next_sh->sh_offset;
  }
  return qmin(sh.sh_size, next_boundary - sh.sh_offset);
}

//-------------------------------------------------------------------------
void section_headers_t::read_file_contents(
        bytevec_t *out,
        const elf_shdr_t &sh) const
{
  uint64 nbytes = get_size_in_file(sh);
  out->resize(nbytes);
  reader->seek(sh.sh_offset);
  reader->safe_read(out->begin(), nbytes);
}


//-------------------------------------------------------------------------
//                          program_headers_t
//----------------------------------------------------------------------------
const char *program_headers_t::p_type_str(uint32 p_type) const
{
#define NM(tp) case PT_##tp: return #tp
#define NM2(tp, nm) case PT_##tp: return #nm
  switch ( p_type )
  {
    NM(NULL);
    NM(LOAD);
    NM(DYNAMIC);
    NM(INTERP);
    NM(NOTE);
    NM(SHLIB);
    NM(PHDR);
    NM(TLS);

    NM2(GNU_EH_FRAME, EH_FRAME);
    NM2(GNU_STACK, STACK);
    NM2(GNU_RELRO, RO-AFTER);
    NM2(PAX_FLAGS, PAX-FLAG);

    default:
      {
        uint32 m = reader->get_header().e_machine;
        if ( m == EM_ARM )
        {
          switch ( p_type )
          {
            NM2(ARM_ARCHEXT, ARCHEXT);
            NM2(ARM_EXIDX, EXIDX);
          }
        }
        else if ( m == EM_IA64 )
        {
          switch ( p_type )
          {
            NM(HP_TLS           );
            NM(HP_CORE_NONE     );
            NM(HP_CORE_VERSION  );
            NM(HP_CORE_KERNEL   );
            NM(HP_CORE_COMM     );
            NM(HP_CORE_PROC     );
            NM(HP_CORE_LOADABLE );
            NM(HP_CORE_STACK    );
            NM(HP_CORE_SHM      );
            NM(HP_CORE_MMF      );
            NM(HP_PARALLEL      );
            NM(HP_FASTBIND      );
            NM(HP_OPT_ANNOT     );
            NM(HP_HSL_ANNOT     );
            NM(HP_STACK         );
            NM(HP_CORE_UTSNAME  );
            NM(HP_LINKER_FOOTPRINT );
            NM(IA_64_ARCHEXT    );
            NM(IA_64_UNWIND     );
          }
        }
        else if ( m == EM_MIPS )
        {
          switch ( p_type )
          {
            NM2(MIPS_IOPMOD, IOPMOD);
            NM2(MIPS_EEMOD, EEMOD);
            NM2(MIPS_PSPREL, PSPREL);
            NM2(MIPS_PSPREL2, PSPREL2);
          }
        }
        else if ( m == EM_PPC64 )
        {
          switch ( p_type )
          {
            case PHT_PS3PRX_RELA : return "PRXRELA";
          }
        }
        static char buf[10];
        qsnprintf(buf, sizeof(buf), "%08X", p_type);
        return buf;
      }
  }
#undef NM2
#undef NM
}

//----------------------------------------------------------------------------
template<> void buffered_input_t<sym_rel>::start_reading()
{
  reader.get_arch_specific()->on_start_symbols(reader);
}

//----------------------------------------------------------------------------
template<> bool buffered_input_t<sym_rel>::read_item(sym_rel &storage)
{
  storage.clear_original_name();
  memset(&storage, 0, sizeof(storage));

  elf_sym_t &orig = storage.original;
#define _safe(expr) do { if ( expr < 0 ) return false; } while(0)
  if ( is_64 )
  {
    _safe(reader.read_word(&orig.st_name));
    _safe(reader.read_byte(&orig.st_info));
    _safe(reader.read_byte(&orig.st_other));
    _safe(reader.read_half(&orig.st_shndx));
    _safe(reader.read_addr(&orig.st_value));
    _safe(reader.read_xword(&orig.st_size));
  }
  else
  {
    _safe(reader.read_word(&orig.st_name));
    _safe(reader.read_addr(&orig.st_value));
    _safe(reader.read_word((uint32 *) &orig.st_size));
    _safe(reader.read_byte(&orig.st_info));
    _safe(reader.read_byte(&orig.st_other));
    _safe(reader.read_half(&orig.st_shndx));
  }
#undef _safe

  ushort bind = ELF_ST_BIND(orig.st_info);
  if ( bind > STB_WEAK )
  {
    CASSERT(STB_LOCAL < STB_WEAK && STB_GLOBAL < STB_WEAK);
    if ( reader.get_header().e_machine == EM_ARM && bind == STB_LOPROC+1 )
      // codewarrior for arm seems to use this binding type similar to local or weak
      bind = STB_WEAK;
    else if ( bind < STB_LOOS || bind > STB_HIPROC )
      bind = STB_INVALID;
  }

  storage.bind   = (uchar) bind;
  storage.sec    = orig.st_shndx;
  storage.type   = ELF_ST_TYPE(orig.st_info);
  storage.value  = orig.st_value + reader.get_load_bias();
  storage.size   = orig.st_size;
  storage.symsec = section_idx;

  reader.get_arch_specific()->on_symbol_read(reader, *this, storage);
  return true;
}

//----------------------------------------------------------------------------
static inline void swap_64_at(uint64 *ptr)
{
  *ptr = swap64(*ptr);
}

//----------------------------------------------------------------------------
static inline void swap_64_at(int64 *ptr)
{
  *ptr = swap64(*ptr);
}

//----------------------------------------------------------------------------
#define swap_addr(ptr)  swap_64_at(ptr);
#define swap_xword(ptr) swap_64_at(ptr);
#define swap_sxword(ptr) swap_64_at(ptr);

//----------------------------------------------------------------------------
template<> ssize_t buffered_input_t<elf_rel_t>::read_items(size_t max)
{
  if ( isize != sizeof(Elf32_Rel) && isize != sizeof(Elf64_Rel) )
    return 0;
  if ( !is_mul_ok<uint64>(read, isize) || !is_mul_ok(max, isize) )
    return 0;
  input_status_t save_excursion(reader, offset + (read * isize));
  memset(buffer, 0, sizeof(buffer));
  ssize_t bytes = max * isize;
  QASSERT(20043, bytes <= sizeof(buffer));
  if ( qlread(reader.get_linput(), buffer, bytes) != bytes )
    return 0;

#if __MF__
  bool swap = !reader.is_msb();
#else
  bool swap = reader.is_msb();
#endif

  if ( isize == sizeof(Elf32_Rel) )
  {
    Elf32_Rel *rel32 = (Elf32_Rel *) buffer;
    Elf64_Rel *rel64 = (Elf64_Rel *) buffer;
    rel32 += max - 1;
    rel64 += max - 1;
    uint64 inf64, off64;
    for ( size_t i = 0; i < max; i++, rel32--, rel64-- )
    {
      if ( swap )
      {
        inf64 = swap32(rel32->r_info);
        off64 = swap32(rel32->r_offset);
      }
      else
      {
        inf64 = rel32->r_info;
        off64 = rel32->r_offset;
      }
      rel64->r_info   = inf64;
      rel64->r_offset = off64;
    }
  }
  else
  {
    if ( swap )
    {
      elf_rel_t *rel64 = buffer;
      for ( size_t i = 0; i < max; i++, rel64++ )
      {
        swap_addr(&rel64->r_offset);
        swap_xword(&rel64->r_info);
      }
    }
  }

  return max;
}

//----------------------------------------------------------------------------
template<> ssize_t buffered_input_t<elf_rela_t>::read_items(size_t max)
{
  if ( isize != sizeof(Elf32_Rela) && isize != sizeof(Elf64_Rela) )
    return 0;
  if ( !is_mul_ok<uint64>(read, isize) || !is_mul_ok(max, isize) )
    return 0;
  input_status_t save_excursion(reader, offset + (read * isize));
  memset(buffer, 0, sizeof(buffer));
  ssize_t bytes = max * isize;
  QASSERT(20044, bytes <= sizeof(buffer));
  if ( qlread(reader.get_linput(), buffer, bytes) != bytes )
    return 0;

#if __MF__
  bool swap = !reader.is_msb();
#else
  bool swap = reader.is_msb();
#endif

  if ( isize == sizeof(Elf32_Rela) )
  {
    Elf32_Rela *rela32 = (Elf32_Rela *) buffer;
    Elf64_Rela *rela64 = (Elf64_Rela *) buffer;
    rela32 += max - 1;
    rela64 += max - 1;
    uint64 inf64, off64;
    int64 addend;
    for ( size_t i = 0; i < max; i++, rela32--, rela64-- )
    {
      if ( swap )
      {
        inf64  = swap32(rela32->r_info);
        off64  = swap32(rela32->r_offset);
        addend = swap32(rela32->r_addend);
      }
      else
      {
        inf64  = rela32->r_info;
        off64  = rela32->r_offset;
        addend = rela32->r_addend;
      }
      rela64->r_info   = inf64;
      rela64->r_offset = off64;
      rela64->r_addend = addend;
    }
  }
  else
  {
    if ( swap )
    {
      elf_rela_t *rela64 = buffer;
      for ( size_t i = 0; i < max; i++, rela64++ )
      {
        swap_addr(&rela64->r_offset);
        swap_xword(&rela64->r_info);
        swap_sxword(&rela64->r_addend);
      }
    }
  }

  return max;
}

//----------------------------------------------------------------------------
template<> bool buffered_input_t<elf_dyn_t>::read_item(elf_dyn_t &storage)
{
  // FIXME: Load bias?
  memset(&storage, 0, sizeof(storage));
#define _safe(expr) do { if ( expr < 0 ) return false; } while(0)
  _safe(reader.read_sxword(&storage.d_tag));
  _safe(reader.read_addr(&storage.d_un));
#undef _safe
  return true;
}

//----------------------------------------------------------------------------
dynamic_info_handler_t::dynamic_info_handler_t(reader_t &_r)
  : reader(_r)
{
}

//----------------------------------------------------------------------------
uint64 dynamic_info_handler_t::file_offset(uint64 ea) const
{
  return reader.file_offset(ea);
}

//-------------------------------------------------------------------------
void dynamic_info_t::initialize(const reader_t &reader)
{
  symtab.entsize = reader.stdsizes.entries.sym;
  rel.entsize = reader.stdsizes.dyn.rel;
  rela.entsize = reader.stdsizes.dyn.rela;
  set_status(INITIALIZED);
  QASSERT(20037, symtab.entsize != 0 && rel.entsize != 0 && rela.entsize != 0);
}
//----------------------------------------------------------------------------
void dynamic_info_t::do_fill_section_header(
        elf_shdr_t &sh,
        uint64 sh_offset,
        uint64 sh_size,
        uint32 sh_type,
        uint64 sh_entsize) const
{
  memset(&sh, 0, sizeof(sh));
  sh.sh_offset  = sh_offset;
  sh.sh_size    = sh_size;
  sh.sh_type    = sh_type;
  sh.sh_info    = 0;
  sh.sh_entsize = sh_entsize;
}

//----------------------------------------------------------------------------
void dynamic_info_t::fill_section_header(
        const reader_t & /*reader*/,
        const symtab_t &stab,
        elf_shdr_t &sh) const
{
  do_fill_section_header(sh, stab.offset, stab.size, SHT_DYNSYM, stab.entsize);
}

//----------------------------------------------------------------------------
void dynamic_info_t::fill_section_header(
        const reader_t & /*reader*/,
        const rel_t &_rel,
        elf_shdr_t &sh) const
{
  do_fill_section_header(sh, _rel.offset, _rel.size, SHT_REL, _rel.entsize);
}

//----------------------------------------------------------------------------
void dynamic_info_t::fill_section_header(
        const reader_t & /*reader*/,
        const rela_t &_rela,
        elf_shdr_t &sh) const
{
  do_fill_section_header(sh, _rela.offset, _rela.size, SHT_RELA, _rela.entsize);
}

//----------------------------------------------------------------------------
void dynamic_info_t::fill_section_header(
        const reader_t & /*reader*/,
        const plt_t &_plt,
        elf_shdr_t &sh) const
{
  bool is_rela  = _plt.type == DT_RELA;
  uint32 sh_type = is_rela ? SHT_RELA : SHT_REL;
  uint64 sh_entsize = is_rela ? rela.entsize : rel.entsize;
  do_fill_section_header(sh, _plt.offset, _plt.size, sh_type, sh_entsize);
}

//----------------------------------------------------------------------------
const char *dynamic_info_t::d_tag_str(uint16 e_machine, int64 d_tag) const
{
#define NM(tp) case tp: return #tp
  switch ( d_tag )
  {
    case DT_NULL:     return "DT_NULL     end of _DYNAMIC array";
    case DT_NEEDED:   return "DT_NEEDED   str-table offset name to needed library";
    case DT_PLTRELSZ: return "DT_PLTRELSZ tot.size in bytes of relocation entries";
    case DT_PLTGOT:   return "DT_PLTGOT   ";
    case DT_HASH:     return "DT_HASH     addr. of symbol hash teble";
    case DT_STRTAB:   return "DT_STRTAB   addr of string table";
    case DT_SYMTAB:   return "DT_SYMTAB   addr of symbol table";
    case DT_RELA:     return "DT_RELA     addr of relocation table";
    case DT_RELASZ:   return "DT_RELASZ   size in bytes of DT_RELA table";
    case DT_RELAENT:  return "DT_RELAENT  size in bytes of DT_RELA entry";
    case DT_STRSZ:    return "DT_STRSZ    size in bytes of string table";
    case DT_SYMENT:   return "DT_SYMENT   size in bytes of symbol table entry";
    case DT_INIT:     return "DT_INIT     addr. of initialization function";
    case DT_FINI:     return "DT_FINI     addr. of termination function";
    case DT_SONAME:   return "DT_SONAME   offs in str.-table - name of shared object";
                           // 123456789012345678901234567890123456789012345678901234567890
                           //          1         2         3         4         5
    case DT_RPATH:    return "DT_RPATH    offs in str-table - search path";
    case DT_RUNPATH:  return "DT_RUNPATH  array of search pathes";
    case DT_SYMBOLIC: return "DT_SYMBOLIC start search of shared object";
    case DT_REL:      return "DT_REL      addr of relocation table";
    case DT_RELSZ:    return "DT_RELSZ    tot.size in bytes of DT_REL";
    case DT_RELENT:   return "DT_RELENT   size in bytes of DT_REL entry";
    case DT_PLTREL:   return "DT_PLTREL   type of relocation (DT_REL or DT_RELA)";
    case DT_DEBUG:    return "DT_DEBUG    not specified";
    case DT_TEXTREL:  return "DT_TEXTREL  segment permisson";
    case DT_JMPREL:   return "DT_JMPREL   addr of dlt procedure (if present)";

    NM(DT_BIND_NOW);
    NM(DT_PREINIT_ARRAY);
    NM(DT_INIT_ARRAY);
    NM(DT_FINI_ARRAY);
    NM(DT_INIT_ARRAYSZ);
    NM(DT_FINI_ARRAYSZ);
    NM(DT_PREINIT_ARRAYSZ);
    NM(DT_FLAGS);

    NM(DT_VALRNGLO);
    NM(DT_GNU_PRELINKED);
    NM(DT_GNU_CONFLICTSZ);
    NM(DT_GNU_LIBLISTSZ);
    NM(DT_CHECKSUM);
    NM(DT_PLTPADSZ);
    NM(DT_MOVEENT);
    NM(DT_MOVESZ);
    NM(DT_FEATURE);
    NM(DT_POSFLAG_1);
    NM(DT_SYMINSZ);
    NM(DT_SYMINENT);
//    NM(DT_VALRNGHI);
    NM(DT_ADDRRNGLO);
    NM(DT_GNU_HASH);
    NM(DT_TLSDESC_PLT);
    NM(DT_TLSDESC_GOT);
    NM(DT_GNU_CONFLICT);
    NM(DT_GNU_LIBLIST);
    NM(DT_CONFIG);
    NM(DT_DEPAUDIT);
    NM(DT_AUDIT);
    NM(DT_PLTPAD);
    NM(DT_MOVETAB);
    NM(DT_SYMINFO);
//    NM(DT_ADDRRNGHI);
    NM(DT_RELACOUNT);
    NM(DT_RELCOUNT);
    NM(DT_FLAGS_1);
    NM(DT_VERDEF);
    NM(DT_VERDEFNUM);
    NM(DT_VERNEED);
    NM(DT_VERNEEDNUM);
    NM(DT_VERSYM);

    NM(DT_AUXILIARY);
    NM(DT_USED);
    NM(DT_FILTER);
  }
  if ( e_machine == EM_MIPS )
  {
    switch ( d_tag )
    {
      NM(DT_MIPS_RLD_VERSION);
      NM(DT_MIPS_TIME_STAMP);
      NM(DT_MIPS_ICHECKSUM);
      NM(DT_MIPS_IVERSION);
      NM(DT_MIPS_FLAGS);
      NM(DT_MIPS_BASE_ADDRESS);
      NM(DT_MIPS_MSYM);
      NM(DT_MIPS_CONFLICT);
      NM(DT_MIPS_LIBLIST);
      NM(DT_MIPS_LOCAL_GOTNO);
      NM(DT_MIPS_CONFLICTNO);
      NM(DT_MIPS_LIBLISTNO);
      NM(DT_MIPS_SYMTABNO);
      NM(DT_MIPS_UNREFEXTNO);
      NM(DT_MIPS_GOTSYM);
      NM(DT_MIPS_HIPAGENO);
      NM(DT_MIPS_RLD_MAP);
      NM(DT_MIPS_DELTA_CLASS);
      NM(DT_MIPS_DELTA_CLASS_NO);
      NM(DT_MIPS_DELTA_INSTANCE);
      NM(DT_MIPS_DELTA_INSTANCE_NO);
      NM(DT_MIPS_DELTA_RELOC);
      NM(DT_MIPS_DELTA_RELOC_NO);
      NM(DT_MIPS_DELTA_SYM);
      NM(DT_MIPS_DELTA_SYM_NO);
      NM(DT_MIPS_DELTA_CLASSSYM);
      NM(DT_MIPS_DELTA_CLASSSYM_NO);
      NM(DT_MIPS_CXX_FLAGS);
      NM(DT_MIPS_PIXIE_INIT);
      NM(DT_MIPS_SYMBOL_LIB);
      NM(DT_MIPS_LOCALPAGE_GOTIDX);
      NM(DT_MIPS_LOCAL_GOTIDX);
      NM(DT_MIPS_HIDDEN_GOTIDX);
      NM(DT_MIPS_PROTECTED_GOTIDX);
      NM(DT_MIPS_OPTIONS);
      NM(DT_MIPS_INTERFACE);
      NM(DT_MIPS_DYNSTR_ALIGN);
      NM(DT_MIPS_INTERFACE_SIZE);
      NM(DT_MIPS_RLD_TEXT_RESOLVE_ADDR);
      NM(DT_MIPS_PERF_SUFFIX);
      NM(DT_MIPS_COMPACT_SIZE);
      NM(DT_MIPS_GP_VALUE);
      NM(DT_MIPS_AUX_DYNAMIC);
      NM(DT_MIPS_PLTGOT);
      NM(DT_MIPS_RWPLT);
    }
  }
  if ( e_machine == EM_IA64 )
  {
    switch ( d_tag )
    {
      NM(DT_HP_LOAD_MAP);
      NM(DT_HP_DLD_FLAGS);
      NM(DT_HP_DLD_HOOK);
      NM(DT_HP_UX10_INIT);
      NM(DT_HP_UX10_INITSZ);
      NM(DT_HP_PREINIT);
      NM(DT_HP_PREINITSZ);
      NM(DT_HP_NEEDED);
      NM(DT_HP_TIME_STAMP);
      NM(DT_HP_CHECKSUM);
      NM(DT_HP_GST_SIZE);
      NM(DT_HP_GST_VERSION);
      NM(DT_HP_GST_HASHVAL);
      NM(DT_HP_EPLTREL);
      NM(DT_HP_EPLTRELSZ);
      NM(DT_HP_FILTERED);
      NM(DT_HP_FILTER_TLS);
      NM(DT_HP_COMPAT_FILTERED);
      NM(DT_HP_LAZYLOAD);
      NM(DT_HP_BIND_NOW_COUNT);
      NM(DT_PLT);
      NM(DT_PLT_SIZE);
      NM(DT_DLT);
      NM(DT_DLT_SIZE);
      NM(DT_HP_SYM_CHECKSUM);
      NM(DT_IA_64_PLT_RESERVE);
    }
  }
#undef NM
  static char buf[100];
  qsnprintf(buf, sizeof(buf), "DT_????     Unknown (%08" FMT_64 "X)", d_tag);
  return buf;
}

//----------------------------------------------------------------------------
uint64 symrel_cache_t::slice_start(slice_type_t t) const
{
  slice_t::check_type(t);
  if ( t == SLT_SYMTAB )
    return 0;
  else if ( t == SLT_DYNSYM )
    return slice_end(SLT_SYMTAB);
  else
    return 0;
}

//----------------------------------------------------------------------------
uint64 symrel_cache_t::slice_end(slice_type_t t) const
{
  slice_t::check_type(t);
  if ( t == SLT_SYMTAB )
    return dynsym_index;
  else
    return storage.size();
}

//----------------------------------------------------------------------------
sym_rel &symrel_cache_t::append(slice_type_t t)
{
  slice_t::check_type(t);
  uint32 idx = slice_end(t);
  if ( idx == storage.size() )
  {
    if ( t == SLT_SYMTAB )
      dynsym_index++;

    return storage.push_back();
  }
  else
  {
    typedef qvector<sym_rel>::iterator iter;
    iter it = storage.begin() + idx;
    sym_rel sr;
    storage.insert(it, sr);
    return storage[idx];
  }
}

//----------------------------------------------------------------------------
struct section_and_value_sorter_t : public std::binary_function<sym_rel*, sym_rel*, bool>
{
  bool operator() (const sym_rel* e0, const sym_rel* e1)
  {
    if ( e0->original.st_shndx != e1->original.st_shndx )
      return e0->original.st_shndx < e1->original.st_shndx;
    else
      return e0->original.st_value < e1->original.st_value;
  }
};

//----------------------------------------------------------------------------
void symrel_cache_t::slice_t::sorted(sort_type_t t, qvector<const sym_rel*> &out) const
{
  out.qclear();

  size_t len = size();
  for ( uint64 i = 0; i < len; i++ )
    out.push_back(&get(i));

  switch ( t )
  {
    case symrel_cache_t::slice_t::section_and_value:
      std::sort(out.begin(), out.end(), section_and_value_sorter_t());
      break;
    default:
      INTERR(20020);
  }
}

//----------------------------------------------------------------------------
symrel_cache_t::ptr_t symrel_cache_t::get_ptr(const sym_rel &sym)
{
  const sym_rel *symbol = &sym;
  qvector<sym_rel>::const_iterator beg = storage.begin();
  qvector<sym_rel>::const_iterator end = storage.end();
  if ( symbol < beg || symbol > end )
  {
    return ptr_t(this, SLT_INVALID, (uint64) -1);
  }
  else
  {
    size_t idx = symbol - beg;
    size_t symtab_sz = slice_size(SLT_SYMTAB);
    if ( idx < symtab_sz )
      return ptr_t(this, SLT_SYMTAB, idx);
    else
      return ptr_t(this, SLT_DYNSYM, idx - symtab_sz);
  }
}


// ===========================================================================
//                           ARM-specific code.
// ===========================================================================



//----------------------------------------------------------------------------
bool arm_arch_specific_t::is_mapping_symbol(const char *name) const
{
  if ( name == NULL )
    return false;

  if ( name[0] == '$'
    && (name[2] == '\0' || name[2] == '.') )
  {
    switch ( name[1] )
    {
      case 'a':   // labels the first byte of a sequence of ARM instructions. Its type is STT_FUNC.
      case 't':   // labels the first byte of a sequence of Thumb instructions. Its type is STT_FUNC.
      case 'b':   // labels a Thumb BL instruction. Its type is STT_FUNC.
      case 'd':   // labels the first byte of a sequence of data items. Its type is STT_OBJECT.
      case 'p':   // labels the final, PC-modifying instruction of an
                  // indirect function call. Its type is STT_FUNC.
                  // (An indirect call is a call through a function pointer
                  // variable). $p does not label the PC-modifying
                  // instruction of a function return sequence.
      case 'f':   // labels a function pointer constant (static pointer to code).
                  // Its type is STT_OBJECT.
        return true;
    }
  }
  return false;
}

//----------------------------------------------------------------------------
void arm_arch_specific_t::on_start_symbols(reader_t &)
{
  has_mapsym = false;
#ifdef BUILD_LOADER
  if ( thumb_entry != BADADDR )
  {
    ph.notify(ph.loader, thumb_entry);
    auto_make_code(thumb_entry);
  }
#endif
}

//----------------------------------------------------------------------------
void arm_arch_specific_t::on_symbol_read(reader_t &reader,
                                         buffered_input_t<sym_rel> &,
                                         sym_rel &sym)
{
  // If it has not *yet* been determined that this ELF module
  // has mapping symbols, try harder!
  if ( !has_mapsym )
  {
    const char *name = sym.get_original_name(reader);
    if ( is_mapping_symbol(name) )
        has_mapsym = true;
  }

  const char *name = sym.get_original_name(reader);
  if ( is_mapping_symbol(name) )
  {
    char name1 = name[1];
    if ( name1 == 'a' || name1 == 't' )
    {
      isa_t isa = name1 == 'a' ? isa_arm : isa_thumb;
      sym.set_flag(thumb_function); // FIXME: Shouldn't we check 'a' or 't', here?
                                    // FIXME: Shouldn't it be reversed, too?
      notify_isa(reader, sym, isa, true);
      if ( is_mapping_symbols_tracking() )
        set_isa(sym, isa);
    }
  }
  else
  {
    uchar bind = sym.bind;

    // Keep going _only_ if function
    ushort orig_type = ELF_ST_TYPE(sym.original.st_info);
    if ( (orig_type != STT_FUNC
       && orig_type != STT_ARM_TFUNC
       && orig_type != STT_ARM_16BIT )
      || (bind != STB_GLOBAL
       && bind != STB_LOCAL
       && bind != STB_WEAK) )
    {
      return;
    }

    sym.value &= ~1;

    // If original type is ARM_TFUNC, make it FUNC,
    // so it gets treated as a regular FUNC by
    // upstream code.
    if ( orig_type == STT_ARM_TFUNC )
      sym.type = STT_FUNC;

    if ( (orig_type == STT_ARM_TFUNC
       || orig_type == STT_ARM_16BIT
       || (sym.original.st_value & 1) != 0) )
    {
      sym.set_flag(thumb_function);
      notify_isa(reader, sym, isa_thumb, false);
    }

    if ( !sym.has_flag(thumb_function)
       && is_mapping_symbols_tracking()
       && get_isa(sym) == isa_thumb)
    {
      sym.set_flag(thumb_function);
      notify_isa(reader, sym, isa_thumb, false);
    }

    if ( !sym.has_flag(thumb_function) )
      notify_isa(reader, sym, isa_arm, false);
  }
}

//----------------------------------------------------------------------------
void arm_arch_specific_t::set_isa(const sym_rel &symbol, isa_t isa)
{
  isa_ranges_t::iterator it = isa_ranges.find(symbol.sec);
  if ( it == isa_ranges.end() )
  {
    isa_ranges[symbol.sec] = section_isa_ranges_t();
    it = isa_ranges.find(symbol.sec);
  }

  section_isa_ranges_t &section_isa_ranges = it->second;
  section_isa_ranges[symbol.original.st_value] = isa;
}

//----------------------------------------------------------------------------
arm_arch_specific_t::isa_t arm_arch_specific_t::get_isa(const sym_rel &symbol) const
{
  isa_t current_isa = isa_arm;
  isa_ranges_t::const_iterator it = isa_ranges.find(symbol.sec);
  if ( it != isa_ranges.end() )
  {
    const section_isa_ranges_t &section_isa_ranges = it->second;
    section_isa_ranges_t::const_iterator p;
    section_isa_ranges_t::const_iterator end = section_isa_ranges.end();
    for ( p = section_isa_ranges.begin(); p != end; ++p )
    {
      uint64 offset_in_section = p->first;
      if ( offset_in_section > symbol.original.st_value )
        break;

      current_isa = p->second;
    }
  }
  return current_isa;
}

#endif // ELF_READER_CPP
