
#define is_magic(a) ( ((a) == MH_MAGIC) || ((a) == MH_MAGIC_64) )
#define is_cigam(a) ( ((a) == MH_CIGAM) || ((a) == MH_CIGAM_64) )


//--------------------------------------------------------------------------
local void swap_fat_header(fat_header *fh)
{
  fh->magic     = swap32(fh->magic);
  fh->nfat_arch = swap32(fh->nfat_arch);
}

//--------------------------------------------------------------------------
local void swap_fat_arch(fat_arch *fa)
{
  fa->cputype    = swap32(fa->cputype);
  fa->cpusubtype = swap32(fa->cpusubtype);
  fa->offset     = swap32(fa->offset);
  fa->size       = swap32(fa->size);
  fa->align      = swap32(fa->align);
}

#if defined(LOADER_COMPILE) || defined(BUILD_DWARF) || defined(BUILD_EFD) || defined(BUILD_DEBUGGER)
// ---------------------------------------------------------------------------
int macho_arch_to_ida_arch(cpu_type_t cputype, cpu_subtype_t /*cpusubtype*/)
{
  int target = -1;
  switch ( cputype )
  {
    default:
    case CPU_TYPE_VAX:
    case CPU_TYPE_ROMP:
    case CPU_TYPE_NS32032:
    case CPU_TYPE_NS32332:
    case CPU_TYPE_MC88000:
      break;
    case CPU_TYPE_MC680x0:
      target = PLFM_68K;
      break;
    case CPU_TYPE_I860:
      target = PLFM_I860;
      break;
    case CPU_TYPE_I386:
      target = PLFM_386;
      break;
    case CPU_TYPE_POWERPC:
      target = PLFM_PPC;
      break;
    case CPU_TYPE_HPPA:
      target = PLFM_HPPA;
      break;
    case CPU_TYPE_SPARC:
      target = PLFM_SPARC;
      break;
    case CPU_TYPE_MIPS:
      target = PLFM_MIPS;
      break;
    case CPU_TYPE_ARM:
      target = PLFM_ARM;
      break;
#ifdef __EA64__ // see also below, the error message for it
    case CPU_TYPE_ARM64:
      target = PLFM_ARM;
      break;
    case CPU_TYPE_X86_64:
      target = PLFM_386;
      break;
#endif
    case CPU_TYPE_POWERPC64:
      target = PLFM_PPC;
      break;
  }
  return target;
}
#endif

//--------------------------------------------------------------------------
bool macho_file_t::parse_header()
{
  qlseek(li, start_offset);
  uint32 magic;
  if ( qlread(li, &magic, sizeof(magic)) != sizeof(magic) )
    return false;
  if ( magic == FAT_MAGIC || magic == FAT_CIGAM )
    return parse_fat_header();
  else
    return is_magic(magic) || is_cigam(magic);
}

//--------------------------------------------------------------------------
bool macho_file_t::parse_fat_header()
{
  qlseek(li, start_offset);
  if ( qlread(li, &fheader, sizeof(fheader)) != sizeof(fheader) )
    return false;
  int code = (fheader.magic == FAT_MAGIC);
  if ( fheader.magic == FAT_CIGAM )
  {
    swap_fat_header(&fheader);
    code = 2;
  }
  if ( code == 0 || fheader.nfat_arch > 16 )
    return false;

  uint32 fsize = qlsize(li);
  uint32 archs_size = fheader.nfat_arch * sizeof(fat_arch);
  if ( sizeof(fat_header) + archs_size >= fsize )
    return false;

  fat_archs.resize(fheader.nfat_arch);

  if ( qlread(li, fat_archs.begin(), archs_size) != archs_size )
  {
    fat_archs.clear();
    return false;
  }

  for ( uint32_t i=0; i < fheader.nfat_arch; i++ )
  {
    fat_arch *parch = &fat_archs[i];
    if ( code == 2 )
      swap_fat_arch(parch);
    if ( parch->size <= sizeof(mach_header) ||
         parch->size >= fsize ||
         parch->offset < sizeof(fat_header) + archs_size ||
         parch->offset + parch->size > fsize )
    {
      fat_archs.clear();
      return false;
    }
  }
  return true;
}

//--------------------------------------------------------------------------
bool macho_file_t::get_fat_header(fat_header *fh)
{
  if ( fat_archs.empty() )
    return false;
  *fh = fheader;
  return true;
}
//--------------------------------------------------------------------------
bool macho_file_t::get_fat_arch(uint n, fat_arch *fa)
{
  if ( n >= fat_archs.size() )
  {
    memset(fa, 0, sizeof(*fa));
    return false;
  }
  *fa = fat_archs[n];
  return true;
}
