
#include <diskio.hpp>

#define MAGICLEN ((SARMAG > SAIAMAG) ? SARMAG : SAIAMAG)

//------------------------------------------------------------------------
bool is_ar_file(linput_t *li, int32 offset, bool include_aix)
{
  char magic[MAGICLEN];
  qlseek(li, offset);
  if ( qlread(li, magic, sizeof(magic)) != sizeof(magic) )
    return false;
  return memcmp(magic, ARMAG,  SARMAG) == 0
      || memcmp(magic, ARMAGB, SARMAG) == 0
      || memcmp(magic, ARMAGE, SARMAG) == 0
      || include_aix && (memcmp(magic,AIAMAG,SAIAMAG) == 0 
                      || memcmp(magic,AIAMAGBIG,SAIAMAG) == 0);
}

//------------------------------------------------------------------------
static char *get_msft_module_name(
        const char *ahname,
        const char *ahend,
        char *name,
        size_t size)
{
  if ( size == 0 )
    return NULL;
  char *ptr = name;
  for ( size_t i=0; ahname < ahend; i++,ptr++ )
  {
    char chr = *ahname++;
    if ( chr == '\n' || i == size-1 )
      chr = '\0';
    *ptr = chr;
    if ( chr == '\0' )
      break;
  }
  while ( ptr > name && qisspace(ptr[-1]) )
    *--ptr = '\0';
  if ( ptr > name && ptr[-1] == '/' )
    ptr[-1] = '\0';
  return name;
}

//------------------------------------------------------------------------
static const char *get_ar_modname(
        const char *lnames,
        const char *end,
        const char *name,
        char *buf,
        size_t bufsize)
{
  if ( lnames != NULL && *name == '/' )
  {
    name++;
    size_t off = size_t(atol(name));
    while ( qisdigit(*name) )
      name++;
    if ( *name == '\0' )
    {
      if ( lnames+off < lnames )
        return qstrncpy(buf, "?", bufsize);
      return get_msft_module_name(lnames+off, end, buf, bufsize);
    }
  }
  return qstrncpy(buf, name, bufsize);
}

//------------------------------------------------------------------------
// return codes:
// 1: no input file
// 0: ok
// 2: read error
// 3: bad archive
// 4: not enough memory
// 5: maxpos reached
int enum_ar_contents64(linput_t *li,
                     int (idaapi *_callback)(void *ud,
                                             qoff64_t offset,
                                             ar_hdr *ah,
                                             uint64 size,
                                             char *filename),
                     void *ud,
                     // Max position in file. Typically used when
                     // archive is embedded within other file.
                     int32 maxpos = -1)
{
  int code = 0;
  char *names = NULL;
  size_t names_size = 0;
  while ( true )
  {
    ar_hdr ah;
    qoff64_t filepos = qltell64(li);
    if ( filepos & 1 )
      qlseek64(li, filepos+1);
    if ( maxpos > -1 && filepos >= maxpos )
    {
      code = 5;
      break;
    }
    ssize_t bytes = qlread(li, &ah, sizeof(ah));
    if ( bytes == 0 )
      break;    // end of archive, no error
    if ( bytes != sizeof(ah) )
    {
      code = 2; // read error
      break;
    }
    if ( memcmp(ah.ar_fmag, ARFMAG, sizeof(ah.ar_fmag)) != 0 )
    {
      code = 3; // bad archive
      break;
    }
    char name[sizeof(ah.ar_name)+1];
    get_msft_module_name(ah.ar_name, ah.ar_name+sizeof(ah.ar_name), name, sizeof(name));
    uint64 size = qatoll(ah.ar_size);
    filepos = qltell64(li);
    if ( names == NULL && name[0] == '/' && name[1] == '\0' )
    {
      if ( size != 0 )
      {
        names = (char *)qalloc(size);
        if ( names == NULL )
        {
          code = 4;  // not enough memory
          break;
        }
        names_size = size;
        if ( qlread(li, names, size) != size )
        {
          code = 2;  // read error
          break;
        }
      }
      continue;
    }
    if ( memcmp(name, AR_EFMT1, 3) == 0)
    {
      //BSD/Apple archive: the length of long name follows
      //#1/nnn
      size_t extralen = size_t(atol(name+3));
      char* modname = (char *)qalloc(extralen+1);
      if ( modname == NULL )
      {
        code = 4;  // not enough memory
        break;
      }
      if ( qlread(li, modname, extralen) != extralen )
      {
        code = 2;  // read error
        break;
      }
      modname[extralen]='\0';

      //skip special files
      if ( strncmp(modname, "__.SYMDEF", sizeof("__.SYMDEF")-1) )
      {
        code = _callback(ud, qoff64_t(filepos+extralen), &ah, size-extralen, modname);
        if ( code != 0 ) break;
      }
      qfree(modname);
    }
    else if ( name[0] != '\0' )
    {
      char modname[MAXSTR];
      get_ar_modname(names, names+names_size, name, modname, sizeof(modname));
      code = _callback(ud, filepos, &ah, size, modname);
      if ( code != 0 ) break;
    }
    qlseek64(li, qoff64_t(filepos+size));
  }
  qfree(names);
  return code;
}

//----------------------------------------------------------------------------
struct proxy32_ar_cbdata_t
{
  int (idaapi *callback)(
                   void *ud,
                   int32 offset,
                   ar_hdr *ah,
                   size_t size,
                   char *filename);
  void *ud;
};

//----------------------------------------------------------------------------
static int idaapi proxy32_ar_callback(
                   void *ud,
                   qoff64_t offset,
                   ar_hdr *ah,
                   uint64 size,
                   char *filename)
{
  if ( offset >> 31 != 0 || size >> 31 != 0 )
    return 6;
  proxy32_ar_cbdata_t *d32 = (proxy32_ar_cbdata_t *)ud;
  return d32->callback(d32->ud, offset, ah, size, filename);
}

//------------------------------------------------------------------------
// return codes:
// 1: no input file
// 0: ok
// 2: read error
// 3: bad archive
// 4: not enough memory
// 5: maxpos reached
// 6: file is too large - use 64bit offset!
int enum_ar_contents(linput_t *li,
                     int (idaapi *_callback)(void *ud,
                                             int32 offset,
                                             ar_hdr *ah,
                                             size_t size,
                                             char *filename),
                     void *ud,
                     // Max position in file. Typically used when
                     // archive is embedded within other file.
                     int32 maxpos = -1)
{
  proxy32_ar_cbdata_t d32 = { _callback, ud };
  return enum_ar_contents64(li, proxy32_ar_callback, &d32, maxpos);
}

//--------------------------------------------------------------------------
// convert small archive header to big one
bool upgrade_aix_fl_hdr(fl_hdr *fh, const fl_hdr_small *fh_small)
{
  if ( memcmp(fh_small->fl_magic, AIAMAG, SAIAMAG) != 0 )
    return false;   // not small archive
  qstrncpy(fh->fl_memoff, fh_small->fl_memoff, sizeof(fh->fl_memoff));
  qstrncpy(fh->fl_gstoff, fh_small->fl_gstoff, sizeof(fh->fl_gstoff));
  fh->fl_gst64off[0] = '\0';
  qstrncpy(fh->fl_fstmoff, fh_small->fl_fstmoff, sizeof(fh->fl_fstmoff));
  qstrncpy(fh->fl_lstmoff, fh_small->fl_lstmoff, sizeof(fh->fl_lstmoff));
  qstrncpy(fh->fl_freeoff, fh_small->fl_freeoff, sizeof(fh->fl_freeoff));
  return true;
}

//--------------------------------------------------------------------------
bool read_aix_fl_hdr(fl_hdr *fh, linput_t *li)
{
  size_t nread = qlread(li, fh, sizeof(*fh));
  if ( nread == sizeof(*fh) && memcmp(fh->fl_magic, AIAMAGBIG, SAIAMAG) == 0 )
    return true;
  if ( nread < sizeof(fl_hdr_small) )
    return false;
  fl_hdr_small fh_small;
  memcpy(&fh_small, fh, sizeof(fh_small));
  return upgrade_aix_fl_hdr(fh, &fh_small);
}

//--------------------------------------------------------------------------
// convert small member header to big one
void upgrade_aix_ar_hdr(aix_ar_hdr *ah, const aix_ar_hdr_small *ah_small)
{
  qstrncpy(ah->ar_size, ah_small->ar_size, sizeof(ah->ar_size));
  qstrncpy(ah->ar_nxtmem, ah_small->ar_nxtmem, sizeof(ah->ar_nxtmem));
  qstrncpy(ah->ar_prvmem, ah_small->ar_prvmem, sizeof(ah->ar_prvmem));
  qstrncpy(ah->ar_date, ah_small->ar_date, sizeof(ah->ar_date));
  qstrncpy(ah->ar_uid, ah_small->ar_uid, sizeof(ah->ar_uid));
  qstrncpy(ah->ar_gid, ah_small->ar_gid, sizeof(ah->ar_gid));
  qstrncpy(ah->ar_mode, ah_small->ar_mode, sizeof(ah->ar_mode));
  qstrncpy(ah->ar_namlen, ah_small->ar_namlen, sizeof(ah->ar_namlen));
}

//--------------------------------------------------------------------------
bool read_aix_ar_hdr(aix_ar_hdr *ah, const fl_hdr *fh, linput_t *li)
{
  if ( memcmp(fh->fl_magic, AIAMAGBIG, SAIAMAG) == 0 )
    return qlread(li, ah, sizeof(*ah)) == sizeof(*ah);
  aix_ar_hdr_small ah_small;
  if ( qlread(li, &ah_small, sizeof(ah_small)) != sizeof(ah_small) )
    return false;
  upgrade_aix_ar_hdr(ah, &ah_small);
  return true;
}

