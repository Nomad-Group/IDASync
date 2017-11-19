#include <fpro.h>
#include <prodir.h>
#include <diskio.hpp>
#include "linuxbase_debmod.h"

//--------------------------------------------------------------------------
static inline const char *str_bitness(int bitness)
{
  switch ( bitness )
  {
    case 8:
      return "[64]";
    case 4:
      return "[32]";
    default:
      return "[x]";
  }
}

//--------------------------------------------------------------------------
static void build_process_ext_name(ext_process_info_t *pinfo)
{
  pinfo->ext_name = str_bitness(pinfo->addrsize);

  char buf[QMAXPATH];
  qsnprintf(buf, sizeof(buf), "/proc/%u/cmdline", pinfo->pid);

  FILE *cmdfp = qfopen(buf, "r");
  if ( cmdfp != NULL )
  {
    int size = qfread(cmdfp, buf, sizeof(buf));
    qfclose(cmdfp);

    for ( int i=0; i < size; )
    {
      const char *in = &buf[i];
      pinfo->ext_name +=  ' ';

      bool quoted = false;
      if ( strchr(in, ' ') != NULL || strchr(in, '"') != NULL )
      {
        pinfo->ext_name +=  '"';
        quoted = true;
      }
      char qbuf[QMAXPATH];
      str2user(qbuf, in, sizeof(qbuf));
      pinfo->ext_name += qbuf;
      if ( quoted )
        pinfo->ext_name +=  '"';
      i += strlen(in) + 1;
    }
  }
}

//--------------------------------------------------------------------------
// Returns the file name assciated with pid
bool idaapi linuxbase_debmod_t::get_exec_fname(
        int _pid,
        char *buf, size_t bufsize)
{
  char path[QMAXPATH];
  qsnprintf(path, sizeof(path), "/proc/%u/exe", _pid);
  int len = readlink(path, buf, bufsize-1);
  if ( len > 0 )
  {
    buf[len] = '\0';
    return true;
  }
  else
  {
    buf[0] = '\0';
    return false;
  }
}

//--------------------------------------------------------------------------
// Get process bitness: 32bit - 4, 64bit - 8, 0 - unknown
int idaapi linuxbase_debmod_t::get_process_bitness(int _pid)
{
  char fname[QMAXPATH];
  qsnprintf(fname, sizeof(fname), "/proc/%u/maps", _pid);
  FILE *mapfp = fopenRT(fname);
  if ( mapfp == NULL )
    return 0;

  int bitness = 4;
  char line[2*MAXSTR];
  while ( qfgets(line, sizeof(line), mapfp) != NULL )
  {
    ea_t ea1;
    ea_t ea2;
    if ( qsscanf(line, "%a-%a ", &ea1, &ea2) == 2 )
    {
      const char *found = strchr(line, '-');
      if ( (found - line) > 8 )
      {
        bitness = 8;
        break;
      }
    }
  }
  qfclose(mapfp);
  return bitness;
}

//--------------------------------------------------------------------------
int idaapi linuxbase_debmod_t::get_process_list(procvec_t *list)
{
  int mypid = getpid();
  list->clear();
  qffblk64_t fb;
  for ( int code = qfindfirst64("/proc/*", &fb, FA_DIREC);
        code == 0;
        code = qfindnext64(&fb) )
  {
    if ( !qisdigit(fb.ff_name[0]) )
      continue;
    ext_process_info_t pinfo;
    pinfo.pid = atoi(fb.ff_name);
    if ( pinfo.pid == mypid )
      continue;
    if ( !get_exec_fname(pinfo.pid, pinfo.name, sizeof(pinfo.name)) )
      continue; // we skip the process because we can not debug it anyway
    pinfo.addrsize = get_process_bitness(pinfo.pid);
    build_process_ext_name(&pinfo);
    list->push_back(pinfo);
  }
  return list->size();
}
