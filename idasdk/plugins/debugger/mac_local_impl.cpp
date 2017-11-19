// Can not include this file, compilation errors under linux:
//#include "../../ldr/mach-o/common.h"
#define MACHO_NODE "$ macho"    // supval(0) - mach_header

#include <loader.hpp>

//--------------------------------------------------------------------------
// installs or uninstalls debugger specific idc functions
inline bool register_idc_funcs(bool)
{
  return true;
}

//--------------------------------------------------------------------------
void idaapi rebase_if_required_to(ea_t new_base)
{
  ea_t base = get_imagebase();
  if ( base == 0 )
  {
    // old databases don't have it set; use info from netnode
    netnode n(MACHO_NODE);
    if ( exist(n) )
      base = n.altval(-1);
  }
  if ( base != BADADDR && new_base != BADADDR && base != new_base )
    rebase_or_warn(base, new_base);
}

//--------------------------------------------------------------------------
static bool init_plugin(void)
{
#ifndef RPC_CLIENT
  if ( !init_subsystem() )
    return false;
#endif

  if ( !netnode::inited() || is_miniidb() || inf.is_snapshot() )
  {
#ifdef __MAC__
    // local debugger is available if we are running under MAC OS X
    return true;
#else
    // for other systems only the remote debugger is available
    return debugger.is_remote();
#endif
  }

  char buf[MAXSTR];
  if ( get_loader_name(buf, sizeof(buf)) <= 0 )
    return false;
  if ( stricmp(buf, "macho") != 0 )     // only Mach-O files
    return false;
  if ( ph.id != TARGET_PROCESSOR )
    return false;

  return true;
}

//--------------------------------------------------------------------------
inline void term_plugin(void)
{
#ifndef RPC_CLIENT
  term_subsystem();
#endif
}

//--------------------------------------------------------------------------
static const char comment[] = "Userland Mac OS X debugger plugin.";
