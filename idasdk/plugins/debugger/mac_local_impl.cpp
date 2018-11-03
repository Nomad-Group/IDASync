#include <loader.hpp>

#include "macho_rebase.cpp"

//--------------------------------------------------------------------------
// installs or uninstalls debugger specific idc functions
inline bool register_idc_funcs(bool)
{
  return true;
}

//--------------------------------------------------------------------------
void idaapi rebase_if_required_to(ea_t new_base)
{
  // not a shared cache lib: it's safe to just use the imagebase
  ea_t base = get_imagebase();
  if ( base == 0 )
  {
    // old databases don't have it set; use info from netnode
    netnode n(MACHO_NODE);
    if ( exist(n) )
      base = n.altval(MACHO_ALT_IMAGEBASE);
  }

  if ( base != BADADDR
    && new_base != BADADDR
    && base != new_base
    && !rebase_scattered_segments(new_base) )
  {
    rebase_or_warn(base, new_base);
  }
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
  if ( ph.id != TARGET_PROCESSOR && ph.id != -1 )
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
