
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
  if ( base != BADADDR && new_base != BADADDR && base != new_base )
    rebase_or_warn(base, new_base);
}

//--------------------------------------------------------------------------
static bool init_plugin(void)
{
  if ( !netnode::inited() || is_miniidb() || inf.is_snapshot() )
    return debugger.is_remote();

  char buf[MAXSTR];
  if ( get_loader_name(buf, sizeof(buf)) <= 0 )
    return false;
  if ( stricmp(buf, "epoc") != 0 )      // only EPOC files
    return false;

  if ( ph.id != PLFM_ARM )              // only ARM
    return false;

//  is_dll = false;               // fixme: set it!
  return true;
}

//--------------------------------------------------------------------------
inline void term_plugin(void)
{
}

//--------------------------------------------------------------------------
static const char comment[] = "Userland Symbian debugger plugin";
