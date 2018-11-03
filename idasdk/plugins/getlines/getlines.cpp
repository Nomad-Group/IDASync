/*
 *  This is a sample plugin module
 *
 *      It demonstrates how to get the disassembly lines for one address
 *
 */

#include <ida.hpp>
#include <idp.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

//--------------------------------------------------------------------------
int idaapi init(void)
{
  return PLUGIN_OK;
}

//--------------------------------------------------------------------------
void idaapi term(void)
{
}

//--------------------------------------------------------------------------
bool idaapi run(size_t)
{
  ea_t ea = get_screen_ea();
  if ( ask_addr(&ea, "Please enter the disassembly address")
    && is_mapped(ea) )                              // address belongs to disassembly
  {
    int flags = calc_default_idaplace_flags();
    linearray_t ln(&flags);
    idaplace_t pl;
    pl.ea = ea;
    pl.lnnum = 0;
    ln.set_place(&pl);
    msg("printing disassembly lines:\n");
    int n = ln.get_linecnt();                // how many lines for this address?
    for ( int i=0; i < n; i++ )              // process all of them
    {
      qstring buf;
      tag_remove(&buf, *ln.down());          // get line and remove color codes
      msg("%d: %s\n", i, buf.c_str());       // display it on the message window
    }
    msg("total %d lines\n", n);
  }
  return true;
}

//--------------------------------------------------------------------------
static const char comment[] = "Generate disassembly lines for one address";
static const char help[] = "Generate disassembly lines for one address\n";


//--------------------------------------------------------------------------
// This is the preferred name of the plugin module in the menu system
// The preferred name may be overriden in plugins.cfg file

static const char wanted_name[] = "Disassembly lines sample";


// This is the preferred hotkey for the plugin module
// The preferred hotkey may be overriden in plugins.cfg file
// Note: IDA won't tell you if the hotkey is not correct
//       It will just disable the hotkey.

static const char wanted_hotkey[] = "";


//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  0,                    // plugin flags
  init,                 // initialize

  term,                 // terminate. this pointer may be NULL.

  run,                  // invoke plugin

  comment,              // long comment about the plugin
                        // it could appear in the status line
                        // or as a hint

  help,                 // multiline help about the plugin

  wanted_name,          // the preferred short name of the plugin
  wanted_hotkey         // the preferred hotkey to run the plugin
};
