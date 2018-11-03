/*
 *  This is a sample plugin module.
 *  It demonstrates how to generate ida graphs for arbitrary ranges.
 */

#include <ida.hpp>
#include <idp.hpp>
#include <graph.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

//--------------------------------------------------------------------------
int idaapi init(void)
{
  // unload us if text mode, no graph are there
  if ( !is_idaq() )
    return PLUGIN_SKIP;
  return PLUGIN_OK;
}

//--------------------------------------------------------------------------
void idaapi term(void)
{
}

//--------------------------------------------------------------------------
bool idaapi run(size_t)
{
  ea_t ea1, ea2;
  if ( !read_range_selection(NULL, &ea1, &ea2) )
  {
    warning("Please select a range before running the plugin");
    return true;
  }
  unmark_selection();

  // fixme: how to specify multiple ranges?

  rangevec_t ranges;
  ranges.push_back(range_t(ea1, ea2));
  open_disasm_window("Selected range", &ranges);
  return true;
}

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
  NULL,
  NULL,
  "Generate graph for selection",
  NULL
};
