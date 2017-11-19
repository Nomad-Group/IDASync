/*
 *  This plugin demonstrates how to customize navigation band colors.
 *  It is fully automatic and simply inverts all colors
 */

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

static nav_colorizer_t *old_colorizer;
//--------------------------------------------------------------------------
// Callback that calculates the pixel color given the address and the number of bytes
static uint32 idaapi my_colorizer(ea_t ea, asize_t nbytes)
{
  // you are at your own here. just for the sake of illustrating how things work
  // we will invert all colors
  uint32 color = old_colorizer(ea, nbytes);
  return ~color;
}

//--------------------------------------------------------------------------
// initialize the plugin
static int idaapi init(void)
{
  // we always agree to work.
  // we must return PLUGIN_KEEP because we will install callbacks.
  // if we return PLUGIN_OK, the kernel may unload us at any time and this will
  // lead to crashes.
  old_colorizer = set_nav_colorizer(my_colorizer);
  return PLUGIN_KEEP;
}

//--------------------------------------------------------------------------
// initialize the plugin
static void idaapi term(void)
{
  // uninstall our callback for navigation band, otherwise ida will crash
  set_nav_colorizer(old_colorizer);
}

//--------------------------------------------------------------------------
static void idaapi run(int)
{
  info("This plugin is fully automatic");
}

//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  0,
  init,                 // initialize
  term,                 // terminate. this pointer may be NULL.
  run,                  // invoke plugin
  NULL,                 // long comment about the plugin
  NULL,                 // multiline help about the plugin
  "Modify navigation band colors (automatic)",// the preferred short name of the plugin
  NULL                  // the preferred hotkey to run the plugin
};
