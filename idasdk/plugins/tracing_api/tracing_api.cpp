/* Tracing API sample plugin.
 *
 * Copyright (c) 2012 Hex-Rays, support@hex-rays.com
 *
 * This sample plugin demonstrates how to use the tracing events API
 * in IDA v6.3
 *
 * The tracing events API allow you to record, save and load traces,
 * find register values as well as memory pointed by registers.
 *
 * This sample plugin looks for an ASCII string in the recorded
 * trace's memory
 *
 */

//---------------------------------------------------------------------------
#include <idp.hpp>
#include <dbg.hpp>
#include <loader.hpp>

// last found buffer
bytevec_t last_found;

//--------------------------------------------------------------------------
bool inline __memmem(
    const unsigned char *where,
    size_t size1,
    const char *what,
    size_t size2)
{
  if ( size2 > size1 )
    return false;
  else if ( size2 == size1 )
    return memcmp(where, what, size1) == 0;

  int i = size1 - size2;
  do
  {
    if ( where[i] == what[0] )
    {
      if ( memcmp(where+i, what, size2) == 0 )
        return true;
    }
  }
  while ( --i >= 0 );

  return false;
}

//--------------------------------------------------------------------------
static void dump_memreg(const unsigned char *buf, size_t size)
{
  msg("Memory found: ");
  for ( int i = 0; i < size; i++ )
  {
    if ( isprint(buf[i]) )
      msg("%c", buf[i]);
    else
      msg(".");
  }
  msg("\n");
}

//--------------------------------------------------------------------------
static bool find_memory_tev(int i, const char *mem)
{
  // retrieve the memory map
  memreg_infos_t memmap;
  if ( get_insn_tev_reg_mem(i, &memmap) )
  {
    // iterate over all elements in the map
    memreg_infos_t::iterator p;
    for ( p = memmap.begin(); p != memmap.end(); ++p )
    {
      memreg_info_t reg = *p;
      // compare the memory of this memreg_info_t object with the given
      // string mem
      if ( last_found != reg.bytes && __memmem(reg.bytes.begin(), reg.bytes.size(), mem, strlen(mem)) )
      {
        last_found = reg.bytes;
        // if found, print it to the output window
        dump_memreg(reg.bytes.begin(), reg.bytes.size());
        return true;
      }
    }
  }
  return false;
}

//--------------------------------------------------------------------------
void idaapi run(int /*arg*/)
{
  // clear the last found buffer
  last_found.clear();

  // get the number of recorded events
  size_t total = get_tev_qty();
  if ( total == 0 )
  {
    msg("No recorded events.");
    return;
  }

  char *mem_search = askstr(HIST_SRCH, "", "Enter the string to search in the recorded trace:");
  if ( mem_search == NULL || mem_search[0] == '\0' )
    return;

  // iterate over all the recorded events
  for ( int i = total; i != 0; i-- )
  {
    // if the recorded event is an instruction trace event
    // search the string mem_search in the recorded memory
    tev_info_t tev;
    if ( get_tev_info(i, &tev) && tev.type == tev_insn )
    {
      // if the string is found in this instruction trace event's memory
      // print the tev object address, thread and number if the output
      // window
      if ( find_memory_tev(i, mem_search) )
        msg("%a: tid %d: string '%s' found in tev %d.\n", tev.ea, tev.tid, mem_search, i);
    }
  }
}

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
  "Search for a string in the recorded trace memory", // long comment about the plugin
  "", // multiline help about the plugin
  "Trace search",       // the preferred short name of the plugin
  "" // the preferred hotkey to run the plugin
};
