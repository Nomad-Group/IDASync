/*
        This file contains Win9x (95, 98) specific stuff.

        It can be safely ignored if you are only interested in XP systems.

*/

#include <windows.h>
#include <map>

#include <ida.hpp>
#include <idp.hpp>
#include <dbg.hpp>

#include "uunp.hpp"

#pragma pack(push, 1)
#ifndef __X64__
struct push_insn_t
{
  BYTE  push;   // must be 0x68
  DWORD ea;
};
#endif

//lint -estring(958,member) padding is required to align members
struct push_jump_insns_t
{
  BYTE  push;   // must be 0x68
  DWORD ea;
  BYTE  jmp;    // must be 0xE9
  DWORD reloff; //lint -esym(754,push_jump_insns_t::reloff)
};

typedef std::map<ea_t, ea_t> thunks_t;

#pragma pack(pop)

static thunks_t thunks;

//--------------------------------------------------------------------------
#ifndef __X64__
// find the address of the thunk for GetProcessAddress() under Windows 9x
void win9x_resolve_gpa_thunk(void)
{
  DWORD off;

  ea_t ea = curmod.startEA + offsetof(IMAGE_DOS_HEADER, e_lfanew);
  if ( read_dbg_memory(ea, &off, sizeof(off)) != sizeof(off) )
      return;

#define _OI offsetof(IMAGE_NT_HEADERS, OptionalHeader.DataDirectory[ \
                             IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)
  if ( read_dbg_memory((DWORD)curmod.startEA + off + _OI, &off, sizeof(off)) != sizeof(off) )
      return;
#undef _OI

  IMAGE_IMPORT_DESCRIPTOR imp;
  DWORD hK32 = (DWORD)GetModuleHandle("kernel32");

  bool found = false;
  for ( off += (DWORD)curmod.startEA;
        read_dbg_memory(off, &imp, sizeof(imp)) == sizeof(imp) && imp.Name;
        off += sizeof(imp) )
  {
    if ( imp.ForwarderChain == hK32 )
    {
      found = true;
      break;
    }
  }
  if ( found )
  {
    DWORD tmp;
    for ( off = imp.FirstThunk + (DWORD)curmod.startEA;
          read_dbg_memory(off, &tmp, sizeof(tmp)) == sizeof(tmp) && tmp != 0;
          off += sizeof(DWORD) )
    {
      if ( tmp >= hK32 )
        continue;  // for TH_xxx entries

      push_insn_t thunk;
      if ( read_dbg_memory(tmp, &thunk, sizeof(thunk)) != sizeof(thunk)
        || thunk.push != 0x68 )
      {
        break;
      }

      if( thunk.ea == bp_gpa )
      {
        bp_gpa = tmp;
        break;
      }
    }
  }
}
#endif

//--------------------------------------------------------------------------
// find all dwords equal to 'ea' and remember their translations
// search in the current module
static bool calc_thunk_target(uint32 ea32, uint32 imp32)
{
  bool matched = false;

  for ( ea_t pos = curmod.startEA;
        pos <= curmod.endEA
     && (pos = bin_search(pos, curmod.endEA, (uchar *)&ea32, NULL,
                          4, BIN_SEARCH_FORWARD,
                          BIN_SEARCH_NOBREAK|BIN_SEARCH_CASE)) != BADADDR;
        pos += sizeof(DWORD) )
  {
    if ( pos & 3 )
      continue;

    flags_t F = getFlags(pos);
    if( isTail(F) )
      continue;

    matched = true;
    thunks[pos] = imp32;
  }
  return matched;
}

//--------------------------------------------------------------------------
// find Windows 9x import thunk
static bool resolve_thunk(ea_t ea)
{
  push_jump_insns_t thunk;

  if ( !get_many_bytes(ea, &thunk, sizeof(thunk))
    || thunk.push != 0x68 || thunk.jmp != 0xE9
    || thunk.ea < 0x80000000 || thunk.ea >= 0xC0000000 )
  {
    return false;
  }

  if ( !calc_thunk_target(uint32(ea), thunk.ea) )
    msg("%a: Thunked import (%08a) without references\n", ea, ea_t(thunk.ea));
  return true;
}

//--------------------------------------------------------------------------
// Windows 9x: find thunked imports and their targets
void find_thunked_imports(void)
{
  if( (DWORD)bp_gpa & 0xF )
  {
    warning("Non-standard thunk address");
    return;
  }

  // find the thunk area for our module
  invalidate_dbgmem_contents(curmod.startEA, curmod.endEA); // for bin-search
  invalidate_dbgmem_contents(0x80000000, 0xC0000000);

  for(ea_t ea = bp_gpa; ea > 0x80000000; ea -= 0x10)
  {
      if ( !resolve_thunk(ea) )
        break;
  }

  for(ea_t ea = bp_gpa + 0x10; ea < 0xC0000000; ea += 0x10)
  {
      if ( !resolve_thunk(ea) )
        break;
  }

  if ( thunks.empty() )
    warning("Could not find thunk area");
}

//--------------------------------------------------------------------------
ea_t win9x_find_thunk(ea_t ea)
{
  thunks_t::iterator p = thunks.find(ea);
  ea_t func = p != thunks.end() ? p->second : get_long(ea);
  return func;
}
