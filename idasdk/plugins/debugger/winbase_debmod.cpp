#include <windows.h>
#include <ida.hpp>
#include "winbase_debmod.h"

#ifndef UNDER_CE

typedef BOOL (WINAPI *GetProcessDEPPolicy_t)(HANDLE hProcess, LPDWORD lpFlags, PBOOL lpPermanent);
static GetProcessDEPPolicy_t _GetProcessDEPPolicy = NULL;

enum is_wow64_t
{
  IWT_FALSE,
  IWT_TRUE,
  IWT_UNKNOWN
};

is_wow64_t iswow64 = IWT_UNKNOWN;

//--------------------------------------------------------------------------
winbase_debmod_t::winbase_debmod_t(void)
{
  typedef dep_policy_t (WINAPI *GetSystemDEPPolicy_t)(void);

  dep_policy = dp_always_off;
  HMODULE kern_handle = GetModuleHandle(TEXT(KERNEL_LIB_NAME));
  GetSystemDEPPolicy_t _GetSystemDEPPolicy;
  *(FARPROC*)&_GetSystemDEPPolicy = GetProcAddress(kern_handle, TEXT("GetSystemDEPPolicy"));

  if ( _GetProcessDEPPolicy == NULL )
    *(FARPROC*)&_GetProcessDEPPolicy = GetProcAddress(kern_handle, TEXT("GetProcessDEPPolicy"));

  if ( _GetSystemDEPPolicy != NULL )
    dep_policy = _GetSystemDEPPolicy();
  else
    dep_policy = dp_always_off;

  iswow64 = IWT_UNKNOWN;
  process_handle = INVALID_HANDLE_VALUE;
  win_tool_help = NULL;
  winver = NULL;
  set_platform("win32");
}

//--------------------------------------------------------------------------
// Prepare new page protections for a breakpoint of BPTTYPE.
// Use INPUT as starting page protections.
// Return false in the case of failure.
bool winbase_debmod_t::remove_page_protections(
        DWORD *p_input,
        bpttype_t bpttype,
        dep_policy_t dpolicy,
        HANDLE proc_handle)
{
  // If PAGE_GUARD is already set, do not change anything, it is already ok
  DWORD input = *p_input;
  if ( (input & PAGE_GUARD) != 0 )
    return false;

  // Convert between Unix permissions and Win32 page protections using this array:
  static const uchar win32_page_protections[] =
  {
    PAGE_NOACCESS,          // 000
    PAGE_READONLY,          // 001
    0xFF,                   // 010 WRITE_ONLY does not exist on win32
    PAGE_READWRITE,         // 011
    PAGE_EXECUTE,           // 100
    PAGE_EXECUTE_READ,      // 101
    0xFF,                   // 110 EXECUTE_WRITE does not exist on win32
    PAGE_EXECUTE_READWRITE, // 111
  };
  uchar unix;
  // convert ..COPY page protections into their non-copy counterparts
  // this is the best thing we can do with them because they are automatically
  // converted by the system upon a write access
  if ( (input & PAGE_WRITECOPY) != 0 )
  {
    unix = 3; // rw
  }
  else if ( (input & PAGE_EXECUTE_WRITECOPY) != 0 )
  {
    unix = 7; // rwx
  }
  else
  {
    for ( unix=0; unix < 8; unix++ )
    {
      uchar p = win32_page_protections[unix];
      if ( p != 0xFF && (input & p) != 0 )
        break;
    }
  }
  QASSERT(622, unix < 8);

  // convert bpttype into unix permissions
  int del = 0;
  if ( (bpttype & BPT_READ) != 0 )
    del |= 1;
  if ( (bpttype & BPT_WRITE) != 0 )
    del |= 2;
  if ( (bpttype & BPT_EXEC) != 0 )
  {
    del |= 4;
    // if DEP is disabled for this process then a program can
    // happily execute code in a read only area so we need to
    // remove *all* privileges, unfortunately
    if ( dpolicy != dp_always_on )
    {
      // on XP, GetProcessDEPPolicy returns DEP policy for current process (i.e. the debugger)
      // so we can't use it
	  // assume that DEP is disabled by default
      DWORD flags = 0;
      BOOL permanent = 0;
      if ( _GetProcessDEPPolicy == NULL
        || get_win_version()->is_strictly_xp()
        || _GetProcessDEPPolicy(proc_handle, &flags, &permanent) )
      {
        // flags == 0: DEP is disabled for the specified process.
        //
        // Remarks: if permanent == 0 and global DEP policy is OptIn
        // flags may be equal to 1 *but* having DEP disabled because,
        // in case the process called SetProcessDEPPolicy the
        // permanent argument would be 1, it seems to be a bug in the
        // documentation
        if ( (dpolicy == dp_opt_in && permanent == 0) || flags == 0 )
          del |= 1;
      }
    }
  }

  // Remove the access types to trigger on
  unix &= ~del;

  // Handle WRITE_ONLY and EXECUTE_WRITE cases because win32 does not have them.
  // We use stricter page permissions for them. This means that there will
  // be more useless exceptions but we can not do much about it.
  if ( unix == 2 )
    unix = 0; // use PAGE_NOACCESS instead of WRITE_ONLY
  if ( unix == 6 )
    unix = 4; // use PAGE_EXECUTE instead of EXECUTE_WRITE

  uchar perm = win32_page_protections[unix];
  *p_input = (input & ~0xFF) | perm;
  return true;
}

//--------------------------------------------------------------------------
bool idaapi winbase_debmod_t::dbg_enable_page_bpt(
        page_bpts_t::iterator p,
        bool enable)
{
  pagebpt_data_t &bpt = p->second;
  if ( (bpt.old_prot != 0) == enable )
    return false; // already the desired state

  debdeb("dbg_enable_page_bpt(%s): page_ea=%a, old_prot=0x%x, new_prot=0x%x\n", enable ? "true" : "false", bpt.page_ea, bpt.old_prot, bpt.new_prot);

  DWORD old;
  DWORD prot = enable ? bpt.new_prot : bpt.old_prot;
  if ( !VirtualProtectEx(process_handle, (void*)(size_t)bpt.page_ea,
                         bpt.real_len, prot, &old) )
  {
    deberr("VirtualProtectEx");
    // if the page disappeared while disabling a bpt, do not complain,
    // silently return success
    if ( enable )
      return false;
  }

  debdeb("    success! old=0x%x\n", old);

  if ( enable )
    bpt.old_prot = old;
  else
    bpt.old_prot = 0; // mark as inactive
  return true;
}

//--------------------------------------------------------------------------
// Should we generate a BREAKPOINT event because of page bpt?
//lint -e{1746} could be made const reference
bool should_fire_page_bpt(
    page_bpts_t::iterator p,
    ea_t ea,
    DWORD failed_access_type,
    ea_t pc,
    dep_policy_t dep_policy)
{
  const pagebpt_data_t &bpt = p->second;
  if ( !interval::contains(bpt.ea, bpt.user_len, ea) )
    return false; // not in the user-defined interval

  int bit;
  switch ( failed_access_type )
  {
    default:
      INTERR(623);
    case EXCEPTION_READ_FAULT: // failed READ access
      // depending on the DEP policy we mark this access also
      // to be triggered in case of EXEC breakpoints
      bit = BPT_READ;
      if ( dep_policy != dp_always_on && bpt.type == BPT_EXEC && pc == ea )
        bit |= BPT_EXEC;
      break;
    case EXCEPTION_WRITE_FAULT: // failed WRITE access
      bit = BPT_WRITE;
      break;
    case EXCEPTION_EXECUTE_FAULT: // failed EXECUTE access
      bit = BPT_EXEC;
      break;
  }
  return (bpt.type & bit) != 0;
}

//--------------------------------------------------------------------------
// returns 0-failure, 2-success
int idaapi winbase_debmod_t::dbg_add_page_bpt(
        bpttype_t type,
        ea_t ea,
        int size)
{
  // only one page breakpoint per page is permitted
  page_bpts_t::iterator p = find_page_bpt(ea, size);
  if ( p != page_bpts.end() )
    return 0; // another page bpt exists

  // Find out the current page protections
  MEMORY_BASIC_INFORMATION meminfo;
  ea_t page_ea = calc_page_base(ea);
  if ( !VirtualQueryEx(process_handle, (void *)(size_t)page_ea,
                       &meminfo, sizeof(meminfo)) )
  {
    deberr("VirtualQueryEx");
    return 0;
  }

  // According to MSDN documentation for VirtualQueryEx
  // (...)
  //    AllocationProtect
  //      The memory protection option when the region was initially allocated. This member can be
  //      one of the memory protection constants or 0 if the caller does not have access.
  //
  // Unfortunately, there is no more information about why it my happen so, for now, I'm just
  // returning an error.
  if ( meminfo.Protect == 0 )
  {
    deberr("%a: the page cannot be accessed", page_ea);
    return 0;
  }

  // Calculate new page protections
  int real_len = 0;
  DWORD prot = meminfo.Protect;
  if ( remove_page_protections(&prot, type, dep_policy, process_handle) )
  { // We have to set new protections
    real_len = align_up(size, MEMORY_PAGE_SIZE);
  }

  // Remember the new breakpoint
  p = page_bpts.insert(std::make_pair(page_ea, pagebpt_data_t())).first;
  pagebpt_data_t &bpt = p->second;
  bpt.ea       = ea;
  bpt.user_len = size;
  bpt.page_ea  = page_ea;
  bpt.real_len = real_len;
  bpt.old_prot = 0;
  bpt.new_prot = prot;
  bpt.type     = type;

  // for PAGE_GUARD pages, no need to change the permissions, everything is fine already
  if ( real_len == 0 )
  {
    bpt.old_prot = meminfo.Protect;
    return 2;
  }

  return dbg_enable_page_bpt(p, true) ? 2 : 0;
}

//--------------------------------------------------------------------------
// returns true if changed *protect (in other words, if we have to mask
// the real page protections and return the original one)
bool winbase_debmod_t::mask_page_bpts(
        page_bpts_t::iterator *pbpts,
        ea_t startea,
        ea_t endea,
        uint32 *protect)
{
  // if we have page breakpoints, what we return must be changed to show the
  // real segment privileges, instead of the new ones we applied for the bpt
  int newprot = 0;
  page_bpts_t::iterator p = *pbpts;
  while ( p != page_bpts.end() )
  {
    pagebpt_data_t &pbd = p->second;
    if ( pbd.page_ea + pbd.real_len >= startea )
    {
      if ( pbd.page_ea >= endea )
        break;
      if ( pbd.old_prot != 0 )
      { // bpt has been written to the process memory
        if ( *protect == pbd.new_prot )
        { // return the old protection, before setting the page bpt
          newprot = pbd.old_prot;
        }
        else
        {
          debdeb("mask_page_bpts: app changed our page protection for %a (expected: 0x%x, actual: 0x%x)\n", pbd.page_ea, pbd.new_prot, *protect);
          // page protection has been changed by the application
          DWORD prot = *protect;
          if ( prot == PAGE_WRITECOPY && pbd.new_prot == PAGE_READWRITE
            || prot == PAGE_EXECUTE_WRITECOPY && pbd.new_prot == PAGE_EXECUTE_READWRITE )
          {
            // in some cases OS may restore WRITECOPY protection; do nothing in such cases since it works the same way for breakpoint purposes
            debdeb("   ignoring changes to WRITECOPY protection\n");
          }
          else if ( remove_page_protections(&prot, pbd.type, dep_policy, process_handle) )
          {
            pbd.new_prot = prot;
            pbd.old_prot = 0; // mark our bpt as non-written
            debdeb("   will re-set protection to 0x%x\n", pbd.new_prot);
          }
        }
      }
    }
    ++p;
  }
  *pbpts = p;
  if ( newprot != 0 )
  {
    *protect = newprot;
    return true;
  }
  return false;
}

//--------------------------------------------------------------------------
// Page breakpoints modify the page protections to induce access violations.
// We must hide the modified page protections from IDA and report the original
// page protections.
// Second, the application may render a page bpt inactive by changing its page protections.
// In this case we must report to IDA the new page protections and also reactivate
// the page breakpoint.
void winbase_debmod_t::verify_page_protections(
        meminfo_vec_t *areas,
        const win32_prots_t &prots)
{
  QASSERT(624, areas->size() == prots.size());
  if ( page_bpts.empty() )
    return;

  page_bpts_t::iterator p = page_bpts.begin();
  for ( int i=0; i < areas->size(); i++ )
  {
    uint32 prot = prots[i];
    memory_info_t &a = areas->at(i);
    if ( mask_page_bpts(&p, a.startEA, a.endEA, &prot) )
      a.perm = win_prot_to_ida_perm(prot);
  }

  // reactivate all disabled page bpts, if any
  enable_page_bpts(true);
}

//--------------------------------------------------------------------------
bool winbase_debmod_t::check_wow64_process(HANDLE handle)
{
  if ( iswow64 == IWT_UNKNOWN )
  {
    bool ret;
    iswow64 = IWT_FALSE;
    if ( is_wow64_process_h(handle, &ret) && ret )
      iswow64 = IWT_TRUE;
  }

  return iswow64 == IWT_TRUE;
}

//--------------------------------------------------------------------------
void idaapi winbase_debmod_t::dbg_term(void)
{
  iswow64 = IWT_UNKNOWN;
  delete win_tool_help;
  win_tool_help = NULL;
  delete winver;
  winver = NULL;
}

//--------------------------------------------------------------------------
// Check if we need to install a temporary breakpoint to workaround the
// 'freely running after syscall' problem. Exactly, the problem is the
// following: after single stepping over a "jmp far ptr" instruction in
// wow64cpu.dll for a 32bits process under a 64bits OS (Win7), the trap flag
// is lost. Probably, it's a bug in wow64cpu!CpuReturnFromSimulatedCode.
//
// So, if we find an instruction like "call large dword fs:XX" we add a
// temporary breakpoint at the next instruction and re-enable tracing
// when the breakpoint is reached.
bool winbase_debmod_t::check_for_call_large(
    const debug_event_t *event,
    HANDLE handle)
{
  if ( !check_wow64_process(handle) )
    return false;
  uchar buf[3];
  if ( dbg_read_memory(event->ea, buf, 3) == 3 )
  {
    // is it the call large instruction?
    if ( memcmp(buf, "\x64\xFF\x15", 3) == 0 )
      return true;
  }
  return false;
}

//--------------------------------------------------------------------------
// Get process bitness: 32bit - 4, 64bit - 8, 0 - unknown
int idaapi winbase_debmod_t::get_process_bitness(int _pid)
{
  bool is_wow64;
  if ( _pid == -1 || _pid == GetCurrentProcessId() )
#ifdef __X64__
    return 8; // we are a 64-bit app
#else
    return 4; // we are a 32-bit app
#endif
  if ( !get_win_version()->is_64bitOS() )
    return 4;
  if ( is_wow64_process(_pid, &is_wow64) )
    return is_wow64 ? 4 : 8;
  return 0;
}

//--------------------------------------------------------------------------
static const char *str_bitness(int addrsize)
{
  switch ( addrsize )
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
// this function may correct pinfo->addrsize
bool winbase_debmod_t::get_process_path(
        ext_process_info_t *pinfo,
        char *buf, size_t bufsize)
{
  module_snapshot_t msnap(get_tool_help());
  MODULEENTRY32 me;
  if ( !msnap.first(TH32CS_SNAPMODULE, pinfo->pid, &me) )
  {
    if( msnap.last_err() == ERROR_PARTIAL_COPY && pinfo->addrsize == 0 )
    {
      // MSDN: If the specified process is a 64-bit process and the caller is a
      //       32-bit process, error code is ERROR_PARTIAL_COPY
      pinfo->addrsize = 8;
    }
    qstrncpy(buf, pinfo->name, bufsize);
    return false;
  }
  else
  {
    wcstr(buf, me.szExePath, bufsize);
    return true;
  }
}

#else
winbase_debmod_t::winbase_debmod_t(void) {}
bool idaapi winbase_debmod_t::dbg_enable_page_bpt(page_bpts_t::iterator, bool) { return false; }
int winbase_debmod_t::dbg_add_page_bpt(bpttype_t, ea_t, int) { return 0; }
bool winbase_debmod_t::mask_page_bpts(page_bpts_t::iterator *, ea_t, ea_t, uint32 *) { return false; }
void winbase_debmod_t::verify_page_protections(meminfo_vec_t *, const win32_prots_t &) {}
bool winbase_debmod_t::check_for_call_large(const debug_event_t *, HANDLE) { return false; }
void idaapi winbase_debmod_t::dbg_term(void) {}
int winbase_debmod_t::get_process_bitness(pid_t) { return 4; }

static const char *str_bitness(int) { return ""; }
bool winbase_debmod_t::get_process_path(
        ext_process_info_t *pinfo,
        char *buf, size_t bufsize)
{
  qstrncpy(buf, pinfo->name, bufsize);
  return false;
}

#endif  // UNDER_CE

//--------------------------------------------------------------------------
// The following functions are common for both CE and non-CE systems

//--------------------------------------------------------------------------
win_tool_help_t *winbase_debmod_t::get_tool_help()
{
  if ( win_tool_help == NULL )
    win_tool_help = new win_tool_help_t;
  return win_tool_help;
}

//--------------------------------------------------------------------------
win_version_t *winbase_debmod_t::get_win_version()
{
  if ( winver == NULL )
    winver = new win_version_t;
  return winver;
}

//-------------------------------------------------------------------------
int winbase_debmod_t::get_process_addrsize(pid_t _pid)
{
  int addrsize = get_process_bitness(_pid);
  return addrsize != 0 ? addrsize : 4;
}

//--------------------------------------------------------------------------
//lint -esym(1762,winbase_debmod_t::build_process_ext_name) could be made const
void winbase_debmod_t::build_process_ext_name(ext_process_info_t *pinfo)
{
  char fullname[MAXSTR];
#ifdef __X64__
  get_process_path(pinfo, fullname, sizeof(fullname));
#else
  // we are a 32-bit app
  if ( get_process_path(pinfo, fullname, sizeof(fullname)) )
  {
    // get_process_path succeeded => given process is a 32bit app too
    if ( pinfo->addrsize == 0 )
      pinfo->addrsize = 4;
  }
#endif
  pinfo->ext_name = str_bitness(pinfo->addrsize);
  if ( !pinfo->ext_name.empty() )
    pinfo->ext_name += ' ';
  pinfo->ext_name += fullname;
}

//--------------------------------------------------------------------------
int idaapi winbase_debmod_t::get_process_list(procvec_t *list)
{
  int mypid = GetCurrentProcessId();
  list->clear();

  process_snapshot_t psnap(get_tool_help());
  PROCESSENTRY32 pe32;
  for ( bool ok = psnap.first(TH32CS_SNAPNOHEAPS, &pe32); ok; ok = psnap.next(&pe32) )
  {
    if ( pe32.th32ProcessID != mypid )
    {
      ext_process_info_t pinfo;
      pinfo.pid = pe32.th32ProcessID;
      wcstr(pinfo.name, pe32.szExeFile, sizeof(pinfo.name));
      pinfo.addrsize = get_process_bitness(pinfo.pid);
      build_process_ext_name(&pinfo);
      list->push_back(pinfo);
    }
  }
  return list->size();
}

//--------------------------------------------------------------------------
// Returns the file name assciated with pid
bool idaapi winbase_debmod_t::get_exec_fname(int _pid, char *buf, size_t bufsize)
{
  ext_process_info_t pinfo;
  pinfo.pid = _pid;
  pinfo.name[0] = '\0';
  return get_process_path(&pinfo, buf, bufsize);
}

//--------------------------------------------------------------------------
win_tool_help_t *winbase_debmod_t::win_tool_help = NULL;
win_version_t *winbase_debmod_t::winver = NULL;
