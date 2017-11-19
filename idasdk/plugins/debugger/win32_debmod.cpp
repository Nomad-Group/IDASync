#include <windows.h>
#include <fpro.h>
#include <err.h>
#include <ida.hpp>
#include <dbg.hpp>
#include <prodir.h>
#include <exehdr.h>
#include <kernwin.hpp>
#include <segment.hpp>
#include "win32_debmod.h"
#include "consts.h"

//--------------------------------------------------------------------------

#ifdef UNDER_CE
  #ifndef EXCEPTION_READ_FAULT
    #define EXCEPTION_READ_FAULT 0          // exception caused by a read
  #endif
  #ifndef EXCEPTION_WRITE_FAULT
    #define EXCEPTION_WRITE_FAULT 1         // exception caused by a write
  #endif
  #ifndef EXCEPTION_EXECUTE_FAULT
    #define EXCEPTION_EXECUTE_FAULT 8       // exception caused by an instruction fetch
  #endif

  #include "wince_debmod_impl.cpp"
  #define get_reg_class(reg_idx) ARM_RC_GENERAL
#else
  #ifndef TH32CS_SNAPNOHEAPS
    #define TH32CS_SNAPNOHEAPS    0x0
  #endif
  #include "win32_debmod_impl.cpp"
  #define get_reg_class(reg_idx) get_x86_reg_class(reg_idx)
#endif

typedef HANDLE (WINAPI *OpenThread_t)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId);
OpenThread_t _OpenThread = NULL;

//--------------------------------------------------------------------------
// Macro to test the DBG_FLAG_DONT_DISTURB flag
#if 0
#define NODISTURB_ASSERT(x) QASSERT(x)
#else
#define NODISTURB_ASSERT(x)
#endif

static int g_code = 0;

//--------------------------------------------------------------------------
void win32_debmod_t::check_thread(bool must_be_main_thread) const
{
  // remote debugger uses only one thread
  if ( rpc != NULL )
    return;

  // someone turned off debthread?
  if ( (debugger_flags & DBG_FLAG_DEBTHREAD) == 0 )
    return;

  // local debugger uses 2 threads and we must be in the correct one
  QASSERT(30191, is_main_thread() == must_be_main_thread);
}

//--------------------------------------------------------------------------
static int unicode_to_ansi(char *buf, size_t bufsize, LPCWSTR unicode)
{
  qstring res;
  u2cstr(unicode, &res);
  qstrncpy(buf, res.c_str(), bufsize);
  size_t n = res.length();
  if ( n > bufsize )
    n = bufsize;
  return (int)n;
}

//--------------------------------------------------------------------------
// try to locate full path of a dll name without full path
// for example, toolhelp.dll -> c:\windows\toolhelp.dll
static bool find_full_path(char *fname, size_t fnamesize, const char *process_path)
{
  if ( fname[0] != '\0' && !qisabspath(fname) )
  {
    char path[QMAXPATH];
    char dir[QMAXPATH];
    // check system directory
#ifdef UNDER_CE
    qstrncpy(dir, "\\Windows\\", sizeof(dir));
#else
    GetSystemDirectory(dir, sizeof(dir));
#endif
    qmakepath(path, sizeof(path), dir, fname, NULL);
    if ( qfileexist(path) )
    {
FOUND:
      qstrncpy(fname, path, fnamesize);
      return true;
    }
    // check current process directory
    if ( !qisabspath(process_path) )
    {
      qdirname(dir, sizeof(dir), process_path);
      qmakepath(path, sizeof(path), dir, fname, NULL);
      if ( qfileexist(path) )
        goto FOUND;
    }
#ifndef UNDER_CE
    // check current directory
    if ( GetCurrentDirectory(sizeof(dir), dir) != 0 )
    {
      qmakepath(path, sizeof(path), dir, fname, NULL);
      if ( qfileexist(path) )
        goto FOUND;
    }
#endif
    return false;
  }
  return true;
}

//--------------------------------------------------------------------------
ssize_t win32_debmod_t::access_memory(ea_t ea, void *buffer, ssize_t size, bool do_write, bool suspend)
{
  if ( process_handle == INVALID_HANDLE_VALUE )
    return -1;

  NODISTURB_ASSERT(in_event != NULL || exiting);

  // stop all threads before accessing its memory
  if ( suspend )
    suspend_all_threads();

  ea = s0tops(ea);
  void *addr = (void *)(size_t)ea;

  DWORD_PTR size_access = 0;
  const DWORD BADPROT = DWORD(-1);
  DWORD oldprotect = BADPROT;
  bool ok;

  while ( true )
  {
    // try to access the memory

    ok = do_write
       ? WriteProcessMemory(
           process_handle,     // handle of the process whose memory is accessed
           addr,               // address to start access
           buffer,             // address of buffer
           (DWORD)size,        // number of bytes to access
           (PDWORD_PTR)&size_access) != 0// address of number of bytes accessed
       : ReadProcessMemory(
           process_handle,     // handle of the process whose memory is accessed
           addr,               // address to start access
           buffer,             // address of buffer
           (DWORD)size,        // number of bytes to access
           (PDWORD_PTR)&size_access) != 0;// address of number of bytes accessed

    // if we have changed the page protection, revert it
    if ( oldprotect != BADPROT )
    {
      if ( !VirtualProtectEx(
              process_handle,     // handle of the process whose memory is accessed
              addr,               // address to start access
              (DWORD)size,        // number of bytes to access
              oldprotect,
              &oldprotect) )
      {
        deberr("VirtualProtectEx2(%08a)", ea);
      }
      break; // do not attempt more than once
    }

    // bail out after a successful read/write
    if ( ok )
      break;

    // bail out if it is not about "not enough access rights"
    // *or* ERROR_PARTIAL_COPY as, sometimes we may read/write
    // *only* parts of memory because of page breakpoints
    int code = GetLastError();
    if ( code != ERROR_NOACCESS && code != ERROR_PARTIAL_COPY )
    {
      deberr("%sProcessMemory(%a)", do_write ? "Write" : "Read", ea);
      break;
    }

    if ( code != ERROR_PARTIAL_COPY )
      size_access = 0; // size_access may be spoiled after failed ReadProcessMemory

    // check if the address is valid
    MEMORY_BASIC_INFORMATION meminfo;
    if ( !VirtualQueryEx(process_handle,       // handle of process
                            addr,              // address of region
                            &meminfo,          // address of information buffer
                            sizeof(meminfo)) ) // size of buffer
    {
      size_access = 0;
      break;
    }

    // allow the desired access on the page
    if ( !VirtualProtectEx(
      process_handle,     // handle of the process whose memory is accessed
      addr,               // address to start access
      (DWORD)size,        // number of bytes to access
      do_write ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ,
      &oldprotect) )
    {
      deberr("VirtualProtectEx1(%08a, size=%d for %s)", ea, int(size), do_write ? "write" : "read");
      break;
    }
  }

  if ( do_write && ok )
    FlushInstructionCache(
      process_handle,      // handle to process with cache to flush
      addr,                // pointer to region to flush
      (DWORD)size);        // length of region to flush

  if ( suspend )
    resume_all_threads();
  return size_access;
}

//--------------------------------------------------------------------------
ssize_t win32_debmod_t::_read_memory(ea_t ea, void *buffer, size_t size, bool suspend)
{
  return access_memory(ea, buffer, size, false, suspend);
}

ssize_t idaapi win32_debmod_t::dbg_read_memory(ea_t ea, void *buffer, size_t size)
{
  check_thread(false);
  return _read_memory(ea, buffer, size, true);
}

//--------------------------------------------------------------------------
// Make sure that the thread is suspended
// by calling SuspendThread twice
// If raw=true then SuspendThread() API will be called and we return directly
// without doing any further logic
static void _sure_suspend_thread(thread_info_t &ti, bool raw = false)
{
  HANDLE h = ti.hThread;

  int count = SuspendThread(h);
  if ( raw )
    return;

  if ( count != -1 )
    ti.suspend_count++;

  count = SuspendThread(h);
  if ( count != -1 )
    ti.suspend_count++;
}

//--------------------------------------------------------------------------
// Resume thread by calling ResumeThread as many times as required
// Note: this function just reverts the actions of sure_suspend_thread
// If the thread was already suspended before calling sure_suspend_thread
// then it will stay in the suspended state
// If raw=true then ResumeThread() will be called and we return directly
// without doing any further logic
static void _sure_resume_thread(thread_info_t &ti, bool raw = false)
{
  HANDLE h = ti.hThread;
  if ( raw )
  {
    ResumeThread(h);
    return;
  }

  while ( ti.suspend_count > 0 )
  {
    ResumeThread(h);
    ti.suspend_count--;
  }
}

//--------------------------------------------------------------------------
inline void win32_debmod_t::suspend_all_threads(bool raw)
{
  for ( threads_t::iterator p=threads.begin(); p != threads.end(); ++p )
    _sure_suspend_thread(p->second, raw);
}

//--------------------------------------------------------------------------
inline void win32_debmod_t::resume_all_threads(bool raw)
{
  for ( threads_t::iterator p=threads.begin(); p != threads.end(); ++p )
    _sure_resume_thread(p->second, raw);
}

//--------------------------------------------------------------------------
static int get_thread_suspend_count(HANDLE hThread)
{
  DWORD dwSuspendCount = SuspendThread(hThread);
  ResumeThread(hThread);
  return dwSuspendCount;
}

//--------------------------------------------------------------------------
inline void win32_debmod_t::suspend_running_threads(threadvec_t &suspended)
{
  for ( threads_t::iterator p=threads.begin(); p != threads.end(); ++p )
  {
    thread_info_t t = p->second;
    t.suspend_count = get_thread_suspend_count(t.hThread);
    if ( t.suspend_count == 0 )
    {
      _sure_suspend_thread(t);
      suspended.push_back(t);
    }
  }
}

//--------------------------------------------------------------------------
inline void win32_debmod_t::resume_suspended_threads(threadvec_t suspended) const
{
  threadvec_t::iterator p;
  for ( p = suspended.begin(); p != suspended.end(); ++p )
    _sure_resume_thread(*p);
}

//--------------------------------------------------------------------------
size_t win32_debmod_t::add_dll(image_info_t &ii)
{
  dlls.insert(std::make_pair(ii.base, ii));
  dlls_to_import.insert(ii.base);
  return (size_t)ii.imagesize;
}

//--------------------------------------------------------------------------
// iterate all modules of the specified process
// until the callback returns != 0
int win32_debmod_t::for_each_module(DWORD _pid, module_cb_t module_cb, void *ud)
{
  int code = 0;

  module_snapshot_t msnap(get_tool_help());
  MODULEENTRY32 me;
  for ( bool ok = msnap.first(TH32CS_SNAPNOHEAPS, _pid, &me); ok; ok = msnap.next(&me) )
  {
    code = module_cb(this, &me, ud);
    if ( code != 0 )
      break;
  }
  return code;
}

//--------------------------------------------------------------------------
// callback: get info about the main module of the debugger process
//lint -e{818}
int win32_debmod_t::get_dmi_cb(debmod_t *sess, MODULEENTRY32 *me32, void *ud)
{
  win32_debmod_t *_this = (win32_debmod_t *)sess;
  // if the module name doesn't correspond to the process name,
  // we continue to iterate
  char buf[QMAXPATH];
  wcstr(buf, me32->szModule, sizeof(buf));
  if ( !_this->process_path.empty() && stricmp(buf, qbasename(_this->process_path.c_str())) != 0 )
    return 0;

  // ok, this module corresponds to our debugged process
  module_info_t &dmi = *(module_info_t *)ud;
  qstrncpy(dmi.name, buf, sizeof(dmi.name));
  dmi.base = EA_T(me32->modBaseAddr);
  dmi.size = (asize_t)me32->modBaseSize;
  return 1; // we stop to iterate
}

//--------------------------------------------------------------------------
// Return module information on the currently debugged process
void win32_debmod_t::get_debugged_module_info(module_info_t *dmi)
{
  dmi->name[0]   = '\0';
  dmi->base      = BADADDR;
  dmi->size      = 0;
  dmi->rebase_to = BADADDR;
  for_each_module(pid, get_dmi_cb, dmi);
}

//--------------------------------------------------------------------------
void idaapi win32_debmod_t::dbg_stopped_at_debug_event(void)
{
  check_thread(true);
  // we will take advantage of this event to import information
  // about the exported functions from the loaded dlls
  name_info_t &ni = *get_debug_names();
  for ( easet_t::iterator p=dlls_to_import.begin(); p != dlls_to_import.end(); )
  {
    get_dll_exports(dlls, *p, ni);
    dlls_to_import.erase(p++);
  }
}

//--------------------------------------------------------------------------
// return the address of an exported name
ea_t win32_debmod_t::get_dll_export(
  const images_t &_dlls,
  ea_t imagebase,
  const char *exported_name)
{
  ea_t ret = BADADDR;

  name_info_t ni;
  if ( get_dll_exports(_dlls, imagebase, ni, exported_name) && !ni.addrs.empty() )
    ret = ni.addrs[0];
  return ret;
}

//--------------------------------------------------------------------------
win32_debmod_t::win32_debmod_t()
{
  debug_break_ea = ea_t(0);
  expecting_debug_break = false;
  fake_suspend_event = false;

  pid = -1;

  // Reset handles
  process_handle =
  thread_handle  =
  redirin_handle =
  redirout_handle = INVALID_HANDLE_VALUE;

  attach_evid = INVALID_HANDLE_VALUE;
  attach_status = as_none;

  memset(&cpdi, 0, sizeof(cpdi));
  cpdi.hFile = INVALID_HANDLE_VALUE;  // hFile
  cpdi.hProcess = INVALID_HANDLE_VALUE;  // hProcess
  cpdi.hThread = INVALID_HANDLE_VALUE;  // hThread

  winxp_step_thread = 0;
  memset(&in_event, 0, sizeof(in_event));
  exiting = false;
  DebugBreakProcess_requested = false;

  pdb_remote_session = NULL;
  broken_event_handle = NULL;
  // we don't set platform name here because it will be inherited
  // from winbase_debmod_t
}

//----------------------------------------------------------------------
// return the handle associated with a thread id from the threads list
HANDLE win32_debmod_t::get_thread_handle(thid_t tid)
{
  thread_info_t *tinfo = threads.get(tid);
  return tinfo == NULL ? INVALID_HANDLE_VALUE : tinfo->hThread;
}

//--------------------------------------------------------------------------
bool win32_debmod_t::refresh_hwbpts(void)
{
  for ( threads_t::iterator p=threads.begin(); p != threads.end(); ++p )
    set_hwbpts(p->second.hThread);
  return true;
}

//--------------------------------------------------------------------------
// 1-ok, 0-failed
int idaapi win32_debmod_t::dbg_del_bpt(bpttype_t type, ea_t ea, const uchar *orig_bytes, int len)
{
  check_thread(false);
  if ( orig_bytes != NULL )
  {
    bpts.erase(ea);
    suspend_all_threads();
    // write the old value only if our bpt is still present
    bool ok = has_bpt_at(ea) && _write_memory(ea, orig_bytes, len) == len;
    resume_all_threads();
    return ok;
  }

  // try to delete a page bpt first
  if ( del_page_bpt(ea, type) )
    return true;
  return del_hwbpt(ea, type);
}

//--------------------------------------------------------------------------
ssize_t win32_debmod_t::_write_memory(ea_t ea, const void *buffer, size_t size, bool suspend)
{
  if ( !may_write(ea) )
    return -1;
  return access_memory(ea, (void *)buffer, size, true, suspend);
}

//--------------------------------------------------------------------------
void idaapi win32_debmod_t::dbg_term(void)
{
  check_thread(true);
  cleanup_hwbpts();
  cleanup();
  if ( pdb_remote_session != NULL )
  {
    close_pdb_remote_session(pdb_remote_session);
    pdb_remote_session = NULL;
  }
  inherited::dbg_term();
}

//--------------------------------------------------------------------------
bool win32_debmod_t::has_bpt_at(ea_t ea)
{
  uchar bytes[8];
  int size = bpt_code.size();
  return _read_memory(ea, bytes, size) == size
    && memcmp(bytes, bpt_code.begin(), size) == 0;
}

//--------------------------------------------------------------------------
// 2-ok(pagebpt), 1-ok, 0-failed
int idaapi win32_debmod_t::dbg_add_bpt(bpttype_t type, ea_t ea, int len)
{
  check_thread(false);
  if ( type == BPT_SOFT )
  {
    int size = bpt_code.size();
    debmod_bpt_t dbpt(ea, len);
    if ( dbg_read_memory(ea, dbpt.saved, len)
      && dbg_write_memory(ea, bpt_code.begin(), size) != size )
    {
      return false;
    }
    bpts[ea] = dbpt;
    return true;
  }

#ifdef UNDER_CE
  return add_hwbpt(type, ea, len);
#else
  // try, first, to add a real hw breakpoint
  // if it fails, add a memory range type bpt
  // reason: the user may try to insert a 5th
  // correct hw bpt, however, it isn't possible
  // so, instead, we add a page breakpoint
  int ret = 0;
  if ( check_x86_hwbpt(type, ea, len) == BPT_OK )
    ret = add_hwbpt(type, ea, len);

  if ( !ret )
    ret = dbg_add_page_bpt(type, ea, len);
  return ret;
#endif
}

//--------------------------------------------------------------------------
int idaapi win32_debmod_t::dbg_get_memory_info(meminfo_vec_t &areas)
{
  check_thread(false);
  NODISTURB_ASSERT(in_event != NULL);

  images.clear();
  thread_areas.clear();
  class_areas.clear();
  for ( threads_t::iterator t=threads.begin(); t != threads.end(); ++t )
    add_thread_areas(process_handle, t->first, thread_areas, class_areas);

  if ( process_handle != INVALID_HANDLE_VALUE )
  {
    page_bpts_t::iterator p = page_bpts.begin();
    for ( ea_t ea=0; ea != BADADDR; )
    {
      memory_info_t meminf;
      ea = get_region_info(&p, ea, &meminf);
      if ( meminf.startEA != BADADDR )
        areas.push_back(meminf);
    }
    enable_page_bpts(true);
  }

  if ( same_as_oldmemcfg(areas) )
    return -2;

  save_oldmemcfg(areas);
  return 1;
}

//--------------------------------------------------------------------------
// 1-ok, 0-failed
int idaapi win32_debmod_t::dbg_thread_suspend(thid_t tid)
{
  check_thread(false);
  NODISTURB_ASSERT(in_event != NULL);
  int count = SuspendThread(get_thread_handle(tid));

  if ( debug_debugger )
    debdeb("SuspendThread(%08X) -> %d\n", tid, count);

  return count != -1;
}

//--------------------------------------------------------------------------
// 1-ok, 0-failed
int idaapi win32_debmod_t::dbg_thread_continue(thid_t tid)
{
  check_thread(false);
  NODISTURB_ASSERT(in_event != NULL);
  int count = ResumeThread(get_thread_handle(tid));
  if ( count == -1 )
  {
    deberr("ResumeThread(%08X)", tid);
  }
  //else if ( debug_debugger )
  //{
  //  debdeb("ResumeThread(%08X) -> %d\n", tid, count);
  //}
  return count != -1;
}

//--------------------------------------------------------------------------
bool thread_info_t::read_context(int clsmask)
{
  if ( (flags & clsmask) != clsmask )
  {
    int ctxflags = CONTEXT_CONTROL|CONTEXT_INTEGER;
#ifdef __ARM__
    qnotused(clsmask);
#else
    if ( (clsmask & X86_RC_SEGMENTS) != 0 )
      ctxflags |= CONTEXT_SEGMENTS;
    if ( (clsmask & (X86_RC_FPU|X86_RC_MMX)) != 0 )
      ctxflags |= CONTEXT_FLOATING_POINT;
    if ( (clsmask & X86_RC_XMM) != 0 )
#ifdef __X64__
      ctxflags |= CONTEXT_FLOATING_POINT;
#else
      ctxflags |= CONTEXT_EXTENDED_REGISTERS;
#endif
#endif
    ctx.ContextFlags = ctxflags;
    if ( !GetThreadContext(hThread, &ctx) )
      return false;
    invalidate_context();
    ctx.ContextFlags = ctxflags; // invalidate_context() zeroed it
    flags |= clsmask | RC_GENERAL;
  }
  return true;
}

//--------------------------------------------------------------------------
// 1-ok, 0-failed
int idaapi win32_debmod_t::dbg_prepare_to_pause_process(void)
{
  check_thread(false);
  bool ok = true;
  win_tool_help_t *wth = get_tool_help();
  if ( wth->use_debug_break_process() ) // only possible on XP/2K3 or higher
  {
    ok = wth->debug_break_process(process_handle);
    expecting_debug_break = ok;
  }
  else
  {
    suspend_all_threads();
    for ( threads_t::iterator p=threads.begin(); p != threads.end(); ++p )
    {
      thread_info_t &ti = p->second;
      if ( !ti.read_context(RC_GENERAL) )
      {
        ok = false;
        continue;
      }
      if ( !set_thread_bpt(ti, ti.ctx.Eip) )
        ok = false;
    }
    resume_all_threads();
#ifdef UNDER_CE
    if ( !ok )
    {
      // This could happen if the thread context is in the kernel area and we
      // failed to write the bpt code.
      // In this case we simply suspend all threads to produce a "synthesized" suspended state
      dmsg("!!! Debugger could not break in user code. Suspending all threads instead. !!!\n");
      suspend_all_threads(true);
      // Generate a suspend event
      debug_event_t event;
      event.eid = PROCESS_SUSPEND;
      event.handled = true;
      get_debugged_module_info(&event.modinfo);
      events.enqueue(event, IN_BACK);
      fake_suspend_event = true;
      ok = true;
    }
#endif
  }
  return ok;
}

//----------------------------------------------------------------------
// return the name associated with an existing image in 'images' list
// containing a particular range
static const char *get_range_name(const images_t &images, const area_t *range)
{
  for ( images_t::const_iterator p=images.begin(); p != images.end(); ++p )
  {
    const image_info_t &img = p->second;
    ea_t ea1 = (ea_t)img.base;
    ea_t ea2 = ea1 + img.imagesize;
    area_t b = area_t(ea1, ea2);
    b.intersect(*range);
    if ( !b.empty() )
      return img.name.c_str();
  }
  return NULL;
}

//--------------------------------------------------------------------------
void win32_debmod_t::restore_original_bytes(ea_t ea, bool really_restore)
{
  bpt_info_t::iterator p = thread_bpts.find(ea);
  if ( p == thread_bpts.end() )
  {
    derror("interr: can't find orig_bytes info for %a", ea);
  }
  if ( --p->second.count == 0 )
  {
    uchar *obytes = p->second.orig_bytes;
    if ( really_restore )
    {
      int size = bpt_code.size();
      if ( _write_memory(ea, obytes, size) != size )
      {
        derror("interr: could not restore orginal insn of tmp bpt\n");
      }
    }
    thread_bpts.erase(p);
  }
}

//--------------------------------------------------------------------------
// returns: 0-error,1-ok,2-already had bpt, just increased the counter
int win32_debmod_t::save_original_bytes(ea_t ea)
{
  bpt_info_t::iterator p = thread_bpts.find(ea);
  if ( p == thread_bpts.end() )
  {
    internal_bpt_info_t ibi;
    ibi.count = 1;
    int size = bpt_code.size();
    if ( _read_memory(ea, ibi.orig_bytes, size) != size )
      return 0;
    thread_bpts.insert(std::make_pair(ea, ibi));
    return 1;
  }
  else
  {
    p->second.count++;
    return 2;
  }
}

//--------------------------------------------------------------------------
bool win32_debmod_t::del_thread_bpt(thread_info_t &ti, ea_t ea)
{
  if ( ti.bpt_ea == BADADDR )
    return false;

  if ( ti.bpt_ea == ea )
  {
    if ( !ti.read_context(RC_GENERAL) )
      return false;
    ti.ctx.Eip = ti.bpt_ea; // reset EIP
    DWORD saved = ti.ctx.ContextFlags;
    ti.ctx.ContextFlags = CONTEXT_CONTROL;
    if ( !SetThreadContext(ti.hThread, &ti.ctx) )
      deberr("del_thread_bpt: SetThreadContext");
    ti.ctx.ContextFlags = saved;
  }

  // do not restore the thread breakpoint if we installed
  // a temporary breakpoint to workaround the stepping over
  // callgates problem
  if ( !ti.is_tracing() || ti.bpt_ea != ti.callgate_ea )
  {
    // restore old insn if necessary
    restore_original_bytes(ti.bpt_ea);
    ti.bpt_ea = BADADDR;
  }
  return true;
}

//--------------------------------------------------------------------------
// delete all thread breakpoints
// returns true if a breakpoint at which we stopped was removed
bool win32_debmod_t::del_thread_bpts(ea_t ea)
{
  bool found = false;
  for ( threads_t::iterator p=threads.begin(); p != threads.end(); ++p )
    found |= del_thread_bpt(p->second, ea);
  return found;
}

//--------------------------------------------------------------------------
bool win32_debmod_t::set_thread_bpt(thread_info_t &ti, ea_t ea)
{
  // delete old thread bpt if any existed before
  del_thread_bpt(ti, BADADDR);

  ti.bpt_ea = ea;
  int code = save_original_bytes(ti.bpt_ea);
  if ( code )
  {
    if ( code == 2 ) // already have a bpt?
      return true;   // yes, then everything ok
    int size = bpt_code.size();
    code = _write_memory(ti.bpt_ea, bpt_code.begin(), size);
    if ( code > 0 )
    {
      if ( code == size )
        return true;
      // failed to write, forget the original byte
      restore_original_bytes(ti.bpt_ea, false);
    }
  }
  debdeb("%a: set_thread_bpt() failed to pause thread %d\n", ti.bpt_ea, ti.tid);
  ti.bpt_ea = BADADDR;
  return false;
}

//--------------------------------------------------------------------------
gdecode_t win32_debmod_t::get_debug_event(debug_event_t *event, int timeout_ms)
{
  check_thread(false);
  if ( events.retrieve(event) )
    return events.empty() ? GDE_ONE_EVENT : GDE_MANY_EVENTS;

  DEBUG_EVENT DebugEvent;
  // we have to wait infinitely if we just try to attach to a running process
  if ( attach_status == as_attaching )
    timeout_ms = INFINITE;
  if ( !WaitForDebugEvent(&DebugEvent, timeout_ms) )
  {
    // no event occured
    if ( attach_status == as_detaching ) // if we were requested to detach,
    {                                    // we generate a fake detach event
      event->eid = PROCESS_DETACH;
      return GDE_ONE_EVENT;
    }
#ifdef UNDER_CE
    // Under CE there is no bpt after attaching???
    if ( attach_status == as_breakpoint )
    {
      create_attach_event(event, true);
      return GDE_ONE_EVENT;
    }
#endif
    // else, we don't return an event
    return GDE_NO_EVENT;
  }

  if ( attach_status == as_attaching )
  {
    if ( DebugEvent.dwDebugEventCode != CREATE_PROCESS_DEBUG_EVENT )
      return GDE_ERROR;
    // fill in starting information for the just attached process (we couldn't do it from CreateProcess() return values !)
    process_path   = "";
    pid            = DebugEvent.dwProcessId;
    process_handle = DebugEvent.u.CreateProcessInfo.hProcess;
    thread_handle  = INVALID_HANDLE_VALUE; // no need to close the main thread at the end of the debugging for an attached process
    attach_status  = as_breakpoint;
  }

  if ( debug_debugger )
    show_debug_event(DebugEvent, process_handle, process_path.c_str());

  // ignore events coming from other child processes
  if ( DebugEvent.dwProcessId != pid )
  {
#ifdef UNDER_CE
    // hardware bpts may occur in any application
    if ( DebugEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT )
    {
      if ( check_for_hwbpt(event) )
      {
        event->pid = DebugEvent.dwProcessId;
        event->tid = DebugEvent.dwThreadId;
        event->ea = (ea_t)DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress;
        if ( !is_ce600() )
        {
          if ( event->ea < 0x42000000 )
            event->ea |= get_process_slot((HANDLE)DebugEvent.dwProcessId);
        }
        in_event = event;
        return GDE_ONE_EVENT;
      }
    }
#endif
    debdeb("ignore: pid %x != %x\n", DebugEvent.dwProcessId, pid);
    bool handled = DebugEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT
      && DebugEvent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT;

    if ( !ContinueDebugEvent(DebugEvent.dwProcessId,
      DebugEvent.dwThreadId,
      handled ? DBG_CONTINUE : DBG_EXCEPTION_NOT_HANDLED) )
    {
      deberr("ContinueDebugEvent");
    }
    invalidate_all_contexts();
    return GDE_NO_EVENT;
  }

  event->pid = DebugEvent.dwProcessId;
  event->tid = DebugEvent.dwThreadId;
  event->handled = true;

  gdecode_t gdecode = GDE_ONE_EVENT;
  switch ( DebugEvent.dwDebugEventCode )
  {
    case EXCEPTION_DEBUG_EVENT:
      {
        EXCEPTION_RECORD &er = DebugEvent.u.Exception.ExceptionRecord;
        // remove temporary breakpoints if any
        bool was_thread_bpt = del_thread_bpts(EA_T(er.ExceptionAddress));
        bool firsttime = DebugEvent.u.Exception.dwFirstChance != 0;
        gdecode = handle_exception(event, er, was_thread_bpt, firsttime);
      }
      break;

    case CREATE_THREAD_DEBUG_EVENT:
      {
        // add this thread to our list
        threads.insert(std::make_pair(event->tid, thread_info_t(DebugEvent.u.CreateThread, event->tid)));
        event->eid = THREAD_START;
        event->ea = EA_T(DebugEvent.u.CreateThread.lpStartAddress);
        // set hardware breakpoints if any
        set_hwbpts(DebugEvent.u.CreateThread.hThread);
      }
      break;

    case CREATE_PROCESS_DEBUG_EVENT:
      {
        // save information for later
        cpdi = DebugEvent.u.CreateProcessInfo;
        cpdi.lpBaseOfImage = correct_exe_image_base(cpdi.lpBaseOfImage);
        ea_t base = EA_T(cpdi.lpBaseOfImage);
        process_handle = cpdi.hProcess;

        create_start_event(event);
#ifdef UNDER_CE
        // try GetModuleInformation(0) for the main EXE
        if ( event->modinfo.size == 0 )
          event->modinfo.size = calc_imagesize(0);
#endif
        curproc.insert(std::make_pair(event->modinfo.base, image_info_t(this, event->modinfo)));

        // set debug hook to get information about exceptions
        set_debug_hook(base);

        // add record about the main thread into the list
        CREATE_THREAD_DEBUG_INFO ctdi;
        ctdi.hThread           = cpdi.hThread;
        ctdi.lpThreadLocalBase = cpdi.lpThreadLocalBase;
        ctdi.lpStartAddress    = cpdi.lpStartAddress;
        threads.insert(std::make_pair(DebugEvent.dwThreadId, thread_info_t(ctdi, DebugEvent.dwThreadId)));

        // set hardware breakpoints if any
        set_hwbpts(cpdi.hThread);

        // test hardware breakpoints:
        // add_hwbpt(HWBPT_WRITE, 0x0012FF68, 4);
        if ( !debug_break_ea && get_win_version()->is_DW32() ) // dw32 specific
        {
          HINSTANCE h = GetModuleHandle(TEXT(TOOLHELP_LIB_NAME));
          debug_break_ea = (DWORD_PTR)GetProcAddress(h, TEXT("DebugBreak"));
          expecting_debug_break = true;
        }
        break;
      }

    case EXIT_THREAD_DEBUG_EVENT:
      {
        threads.erase(event->tid);
        event->eid       = THREAD_EXIT;
        event->exit_code = DebugEvent.u.ExitThread.dwExitCode;
        // invalidate corresponding handles
        HANDLE h = get_thread_handle(event->tid);
        if ( h == thread_handle )
          thread_handle = INVALID_HANDLE_VALUE;
        if ( h == cpdi.hThread )
          cpdi.hThread = INVALID_HANDLE_VALUE;
        break;
      }

    case EXIT_PROCESS_DEBUG_EVENT:
      event->eid       = PROCESS_EXIT;
      event->exit_code = DebugEvent.u.ExitProcess.dwExitCode;
      exiting = true;
      break;

    case LOAD_DLL_DEBUG_EVENT:
      {
        event->eid               = LIBRARY_LOAD;
        event->ea                = EA_T(DebugEvent.u.LoadDll.lpBaseOfDll);
        event->modinfo.base      = event->ea;
        event->modinfo.rebase_to = BADADDR; // this must be determined locally - see common_local.cpp

        char full_name[MAXSTR];
        get_filename_for(EA_T(DebugEvent.u.LoadDll.lpImageName),
          DebugEvent.u.LoadDll.fUnicode != 0,
          event->ea,
          full_name,
          sizeof(full_name),
          process_handle,
          process_path.c_str());

        qstrncpy(event->modinfo.name, full_name, sizeof(event->modinfo.name));
        image_info_t di(this, DebugEvent.u.LoadDll, full_name);
        di.name = full_name;

        // set debug hook to get information about exceptions
        set_debug_hook(di.base);

        // we defer the import of the dll until the moment when ida stops
        // at a debug event. we do so to avoid unnecessary imports because
        // the dll might get unloaded before ida stops.
        event->modinfo.size = add_dll(di);

#ifndef UNDER_CE
        // determine the first breakpoint if needed
        if ( debug_break_ea == 0 )
        {
          const char *base_name = qbasename(full_name);
          if ( get_win_version()->is_NT() ) // NT
          {
            if ( stricmp(base_name, "ntdll.dll") == 0
              || stricmp(base_name, "ntdll32.dll") == 0 ) // sysWOW64 under Win64
            {
              debug_break_ea = get_dll_export(dlls, di.base, "DbgBreakPoint");
            }
          }
          else // 9x
          {
            if ( stricmp(base_name, KERNEL_LIB_NAME) == 0 ) // 9X/Me and KERNEL32.DLL
              debug_break_ea = get_dll_export(dlls, di.base, "DebugBreak");
          }
          if ( attach_status == as_none )
            expecting_debug_break = true;
        }
#endif
      }
      break;

    case UNLOAD_DLL_DEBUG_EVENT:
      event->eid = LIBRARY_UNLOAD;
      {
        area_t area(EA_T(DebugEvent.u.UnloadDll.lpBaseOfDll),
          EA_T(DebugEvent.u.UnloadDll.lpBaseOfDll)+MEMORY_PAGE_SIZE); // we assume DLL image is at least a PAGE size
        const char *name = get_range_name(dlls, &area);
        if ( name != NULL )
          qstrncpy(event->info, name, sizeof(event->info));
        else
          event->info[0] = '\0';
        // close the associated DLL handle
        images_t::iterator p = dlls.find(EA_T(DebugEvent.u.UnloadDll.lpBaseOfDll));
        if ( p != dlls.end() )
        {
          myCloseHandle(p->second.dll_info.hFile);
          // Remove it from the list of dlls to import
          // (in the case it was never imported)
          dlls_to_import.erase(p->first);
          dlls.erase(p);
        }
        else
        {
          debdeb("Could not find dll to unload (base=%a)\n", EA_T(DebugEvent.u.UnloadDll.lpBaseOfDll));
        }
      }
      break;

    case OUTPUT_DEBUG_STRING_EVENT:
      event->eid = INFORMATION;
      get_debug_string(DebugEvent,
        event->info,
        sizeof(event->info));
      break;

    case RIP_EVENT:
      debdeb("RIP_EVENT (system debugging error)");
      break;

    default:
      debdeb("UNKNOWN_EVENT %d", DebugEvent.dwDebugEventCode);
      event->handled = false;      // don't handle it
      break;
  }

  if ( gdecode > GDE_NO_EVENT && attach_status == as_breakpoint && event->eid == EXCEPTION )
  { // exception while attaching. apparently things went wrong
    // pretend that we attached successfully
    events.enqueue(*event, IN_BACK);
    create_attach_event(event, true);
    attach_status = as_none;
  }
  return gdecode;
}

//--------------------------------------------------------------------------
gdecode_t idaapi win32_debmod_t::dbg_get_debug_event(debug_event_t *event, int timeout_ms)
{
  check_thread(false);
  gdecode_t gdecode = get_debug_event(event, timeout_ms);
  if ( gdecode >= GDE_ONE_EVENT )
  {
    last_event = *event;
    in_event = &last_event;
  }
  return gdecode;
}


//--------------------------------------------------------------------------
bool win32_debmod_t::get_debug_string(const DEBUG_EVENT &ev, char *buf, size_t bufsize)
{
  buf[0] = '\0';
  size_t nullsize = ev.u.DebugString.fUnicode ? sizeof(wchar_t) : 1;
  size_t msize = qmin(ev.u.DebugString.nDebugStringLength, bufsize-nullsize);
  ea_t ea = EA_T(ev.u.DebugString.lpDebugStringData);
  ssize_t rsize = _read_memory(ea, buf, msize);
  if ( rsize == msize )
  {
    buf[rsize] = '\0';
    if ( ev.u.DebugString.fUnicode )
    {
      *(wchar_t*)(buf + rsize) = 0;
      unicode_to_ansi(buf, bufsize, (LPCWSTR)buf);
    }
    return true;
  }
  return false;
}

//--------------------------------------------------------------------------
void win32_debmod_t::cleanup()
{
  myCloseHandle(redirin_handle);
  myCloseHandle(redirout_handle);
  myCloseHandle(thread_handle);
  myCloseHandle(process_handle);
  myCloseHandle(cpdi.hFile);
  myCloseHandle(cpdi.hProcess);
  myCloseHandle(cpdi.hThread);

  // Close handles of remaining DLLs
  for ( images_t::iterator p=dlls.begin(); p != dlls.end(); ++p )
    myCloseHandle(p->second.dll_info.hFile);

  pid            = (DWORD)  -1;
  debug_break_ea = qgetenv("IDA_SYSTEMBREAKPOINT") ? BADADDR : 0;
  in_event       = NULL;
  memset(&cpdi, 0, sizeof(cpdi));
  cpdi.hFile    = INVALID_HANDLE_VALUE;
  cpdi.hProcess = INVALID_HANDLE_VALUE;
  cpdi.hThread  = INVALID_HANDLE_VALUE;
  attach_status = as_none;
  attach_evid = INVALID_HANDLE_VALUE;

  old_areas.clear();
  threads.clear();
  thread_bpts.clear();
  bpts.clear();
  curproc.clear();
  dlls.clear();
  dlls_to_import.clear();
  images.clear();
  thread_areas.clear();
  class_areas.clear();
  inherited::cleanup();
}

//--------------------------------------------------------------------------
void win32_debmod_t::get_filename_for(
  ea_t image_name_ea,
  bool use_unicode,
  ea_t image_base,
  char *buf,
  size_t bufsize,
  HANDLE handle,
  const char *path)
{
  buf[0] = '\0';

  // first: we try to get DLL path+name from debugged process.
  //   remark: depending on the OS, NTDLL.DLL can return an empty string or only the DLL name!
  if ( image_name_ea != 0 )
    get_filename_from_process(image_name_ea, use_unicode, buf, bufsize);

#ifndef UNDER_CE
  if ( buf[0] == '\0' && _GetModuleFileNameEx != NULL )
  {
    TCHAR tbuf[MAXSTR];
    HMODULE hmod = (HMODULE)(size_t)image_base;
    if ( _GetModuleFileNameEx(handle, hmod, tbuf, qnumber(tbuf)) )
      wcstr(buf, tbuf, bufsize);
  }
#endif

#if 0 // Commented out because the file can be mapped to the memory
  // for reading purposes. Vista generates LOAD_DLL event even in this case!
  // I saw it myself: the system was displaying the "open file" dialog box,
  // the current directory had a file named ar.exe. A LOAD_DLL event
  // with this file name and image address has been generated.
  // After that, the debugger tried to patch the Borland's activehook variable
  // and consequently the debugged application crashed (later).
  // second: we try to get DLL path+name using PSAPI.DLL if available.
  if ( buf[0] == '\0' || qbasename(buf) == buf )
    get_mapped_filename(handle, image_base, buf, bufsize);
#endif

  // third: we try to get DLL name by looking at the export name from
  //   the export directory in PE image in debugged process.
  if ( buf[0] == '\0' )
    get_pe_export_name_from_process(image_base, buf, bufsize);

  // if all these didn't work, then use toolhelp to get the module name
  // commented out: hangs under Windows ce
  /*
  if ( buf[0] == '\0' )
  {
  gmbb_info_t gi;
  gi.base    = image_base;
  gi.buf     = buf;
  gi.bufsize = bufsize;
  for_each_module(pid, get_module_by_base, &gi);
  }
  */

  // for dlls without path, try to find it
  find_full_path(buf, bufsize, path);

  // convert possible short path to long path
  qffblk64_t fb;
  if ( qfindfirst64(buf, &fb, 0) == 0 )
  {
    char *fptr = qbasename(buf);
    qstrncpy(fptr, fb.ff_name, bufsize-(fptr-buf));
  }
}

//--------------------------------------------------------------------------
// 1-ok, 0-failed
int idaapi win32_debmod_t::dbg_detach_process()
{
  check_thread(false);
  if ( in_event != NULL )
    dbg_continue_after_event(in_event);
  BOOL ret = get_tool_help()->debug_detach_process(pid);
  if ( ret )
  {
    attach_status = as_detaching;
    exiting = true;
  }
  return ret;
}

//--------------------------------------------------------------------------
int idaapi win32_debmod_t::dbg_init(bool _debug_debugger)
{
  check_thread(true);
  debug_debugger = _debug_debugger;

  cleanup();
  cleanup_hwbpts();

  return g_code;
}

//--------------------------------------------------------------------------
image_info_t::image_info_t(win32_debmod_t *ses)
  : sess(ses), base(BADADDR), imagesize(0)
{
  memset(&dll_info, 0, sizeof(dll_info));
}

image_info_t::image_info_t(win32_debmod_t *ses, ea_t _base, const qstring &_name)
  : sess(ses), base(_base), name(_name)
{
  imagesize = sess->calc_imagesize(base);
  memset(&dll_info, 0, sizeof(dll_info));
}

image_info_t::image_info_t(win32_debmod_t *ses, ea_t _base, uval_t _imagesize, const qstring &_name)
  : sess(ses), base(_base), imagesize(_imagesize), name(_name)
{
  memset(&dll_info, 0, sizeof(dll_info));
}

image_info_t::image_info_t(win32_debmod_t *ses, const LOAD_DLL_DEBUG_INFO &i, const char *_name)
  : sess(ses), name(_name), dll_info(i)
{
  base = EA_T(i.lpBaseOfDll);
  imagesize = sess->calc_imagesize(base);
}

image_info_t::image_info_t(win32_debmod_t *ses, const module_info_t &m)
  : sess(ses), base(m.base), imagesize(m.size), name(m.name)
{
  memset(&dll_info, 0, sizeof(dll_info));
}

//--------------------------------------------------------------------------
// get (path+)name from debugged process
// lpFileName - pointer to pointer to the file name
// use_unicode - true if the filename is in unicode
bool win32_debmod_t::get_filename_from_process(
        ea_t name_ea,
        bool use_unicode,
        char *buf,
        size_t bufsize)
{
  buf[0] = '\0';
  if ( name_ea == 0 )
    return false;
#ifndef UNDER_CE
  LPVOID dll_addr;
  if ( _read_memory(name_ea, &dll_addr, sizeof(dll_addr)) != sizeof(dll_addr) )
    return false;
  if ( dll_addr == NULL )
    return false;
  name_ea = EA_T(dll_addr);
#endif
  if ( _read_memory(name_ea, buf, bufsize) != bufsize )
    return false;
  if ( use_unicode )
    unicode_to_ansi(buf, bufsize, (LPCWSTR)buf);
  return true;
}

//--------------------------------------------------------------------------
ea_t win32_debmod_t::get_region_info(
        page_bpts_t::iterator *pbpts,
        ea_t ea,
        memory_info_t *mi)
{
  // okay to keep static, they won't change between clients
  static DWORD_PTR totalVirtual = 0;
  static DWORD granularity = 0;

  if ( totalVirtual == 0 )
  {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    granularity = si.dwAllocationGranularity;
    totalVirtual = (DWORD_PTR)si.lpMaximumApplicationAddress;
  }

  void *addr = (void *)(size_t)ea;
  MEMORY_BASIC_INFORMATION meminfo;
  while ( !VirtualQueryEx(process_handle,    // handle of process
                          addr,              // address of region
                          &meminfo,          // address of information buffer
                          sizeof(meminfo)) ) // size of buffer
  {
    // On Windows CE VirtualQueryEx can fail when called with addr == 0,
    // so try to call it again with the next page (and end loop after 2d
    // iteration to prevent scanning of huge number of pages)
    // It's possible VirtualQueryEx fails on Windows CE not only for zero
    // address: perhaps we shouldn't limit the number of iterations and return
    // to using of a separate variable 'first' (as in win32_debmod.cpp#34)
    if ( ea != 0 || ea >= totalVirtual )
      return BADADDR;
    // try to find next valid page
    ea += granularity;
    addr = (void *)(size_t)ea;
  }

  ea_t startea = EA_T(meminfo.BaseAddress);
  ea_t endea = startea + meminfo.RegionSize;
  if ( endea < startea )
    endea = BADADDR;

  debdeb("VirtualQueryEx(%a): base = %a, end = %a, protect=0x%x, allocprotect=0x%x, state=0x%x\n", ea, startea, endea, meminfo.Protect, meminfo.AllocationProtect, meminfo.State);

  // hide the page bpts in this memory region from ida
  uint32 prot = meminfo.Protect;
  if ( mask_page_bpts(pbpts, startea, endea, &prot) )
  {
    debdeb("   masked protect=0x%x\n", prot);
    meminfo.Protect = prot;
  }

#ifndef UNDER_CE
  if ( (meminfo.State & (MEM_FREE|MEM_RESERVE)) != 0 // if the area isn't interesting for/accessible by IDA
    || (meminfo.Protect & PAGE_NOACCESS) != 0 )
  { // we simply return an invalid area, and a pointer to the next (eventual) area
    mi->startEA = BADADDR;
    mi->endEA   = BADADDR;
    return endea;
  }
#endif

  mi->startEA = startea;
  mi->endEA   = endea;
#ifdef __EA64__
  // we may be running a 32bit process in wow64 with idaq64
  mi->bitness = check_wow64_process(process_handle) ? 1 : 2;
#else
  mi->bitness = 1; // 32bit
#endif

  // convert Windows protection modes to IDA protection modes
  mi->perm = win_prot_to_ida_perm(meminfo.Protect);

  // try to associate a segment name to the memory area
  const char *ptr;
  if ( (ptr=get_range_name(curproc,      mi)) != NULL   // first try with the current process
    || (ptr=get_range_name(dlls,         mi)) != NULL   // then try in DLLs
    || (ptr=get_range_name(images,       mi)) != NULL   // then try in previous images areas
    || (ptr=get_range_name(thread_areas, mi)) != NULL ) // and finally in thread areas
  {
    // return the filename without the file path
    mi->name = qbasename(ptr);
  }
  else
  {
    char buf[MAXSTR];
    // if we found nothing, we suppose the segment is a PE file header, and we try to locate a name in it
    if ( get_pe_export_name_from_process(mi->startEA, buf, sizeof(buf)) )
    {                   // we insert it in the image areas list
      image_info_t ii(this, mi->startEA, buf);
      images.insert(std::make_pair(ii.base, ii));
      mi->name = buf;
    }
  }

  // try to associate a segment class name to the memory area
  mi->sclass = get_range_name(class_areas, mi);
  return endea;
}

//--------------------------------------------------------------------------
// 1-ok, 0-failed
int idaapi win32_debmod_t::dbg_attach_process(pid_t _pid, int event_id)
{
  check_thread(false);
  if ( !DebugActiveProcess(_pid) )
  {
    deberr("DebugActiveProcess %08lX", _pid);
    return false;
  }
  debapp_attrs.addrsize = get_process_addrsize(_pid);
  attach_status = as_attaching;
  attach_evid = (HANDLE)(INT_PTR)(event_id);
  exiting = false;
  return 1;
}

//--------------------------------------------------------------------------
int idaapi win32_debmod_t::dbg_start_process(
        const char *path,
        const char *args,
        const char *startdir,
        int flags,
        const char *input_path,
        uint32 input_file_crc32)
{
  check_thread(false);
  // input file specified in the database does not exist
  if ( input_path[0] != '\0' && !qfileexist(input_path) )
  {
    dwarning("AUTOHIDE NONE\nInput file is missing: %s", input_path);
    return -2;
  }

  input_file_path = input_path;
  is_dll = (flags & DBG_PROC_IS_DLL) != 0;

  if ( !qfileexist(path) )
  {
    dwarning("AUTOHIDE NONE\nCan not find host file '%s'", path);
    return -1;
  }

  int mismatch = 0;
  if ( !check_input_file_crc32(input_file_crc32) )
    mismatch = CRC32_MISMATCH;

  exiting = false;

  // Build a full command line
#ifndef UNDER_CE
  qstring args_buffer; // this vector must survive until create_process()
  if ( args != NULL && args[0] != '\0' )
  {
    args_buffer += '"';
    args_buffer += path;
    args_buffer += '"';
    args_buffer += ' ';
    args_buffer += args;
    args = args_buffer.c_str();
  }
#endif

  PROCESS_INFORMATION ProcessInformation;
  bool is_gui = (flags & DBG_PROC_IS_GUI) != 0;
  if ( !create_process(path, args, startdir, is_gui, &ProcessInformation) )
    return 0;

  pid            = ProcessInformation.dwProcessId;
  process_handle = ProcessInformation.hProcess;
  thread_handle  = ProcessInformation.hThread;
  process_path   = path;

  debapp_attrs.addrsize = get_process_addrsize(pid);

  return 1 | mismatch;
}

//--------------------------------------------------------------------------
bool win32_debmod_t::myCloseHandle(HANDLE &h)
{
  bool ok = true;
  if ( h != INVALID_HANDLE_VALUE && h != NULL )
  {
    DWORD code;
    __try
    {
      ok = CloseHandle(h) != 0;
      if ( !ok )
        deberr("CloseHandle(%08X)", h);
    }
    __except ( code=GetExceptionCode() )
    {
      debdeb("CloseHandle(%08X) exception code %08X\n", h, code);
      ok = false;
    }
    h = INVALID_HANDLE_VALUE;
  }
  return ok;
}

//--------------------------------------------------------------------------
void win32_debmod_t::install_callgate_workaround(thread_info_t *ti, const debug_event_t *event)
{
#ifdef UNDER_CE
  qnotused(ti);
  qnotused(event);
#else
  // add a breakpoint after the call statement
  ea_t bpt = event->ea + 7;
  ti->callgate_ea = bpt;
  if ( !set_thread_bpt(*ti, bpt) )
    INTERR(637); // how can it be?
#endif
}

//--------------------------------------------------------------------------
// we do not use 'firsttime' argument anymore. we could use it to distinguish
// the first chance and the second chance but it is more logical to
// behave consistently.
gdecode_t win32_debmod_t::handle_exception(
        debug_event_t *event,
        const EXCEPTION_RECORD &er,
        bool was_thread_bpt,
        bool /*firsttime*/)
{
  int code = er.ExceptionCode;
  const exception_info_t *ei = find_exception(code);

  event->eid          = EXCEPTION;
  event->ea           = EA_T(er.ExceptionAddress);
  event->exc.code     = code;
  event->exc.can_cont = (er.ExceptionFlags == 0);
  event->exc.ea       = BADADDR;
  event->handled      = false;

  if ( exiting && event->eid == EXCEPTION && ei == NULL )
  {
    event->eid = PROCESS_EXIT;
    event->exit_code = -1;
    return GDE_ONE_EVENT;
  }

  bool suspend = true;

  if ( ei != NULL )
  {
    event->handled = ei->handle();
    // if the user asked to suspend the process, do not resume
    if ( !was_thread_bpt )
      suspend = ei->break_on();
    event->exc.info[0] = '\0';
    int elc_flags = 0;
    switch ( uint32(code) )
    {
      case EXCEPTION_BREAKPOINT:
        if ( was_thread_bpt )
        {
          thread_info_t *ti = threads.get(event->tid);
          QASSERT(638, ti != NULL);

          // is installed the workaround for the 'freely running after syscall' problem?
          if ( ti->callgate_ea == event->ea )
          {
            // uninstall the temporary breakpoint
            ti->callgate_ea = BADADDR;
            del_thread_bpt(*ti, event->ea);

            event->eid = STEP;
          }
          else
          {
            event->eid = PROCESS_SUSPEND;
          }
          break;
        }
        if ( attach_status == as_breakpoint ) // the process was successfully suspended after an attachement
        {
          create_attach_event(event, true);
          break;
        }
        // Win7 RC has a hardcoded bpt in LdrpDoDebuggerBreak() instead of a call to DbgBreakPoint()
        // Since we can not calculate its address, we relax the address verification.
        if ( event->ea > 0x70000000 /*event->ea == debug_break_ea*/ // reached the kernel breakpoint?
          && expecting_debug_break
          && get_kernel_bpt_ea(event->ea) == BADADDR ) // not user-defined bpt
        {
          expecting_debug_break = false;
          debdeb("%a: resuming after DbgBreakPoint()\n", event->ea);
          event->handled = true;
          dbg_continue_after_event(event);
          return GDE_NO_EVENT;
        }
        // is this a breakpoint set by ida?
        {
          ea_t kea = get_kernel_bpt_ea(event->ea);
          if ( kea != BADADDR )
          {
            event->eid = BREAKPOINT;
            event->bpt.hea = BADADDR; // no referenced address (only for hardware breakpoint)
            event->bpt.kea = kea == event->ea ? BADADDR : kea;
            event->handled = true;
          }
        }
        break;
      case EXCEPTION_SINGLE_STEP:
        {
          thread_info_t *ti = threads.get(event->tid);
          bool is_stepping = ti != NULL && ti->is_tracing();
#ifndef UNDER_CE
          // if this happened because of a hardware breakpoint
          // find out which one caused it
          if ( !check_for_hwbpt(event, is_stepping) )
#endif
          {
            // if we have not asked for single step, do not convert it to STEP
            if ( is_stepping )
            {
              event->eid     = STEP;   // Single-step breakpoint
              event->handled = true;
              ti->clr_tracing();
              break;
            }
          }
        }
        break;
      case EXCEPTION_ACCESS_VIOLATION:
        {
#ifdef UNDER_CE
          if ( check_for_hwbpt(event) )
            break;
#endif
          ea_t exc_ea = EA_T(er.ExceptionInformation[1]); // virtual address of the inaccessible data.
          event->exc.ea = exc_ea;
#ifndef UNDER_CE
          // is this a page bpt?
          page_bpts_t::iterator p = find_page_bpt(exc_ea);
          if ( p == page_bpts.end() )
          {
            exc_ea = event->ea;
            p = find_page_bpt(exc_ea);
          }
          if ( p != page_bpts.end() )
          {
            // since on access violation the system does not update anything
            // there is no need to reset eip when handling lowcnd below.
            elc_flags |= ELC_KEEP_EIP;
            ea_t exc_eip = EA_T(er.ExceptionAddress);
            if ( !should_fire_page_bpt(p, exc_ea, er.ExceptionInformation[0], exc_eip, dep_policy) )
            { // Silently step over the page breakpoint
              thread_info_t *ti = threads.get(event->tid);
              if ( ti != NULL && ti->is_tracing() )
                elc_flags |= ELC_KEEP_SUSP;
              lowcnd_t lc;
              const pagebpt_data_t &bpt = p->second;
              lc.ea = bpt.ea;
              lc.type = bpt.type;
              lc.size = bpt.user_len;
              if ( !handling_lowcnds.has(bpt.ea)
                && handle_lowcnd(&lc, event, elc_flags) )
              {
                if ( (elc_flags & ELC_KEEP_SUSP) != 0 )
                { // if we were tracing, report a STEP event
                  event->eid     = STEP;
                  event->handled = true;
                  ti->clr_tracing();
                  return GDE_ONE_EVENT;
                }
                return GDE_NO_EVENT;
              }
              // failed to step over, return the exception
            }
            else
            {
              event->eid = BREAKPOINT;
              event->bpt.hea = p->second.ea;
              event->bpt.kea = BADADDR;
              event->handled = true;
              break;
            }
          }
#endif
          qsnprintf(event->exc.info,
                    sizeof(event->exc.info),
                  ei->desc.c_str(), event->ea,
                  event->exc.ea,
                  er.ExceptionInformation[0] == EXCEPTION_EXECUTE_FAULT ? "executed"
                  : er.ExceptionInformation[0] == EXCEPTION_WRITE_FAULT ? "written" : "read");
        }
        break;
#define EXCEPTION_BCC_FATAL  0xEEFFACE
#define EXCEPTION_BCC_NORMAL 0xEEDFAE6
      case EXCEPTION_BCC_FATAL:
      case EXCEPTION_BCC_NORMAL:
        if ( er.NumberParameters == 5
          && er.ExceptionInformation[0] == 2 // these numbers are highly hypothetic
          && er.ExceptionInformation[1] == 3 )
        {
          EXCEPTION_RECORD r2;
          if ( dbg_read_memory(er.ExceptionInformation[3], &r2, sizeof(r2)) == sizeof(r2) )
            return handle_exception(event, r2, false, false);
        }
        break;
    }
    if ( evaluate_and_handle_lowcnd(event, elc_flags) )
      return GDE_NO_EVENT;
    if ( event->eid == EXCEPTION && event->exc.info[0] == '\0' )
      qsnprintf(event->exc.info,
                sizeof(event->exc.info),
                ei->desc.c_str(), event->ea,
                ea_t(er.ExceptionInformation[0]),
                ea_t(er.ExceptionInformation[1]));
  }
  else
  {
    qsnprintf(event->exc.info, sizeof(event->exc.info),
      "unknown exception code %X", code);
  }
  if ( event->eid == EXCEPTION && !suspend )
  {
    log_exception(event, ei);
    // if a single step was scheduled by the user
    thread_info_t *ti = threads.get(event->tid);
    if ( ti != NULL && ti->is_tracing() )
    {
      clear_tbit(*ti);
      if ( event->handled )
      {
        // since we mask the exception, we generate a STEP event
        event->eid = STEP;
        return GDE_ONE_EVENT; // got an event
      }
    }
    dbg_continue_after_event(event);
    return GDE_NO_EVENT;
  }
  return GDE_ONE_EVENT;
}

//--------------------------------------------------------------------------
bool win32_debmod_t::check_for_hwbpt(debug_event_t *event, bool is_stepping)
{
  ea_t ea = is_hwbpt_triggered(event->tid, is_stepping);
  if ( ea != BADADDR )
  {
    event->eid     = BREAKPOINT;
    event->handled = true;
    event->bpt.hea = ea;
    event->bpt.kea = BADADDR;
    return true;
  }
  return false;
}

//--------------------------------------------------------------------------
void win32_debmod_t::create_attach_event(debug_event_t *event, bool attached)
{
  event->eid     = PROCESS_ATTACH;
  event->handled = true;
  if ( attached )
    attach_status = as_attached;
  else
    attach_status = as_attaching;
  if ( attach_evid != INVALID_HANDLE_VALUE )
  {
    SetEvent(attach_evid);
    attach_evid = INVALID_HANDLE_VALUE;
  }
  get_debugged_module_info(&event->modinfo);
}

//--------------------------------------------------------------------------
void win32_debmod_t::create_start_event(debug_event_t *event)
{
  event->eid = PROCESS_START;
  process_snapshot_t psnap(get_tool_help());
  PROCESSENTRY32 pe32;
  for ( bool ok = psnap.first(TH32CS_SNAPNOHEAPS, &pe32); ok; ok = psnap.next(&pe32) )
  {
    if ( pe32.th32ProcessID == event->pid )
    {
      char exefile[QMAXPATH];
      wcstr(exefile, pe32.szExeFile, sizeof(exefile));
      if ( process_path.empty() || qisabspath(exefile) )
        process_path = exefile;
      break;
    }
  }
  qstrncpy(event->modinfo.name, process_path.c_str(), sizeof(event->modinfo.name));

  ea_t base = EA_T(cpdi.lpBaseOfImage);
  event->modinfo.base      = base;
  event->modinfo.size      = calc_imagesize(base);
  event->modinfo.rebase_to = BADADDR; // this must be determined locally - see common_local.cpp
}

//--------------------------------------------------------------------------
ea_t win32_debmod_t::get_kernel_bpt_ea(ea_t ea)
{
  if ( bpts.find(ea) != bpts.end() )
    return ea;
#ifdef UNDER_CE
  // we are forced to enumerate all addresses and check each manually
  if ( ea < 0x42000000 )
  {
    ea  &= ~0xFE000000;
    for ( debmodbpt_map_t::iterator p = bpts.begin(); p != bpts.end(); ++p )
    {
      ea_t ea2 = p->first & ~0xFE000000;
      if ( ea == ea2 )
        return p->first;
    }
  }
#endif
  return BADADDR;
}


ssize_t idaapi win32_debmod_t::dbg_write_memory(ea_t ea, const void *buffer, size_t size)
{
  check_thread(false);
  return _write_memory(ea, buffer, size, true);
}

//--------------------------------------------------------------------------
// 1-ok, 0-failed
int idaapi win32_debmod_t::dbg_thread_get_sreg_base(thid_t tid, int sreg_value, ea_t *pea)
{
  check_thread(false);
  NODISTURB_ASSERT(in_event != NULL);
#ifdef __ARM__
  return 0;
#else
  HANDLE h = get_thread_handle(tid);
  if ( h == INVALID_HANDLE_VALUE )
    return 0;

  LDT_ENTRY se;
  if( !GetThreadSelectorEntry(h, sreg_value, &se) )
  {
    if ( GetLastError() == ERROR_NOT_SUPPORTED )
    {
      *pea = 0;
      return 1;
    }
    deberr("GetThreadSelectorEntry");
    return 0;
  }

  *pea = (se.HighWord.Bytes.BaseHi << 24)  |
    (se.HighWord.Bytes.BaseMid << 16) |
    se.BaseLow;
  return 1;
#endif
}

//--------------------------------------------------------------------------
#ifdef __X64__
#define FloatSave FltSave       // FIXME: use XMM save area!
#define RegisterArea FloatRegisters
#define FPUREG_ENTRY_SIZE  16
#define XMMREG_PTR   ((uchar *)&ctx.Xmm0)
#define XMMREG_MXCSR (ctx.FltSave.MxCsr)
#else
#define XMMREG_PTR ((uchar *)&ctx.ExtendedRegisters[0xA0])
#define XMMREG_MXCSR (*(uint32 *)&ctx.ExtendedRegisters[0x18])
#define FPUREG_ENTRY_SIZE  10
#endif

#define FPUREG_PTR        ((uchar *)ctx.FloatSave.RegisterArea)

// 1-ok, 0-failed
int idaapi win32_debmod_t::dbg_write_register(
  thid_t tid,
  int reg_idx,
  const regval_t *value)
{
  check_thread(false);
  if ( value == NULL )
    return 0;

  NODISTURB_ASSERT(in_event != NULL);

  int regclass = get_reg_class(reg_idx);
  if ( regclass == 0 )
    return 0;

  thread_info_t *ti = threads.get(tid);
  if ( ti == NULL || !ti->read_context(regclass) )
    return 0;
  CONTEXT &ctx = ti->ctx;

  // Patch one field
  patch_context_struct(ctx, reg_idx, value);

  bool ok = SetThreadContext(ti->hThread, &ctx) != 0;
  if ( !ok )
    deberr("SetThreadContext");
  debdeb("write_register: %d\n", ok);
  return ok;
}

//--------------------------------------------------------------------------
bool idaapi win32_debmod_t::write_registers(
  thid_t thread_id,
  int start,
  int count,
  const regval_t *values,
  const int *indices)
{
  thread_info_t *ti = threads.get(thread_id);
  if ( ti == NULL )
    return false;
  if ( !ti->read_context(RC_ALL) )
    return false;

  for ( int i=0; i < count; i++, values++ )
  {
    int idx = indices != NULL ? indices[i] : start+i;
    patch_context_struct(ti->ctx, idx, values);
  }

  bool ok = SetThreadContext(ti->hThread, &ti->ctx) == TRUE;
  debdeb("write_registers: %d\n", ok);
  return ok;
}

//--------------------------------------------------------------------------
// 1-ok, 0-failed
int idaapi win32_debmod_t::dbg_read_registers(thid_t tid, int clsmask, regval_t *values)
{
  check_thread(false);
  if ( values == NULL )
    return 0;

  NODISTURB_ASSERT(in_event != NULL);

  thread_info_t *ti = threads.get(tid);
  if ( ti == NULL || !ti->read_context(clsmask) )
    return 0;

  CONTEXT &ctx = ti->ctx;
#ifdef __ARM__
  if ( (clsmask & ARM_RC_GENERAL) != 0 )
  {
    values[R_R0 ].ival    = ctx.R0;
    values[R_R1 ].ival    = ctx.R1;
    values[R_R2 ].ival    = ctx.R2;
    values[R_R3 ].ival    = ctx.R3;
    values[R_R4 ].ival    = ctx.R4;
    values[R_R5 ].ival    = ctx.R5;
    values[R_R6 ].ival    = ctx.R6;
    values[R_R7 ].ival    = ctx.R7;
    values[R_R8 ].ival    = ctx.R8;
    values[R_R9 ].ival    = ctx.R9;
    values[R_R10].ival    = ctx.R10;
    values[R_R11].ival    = ctx.R11;
    values[R_R12].ival    = ctx.R12;
    values[R_SP ].ival    = ctx.Sp;
    values[R_LR ].ival    = ctx.Lr;
    values[R_PC ].ival    = ctx.Pc;
    values[R_PSR].ival    = ctx.Psr;
  }
#else
  if ( (clsmask & X86_RC_SEGMENTS) != 0 )
  {
    values[R_CS].ival     = ctx.SegCs;
    values[R_DS].ival     = ctx.SegDs;
    values[R_ES].ival     = ctx.SegEs;
    values[R_FS].ival     = ctx.SegFs;
    values[R_GS].ival     = ctx.SegGs;
    values[R_SS].ival     = ctx.SegSs;
  }
  if ( (clsmask & X86_RC_GENERAL) != 0 )
  {
#ifdef __X64__
    values[R_EAX].ival    = ctx.Rax;
    values[R_EBX].ival    = ctx.Rbx;
    values[R_ECX].ival    = ctx.Rcx;
    values[R_EDX].ival    = ctx.Rdx;
    values[R_ESI].ival    = ctx.Rsi;
    values[R_EDI].ival    = ctx.Rdi;
    values[R_EBP].ival    = ctx.Rbp;
    values[R_ESP].ival    = ctx.Rsp;
    values[R_EIP].ival    = ctx.Rip;
    values[R64_R8 ].ival  = ctx.R8;
    values[R64_R9 ].ival  = ctx.R9;
    values[R64_R10].ival  = ctx.R10;
    values[R64_R11].ival  = ctx.R11;
    values[R64_R12].ival  = ctx.R12;
    values[R64_R13].ival  = ctx.R13;
    values[R64_R14].ival  = ctx.R14;
    values[R64_R15].ival  = ctx.R15;
#else
    values[R_EAX].ival    = ctx.Eax;
    values[R_EBX].ival    = ctx.Ebx;
    values[R_ECX].ival    = ctx.Ecx;
    values[R_EDX].ival    = ctx.Edx;
    values[R_ESI].ival    = ctx.Esi;
    values[R_EDI].ival    = ctx.Edi;
    values[R_EBP].ival    = ctx.Ebp;
    values[R_ESP].ival    = ctx.Esp;
    values[R_EIP].ival    = ctx.Eip;
#endif
    values[R_EFLAGS].ival = ctx.EFlags;
  }
  if ( (clsmask & (X86_RC_FPU|X86_RC_MMX)) != 0 )
  {
    if ( (clsmask & X86_RC_FPU) != 0 )
    {
      values[R_CTRL].ival = ctx.FloatSave.ControlWord;
      values[R_STAT].ival = ctx.FloatSave.StatusWord;
      values[R_TAGS].ival = ctx.FloatSave.TagWord;
    }
    read_fpu_registers(values, clsmask, FPUREG_PTR, FPUREG_ENTRY_SIZE);
  }
  if ( (clsmask & X86_RC_XMM) != 0 )
  {
    const uchar *xptr = XMMREG_PTR;
    for ( int i=R_XMM0; i < R_MXCSR; i++,xptr+=16 )
      values[i].set_bytes(xptr, 16);
    values[R_MXCSR].ival = XMMREG_MXCSR;
  }
  //? others registers
#endif

  return 1;
}

//--------------------------------------------------------------------------
// 1-ok, 0-failed
int idaapi win32_debmod_t::dbg_set_resume_mode(thid_t tid, resume_mode_t resmod)
{
  if ( resmod != RESMOD_INTO )
    return 0; // not supported

  check_thread(false);
  NODISTURB_ASSERT(in_event != NULL);
#ifdef __ARM__
  return 0;
#else
  thread_info_t *ti = threads.get(tid);
  if ( ti == NULL || !ti->read_context(RC_GENERAL) )
    return 0;

  int ok = 1;
  CONTEXT &ctx = ti->ctx;
  if ( (ctx.EFlags & EFLAGS_TRAP_FLAG) == 0 )
  {
    QASSERT(30117, (ctx.ContextFlags & CONTEXT_CONTROL) != 0);
    ctx.EFlags |= EFLAGS_TRAP_FLAG;
    int saved = ctx.ContextFlags;
    ctx.ContextFlags = CONTEXT_CONTROL;
    ok = SetThreadContext(ti->hThread, &ctx);
    ctx.ContextFlags = saved;
    if ( ok )
      ti->set_tracing();
    else
      deberr("%d: (set_step) SetThreadContext failed", tid);
  }
  return ok;
#endif
}

//--------------------------------------------------------------------------
bool win32_debmod_t::clear_tbit(thread_info_t &ti)
{
  NODISTURB_ASSERT(in_event != NULL);
#ifdef __ARM__
  return false;
#else
  bool ok = false;
  if ( ti.read_context(RC_GENERAL) )
  {
    CONTEXT &ctx = ti.ctx;
    if ( (ctx.EFlags & EFLAGS_TRAP_FLAG) != 0 )
    {
      ctx.EFlags &= ~EFLAGS_TRAP_FLAG;
      int saved = ctx.ContextFlags;
      ctx.ContextFlags = CONTEXT_CONTROL;
      ok = SetThreadContext(ti.hThread, &ctx) != 0;
      ctx.ContextFlags = saved;
      if ( ok )
        ti.clr_tracing();
      else
        deberr("%d: (clear_tbit) SetThreadContext failed", ti.tid);
    }
  }
  return ok;
#endif
}

//--------------------------------------------------------------------------
// invalidate registers of all threads
void win32_debmod_t::invalidate_all_contexts(void)
{
  for ( threads_t::iterator p=threads.begin(); p != threads.end(); ++p )
      p->second.invalidate_context();
}

//--------------------------------------------------------------------------
// 1-ok, 0-failed
int idaapi win32_debmod_t::dbg_continue_after_event(const debug_event_t *event)
{
  check_thread(false);
  NODISTURB_ASSERT(in_event != NULL || exiting);

  if ( event == NULL )
    return false;

  if ( events.empty() )
  {
    bool done = false;
#ifdef UNDER_CE
    // Special state when we suspended due to no debug event
    // In this case we resume all the threads we previously
    // suspended in order to create a "synthesized" suspended state
    if ( event->eid == PROCESS_SUSPEND && fake_suspend_event )
    {
      fake_suspend_event = false;
      resume_all_threads(true);
      done = true;
    }
    // under WinCE PROCESS_ATTACH is a fake event
    else if ( event->eid == PROCESS_ATTACH )
    {
      done = true;
    }
#endif
    if ( !done )
    {
      // check if we need to install the workaround for single stepping over callgates
      thread_info_t *ti = threads.get(event->tid);
      if ( ti != NULL && ti->is_tracing() )
      {
        if ( check_for_call_large(event, process_handle) )
          install_callgate_workaround(ti, event);
      }

      int flag = event->handled ? DBG_CONTINUE : DBG_EXCEPTION_NOT_HANDLED;
      if ( !ContinueDebugEvent(event->pid, event->tid, flag) )
      {
        deberr("ContinueDebugEvent");
        return false;
      }
      debdeb("ContinueDebugEvent: handled=%s\n", event->handled ? "yes" : "no");
      if ( event->eid == PROCESS_EXIT )
      {
        // from WaitForDebugEvent help page:
        //  If the system previously reported an EXIT_PROCESS_DEBUG_EVENT debugging event,
        //  the system closes the handles to the process and thread when the debugger calls the ContinueDebugEvent function.
        // => we don't close these handles to avoid error messages
        cpdi.hProcess = INVALID_HANDLE_VALUE;
        cpdi.hThread  = INVALID_HANDLE_VALUE;
        cleanup();
      }
    }
    invalidate_all_contexts();
  }
  in_event = NULL;
  return true;
}

//--------------------------------------------------------------------------
// 1-ok, 0-failed
int idaapi win32_debmod_t::dbg_exit_process(void)
{
  check_thread(false);
  // WindowsCE sometimes reports failure but terminates the application.
  // We ignore the return value.
  bool check_termination_code = prepare_to_stop_process(in_event, threads);
  bool terminated = TerminateProcess(process_handle, -1) != 0;
  if ( !terminated && check_termination_code )
  {
    deberr("TerminateProcess");
    return false;
  }
  exiting = true;

  if ( in_event != NULL && !dbg_continue_after_event(in_event) )
  {
    deberr("continue_after_event");
    return 0;
  }
  return 1;
}


//--------------------------------------------------------------------------
void win32_debmod_t::show_exception_record(const EXCEPTION_RECORD &er, int level)
{
  char name[MAXSTR];
  get_exception_name(er.ExceptionCode, name, sizeof(name));
  if ( level > 0 )
    dmsg("%*c", level, ' ');
  dmsg("%s: fl=%X adr=%a #prm=%d\n",
    name,
    er.ExceptionFlags,
    EA_T(er.ExceptionAddress),
    er.NumberParameters);
  if ( er.NumberParameters > 0 )
  {
    dmsg("%*c", level+2, ' ');
    int n = qmin(er.NumberParameters, EXCEPTION_MAXIMUM_PARAMETERS);
    for ( int i=0; i < n; i++ )
      dmsg("%s0x%a", i == 0 ? "" : " ", ea_t(er.ExceptionInformation[i]));
    dmsg("\n");
  }
  if ( er.ExceptionRecord != NULL )
    show_exception_record(*er.ExceptionRecord, level+2);
}

//--------------------------------------------------------------------------
void win32_debmod_t::show_debug_event(
                      const DEBUG_EVENT &ev,
                      HANDLE handle,
                      const char *path)
{
  if ( !debug_debugger )
    return;
  dmsg("[%u %d] ", ev.dwProcessId, ev.dwThreadId);
  switch( ev.dwDebugEventCode )
  {
  case EXCEPTION_DEBUG_EVENT:
    {
      const EXCEPTION_RECORD &er = ev.u.Exception.ExceptionRecord;
      dmsg("EXCEPTION: ea=%a first: %d ",
        EA_T(er.ExceptionAddress), ev.u.Exception.dwFirstChance);
      show_exception_record(er);
    }
    break;

  case CREATE_THREAD_DEBUG_EVENT:
    dmsg("CREATE_THREAD: hThread=%X LocalBase=%a Entry=%a\n",
      ev.u.CreateThread.hThread,
      EA_T(ev.u.CreateThread.lpThreadLocalBase),
      ev.u.CreateThread.lpStartAddress);
    break;

  case CREATE_PROCESS_DEBUG_EVENT:
    {
      const CREATE_PROCESS_DEBUG_INFO &cpinf = ev.u.CreateProcessInfo;
      dmsg("CREATE_PROCESS: hFile=%X hProcess=%X hThread=%X "
        "base=%a\n dbgoff=%X dbgsiz=%X tlbase=%a start=%a\n",
        cpinf.hFile, cpinf.hProcess, cpinf.hThread, EA_T(cpinf.lpBaseOfImage),
        cpinf.dwDebugInfoFileOffset, cpinf.nDebugInfoSize, EA_T(cpinf.lpThreadLocalBase),
        EA_T(cpinf.lpStartAddress));
    }
    break;

  case EXIT_THREAD_DEBUG_EVENT:
    dmsg("EXIT_THREAD: code=%d\n", ev.u.ExitThread.dwExitCode);
    break;

  case EXIT_PROCESS_DEBUG_EVENT:
    dmsg("EXIT_PROCESS: code=%d\n", ev.u.ExitProcess.dwExitCode);
    break;

  case LOAD_DLL_DEBUG_EVENT:
    {
      char name[MAXSTR];
      const LOAD_DLL_DEBUG_INFO &di = ev.u.LoadDll;
      get_filename_for(EA_T(di.lpImageName),
        di.fUnicode != 0,
        EA_T(di.lpBaseOfDll),
        name,
        sizeof(name),
        handle,
        path);
      dmsg("LOAD_DLL: h=%X base=%a dbgoff=%X dbgsiz=%X name=%X '%s'\n",
        di.hFile, EA_T(di.lpBaseOfDll), di.dwDebugInfoFileOffset, di.nDebugInfoSize,
        di.lpImageName, name);
    }
    break;

  case UNLOAD_DLL_DEBUG_EVENT:
    dmsg("UNLOAD_DLL: base=%a\n", EA_T(ev.u.UnloadDll.lpBaseOfDll));
    break;

  case OUTPUT_DEBUG_STRING_EVENT:
    {
      char buf[MAXSTR];
      get_debug_string(ev, buf, sizeof(buf));
      dmsg("OUTPUT_DEBUG_STRING: str=\"%s\"\n", buf);
    }
    break;

  case RIP_EVENT:
    dmsg("RIP_EVENT (system debugging error)\n");
    break;

  default:
    dmsg("UNKNOWN_DEBUG_EVENT %d\n", ev.dwDebugEventCode);
    break;
  }
}

//--------------------------------------------------------------------------
void win32_debmod_t::patch_context_struct(
        CONTEXT &ctx,
        int reg_idx,
        const regval_t *value) const
{
#ifdef __ARM__
  switch ( reg_idx )
  {
    case R_R0:  ctx.R0  = value->ival; break;
    case R_R1:  ctx.R1  = value->ival; break;
    case R_R2:  ctx.R2  = value->ival; break;
    case R_R3:  ctx.R3  = value->ival; break;
    case R_R4:  ctx.R4  = value->ival; break;
    case R_R5:  ctx.R5  = value->ival; break;
    case R_R6:  ctx.R6  = value->ival; break;
    case R_R7:  ctx.R7  = value->ival; break;
    case R_R8:  ctx.R8  = value->ival; break;
    case R_R9:  ctx.R9  = value->ival; break;
    case R_R10: ctx.R10 = value->ival; break;
    case R_R11: ctx.R11 = value->ival; break;
    case R_R12: ctx.R12 = value->ival; break;
    case R_SP:  ctx.Sp  = value->ival; break;
    case R_LR:  ctx.Lr  = value->ival; break;
    case R_PC:  ctx.Pc  = value->ival; break;
    case R_PSR: ctx.Psr = value->ival; break;
  }
#else
  switch ( reg_idx )
  {
    case R_CS:     ctx.SegCs                 = WORD(value->ival); break;
    case R_DS:     ctx.SegDs                 = WORD(value->ival); break;
    case R_ES:     ctx.SegEs                 = WORD(value->ival); break;
    case R_FS:     ctx.SegFs                 = WORD(value->ival); break;
    case R_GS:     ctx.SegGs                 = WORD(value->ival); break;
    case R_SS:     ctx.SegSs                 = WORD(value->ival); break;
#ifdef __X64__
    case R_EAX:    ctx.Rax                   = value->ival; break;
    case R_EBX:    ctx.Rbx                   = value->ival; break;
    case R_ECX:    ctx.Rcx                   = value->ival; break;
    case R_EDX:    ctx.Rdx                   = value->ival; break;
    case R_ESI:    ctx.Rsi                   = value->ival; break;
    case R_EDI:    ctx.Rdi                   = value->ival; break;
    case R_EBP:    ctx.Rbp                   = value->ival; break;
    case R_ESP:    ctx.Rsp                   = value->ival; break;
    case R_EIP:    ctx.Rip                   = value->ival; break;
    case R64_R8:   ctx.R8                    = value->ival; break;
    case R64_R9 :  ctx.R9                    = value->ival; break;
    case R64_R10:  ctx.R10                   = value->ival; break;
    case R64_R11:  ctx.R11                   = value->ival; break;
    case R64_R12:  ctx.R12                   = value->ival; break;
    case R64_R13:  ctx.R13                   = value->ival; break;
    case R64_R14:  ctx.R14                   = value->ival; break;
    case R64_R15:  ctx.R15                   = value->ival; break;
#else
    case R_EAX:    ctx.Eax                   = (size_t)value->ival; break;
    case R_EBX:    ctx.Ebx                   = (size_t)value->ival; break;
    case R_ECX:    ctx.Ecx                   = (size_t)value->ival; break;
    case R_EDX:    ctx.Edx                   = (size_t)value->ival; break;
    case R_ESI:    ctx.Esi                   = (size_t)value->ival; break;
    case R_EDI:    ctx.Edi                   = (size_t)value->ival; break;
    case R_EBP:    ctx.Ebp                   = (size_t)value->ival; break;
    case R_ESP:    ctx.Esp                   = (size_t)value->ival; break;
    case R_EIP:    ctx.Eip                   = (size_t)value->ival; break;
#ifdef __EA64__
    case R64_R8:   break;
    case R64_R9 :  break;
    case R64_R10:  break;
    case R64_R11:  break;
    case R64_R12:  break;
    case R64_R13:  break;
    case R64_R14:  break;
    case R64_R15:  break;
#endif
#endif
    case R_TAGS:   ctx.FloatSave.TagWord     = WORD(value->ival); break;
    case R_EFLAGS: ctx.EFlags                = DWORD(value->ival); break;
    case R_CTRL:   ctx.FloatSave.ControlWord = WORD(value->ival); break;
    case R_STAT:   ctx.FloatSave.StatusWord  = WORD(value->ival); break;
    case R_MXCSR:  XMMREG_MXCSR              = value->ival; break;
    default:
      {
        void *xptr;
        int nbytes;
        int regclass = get_reg_class(reg_idx);
        if ( (regclass & X86_RC_XMM) != 0 )
        { // XMM registers
          xptr = XMMREG_PTR + (reg_idx - R_XMM0) * 16;
          nbytes = 16;
        }
        else if ( (regclass & X86_RC_FPU) != 0 )
        {
          xptr = FPUREG_PTR + (reg_idx-R_ST0) * FPUREG_ENTRY_SIZE;
          nbytes = 10;
        }
        else if ( (regclass & X86_RC_MMX) != 0 )
        {
          xptr = FPUREG_PTR + (reg_idx-R_MMX0) * FPUREG_ENTRY_SIZE;
          nbytes = 8;
        }
        else
        {
          INTERR(30118);
        }
        const void *vptr = value->get_data();
        size_t size = value->get_data_size();
        memcpy(xptr, vptr, qmin(size, nbytes));
      }
      break;
   }
#endif
}

//--------------------------------------------------------------------------
int win32_debmod_t::dbg_freeze_threads_except(thid_t tid)
{
  for ( threads_t::iterator p=threads.begin(); p != threads.end(); ++p )
    if ( p->first != tid )
      _sure_suspend_thread(p->second, true);
  return 1;
}

//--------------------------------------------------------------------------
int win32_debmod_t::dbg_thaw_threads_except(thid_t tid)
{
  for ( threads_t::iterator p=threads.begin(); p != threads.end(); ++p )
    if ( p->first != tid )
      _sure_resume_thread(p->second, true);
  return 1;
}

//--------------------------------------------------------------------------
// if we have to do something as soon as we noticed the connection
// broke, this is the correct place
bool idaapi win32_debmod_t::dbg_prepare_broken_connection(void)
{
  broken_connection = true;
  debmod_t *d = this;
  d->pid = this->pid;

  bool ret = false;
  if ( restore_broken_breakpoints() )
  {
    // create the required event for synchronization; we use it
    // to notify when the process was successfully detached
    broken_event_handle = CreateEvent(NULL, false, false, NULL);

    if ( broken_event_handle != NULL )
    {
      int code = WAIT_TIMEOUT;
      while ( code == WAIT_TIMEOUT )
        code = WaitForSingleObject(broken_event_handle, 100);

      if ( code == WAIT_OBJECT_0 )
      {
        suspend_running_threads(_suspended_threads);
        if ( dbg_detach_process() )
          SetEvent(broken_event_handle);
      }
    }
  }

  return ret;
}

//--------------------------------------------------------------------------
// Continuing from a broken connection in win32 debugger consist in the
// following step (if we're talking about a single threaded server):
//
//  1 - Notify the other thread that we want to reuse that connection
//  2 - Wait for the previous thread to notify that finished his work
//  3 - Reattach to the process and reopen thread's handles as, for a
//      reason, the handles we have are invalid (why?).
//  4 - Resume the threads we suspended before.
//
bool idaapi win32_debmod_t::dbg_continue_broken_connection(pid_t _pid)
{
  debmod_t::dbg_continue_broken_connection(_pid);

  QASSERT(676, broken_event_handle != NULL);

  // notify the broken thread we want to reuse the connection
  SetEvent(broken_event_handle);

  // and wait for the notification for a maximum of 15 seconds
  // as we don't want to wait forever (INFINITE) because the
  // other thread may fail
  int code = WaitForSingleObject(broken_event_handle, 15000);
  if ( code != WAIT_OBJECT_0 )
  {
    msg("Error restoring broken connection");
    return false;
  }

  if ( dbg_attach_process(_pid, -1) && reopen_threads() )
  {
    resume_suspended_threads(_suspended_threads);
    return true;
  }
  return false;
}

//--------------------------------------------------------------------------
bool win32_debmod_t::reopen_threads(void)
{
  if ( _OpenThread == NULL )
    return false;

  for ( threads_t::iterator p=threads.begin(); p != threads.end(); ++p )
  {
    HANDLE hThread;
    hThread = _OpenThread(THREAD_ALL_ACCESS, true, p->second.tid);
    if ( hThread != NULL )
      p->second.hThread = hThread;
    else
      deberr("OpenThread");
    p->second.suspend_count = get_thread_suspend_count(hThread);
  }
  return true;
}

//--------------------------------------------------------------------------
static bool enable_privilege(LPCTSTR privilege, bool enable);
static bool g_subsys_inited = false;
static bool g_got_debpriv = false;

bool init_subsystem()
{
  if ( g_subsys_inited )
    return true;

  if ( !win32_debmod_t::get_win_version()->ok() )
    return false;

  win_tool_help_t *wth = win32_debmod_t::get_tool_help();
  if ( wth->ok() )
    g_code |= DBG_HAS_PROCGETINFO;

  // DebugActiveProcessStop() is only available on XP/2K3
  if ( wth->use_debug_detach_process() )
    g_code |= DBG_HAS_DETACHPROC;

  g_got_debpriv = enable_privilege(SE_DEBUG_NAME, true);
  if ( !g_got_debpriv )
    msg("Can not set debug privilege: %s.\n"
        "Debugging of processes owned by another account won't be possible.\n",
        winerr(GetLastError()));

#ifndef UNDER_CE
  win32_debmod_t::reuse_broken_connections = true;
  init_win32_subsystem();
#else
  init_cefuncs();
#endif

  HINSTANCE h = GetModuleHandle(TEXT(TOOLHELP_LIB_NAME));
  *(FARPROC*)&_OpenThread = GetProcAddress(h, TEXT("OpenThread"));

  g_subsys_inited = g_code != 0;
  return g_subsys_inited;
}

//--------------------------------------------------------------------------
bool term_subsystem()
{
  if ( !g_subsys_inited )
    return true;

  g_subsys_inited = false;

  if ( g_got_debpriv )
  {
    enable_privilege(SE_DEBUG_NAME, false);
    g_got_debpriv = false;
  }

#ifndef UNDER_CE
  term_win32_subsystem();
#endif
  return true;
}

//--------------------------------------------------------------------------
debmod_t *create_debug_session()
{
  return new win32_debmod_t();
}

//--------------------------------------------------------------------------
//
//      DEBUG PRIVILEGE
//
//--------------------------------------------------------------------------
// dynamic linking information for Advapi functions
static HMODULE hAdvapi32 = NULL;
// function prototypes
typedef BOOL (WINAPI *OpenProcessToken_t)(
      HANDLE ProcessHandle,
      DWORD DesiredAccess,
      PHANDLE TokenHandle);
typedef BOOL (WINAPI *LookupPrivilegeValue_t)(
      LPCTSTR lpSystemName,
      LPCTSTR lpName,
      PLUID lpLuid);
typedef BOOL (WINAPI *AdjustTokenPrivileges_t)(
      HANDLE TokenHandle,
      BOOL DisableAllPrivileges,
      PTOKEN_PRIVILEGES NewState,
      DWORD BufferLength,
      PTOKEN_PRIVILEGES PreviousState,
      PDWORD ReturnLength);

// Function pointers
static OpenProcessToken_t      _OpenProcessToken      = NULL;
static LookupPrivilegeValue_t  _LookupPrivilegeValue  = NULL;
static AdjustTokenPrivileges_t _AdjustTokenPrivileges = NULL;

//--------------------------------------------------------------------------
static void term_advapi32(void)
{
  if ( hAdvapi32 != NULL )
  {
    DWORD code = GetLastError();
    FreeLibrary(hAdvapi32);
    SetLastError(code);
    hAdvapi32 = NULL;
  }
}

//--------------------------------------------------------------------------
static bool init_advapi32(void)
{
  // load the library
  hAdvapi32 = LoadLibrary(TEXT("advapi32.dll"));
  if ( hAdvapi32 == NULL )
    return false;

  // find the needed functions
  *(FARPROC*)&_OpenProcessToken       = GetProcAddress(hAdvapi32, TEXT("OpenProcessToken"));
  *(FARPROC*)&_LookupPrivilegeValue   = GetProcAddress(hAdvapi32, TEXT(LookupPrivilegeValue_Name));
  *(FARPROC*)&_AdjustTokenPrivileges  = GetProcAddress(hAdvapi32, TEXT("AdjustTokenPrivileges"));

  bool ok = _OpenProcessToken      != NULL
         && _LookupPrivilegeValue  != NULL
         && _AdjustTokenPrivileges != NULL;
  if ( !ok )
    term_advapi32();
  return ok;
}


//--------------------------------------------------------------------------
// based on code from:
// http://support.microsoft.com/support/kb/articles/Q131/0/65.asp
static bool enable_privilege(LPCTSTR privilege, bool enable)
{
  if ( !win32_debmod_t::get_win_version()->is_NT() ) // no privileges on 9X/ME
    return true;

  bool ok = false;
  if ( init_advapi32() )
  {
    HANDLE hToken;
    DWORD tokens = TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY;
    if ( _OpenProcessToken(GetCurrentProcess(), tokens, &hToken) )
    {
      LUID luid;
      if ( _LookupPrivilegeValue(NULL, privilege, &luid) )
      {
        TOKEN_PRIVILEGES tp;
        memset(&tp, 0, sizeof(tp));
        tp.PrivilegeCount           = 1;
        tp.Privileges[0].Luid       = luid;
        tp.Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;
        ok = _AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL) != FALSE;
      }
      CloseHandle(hToken);
    }
    term_advapi32();
  }
  return ok;
}
