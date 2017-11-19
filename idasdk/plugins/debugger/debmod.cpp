/*
        Base debmod class.
*/

#ifdef __NT__
#include <windows.h>
#endif

#include "debmod.h"
#include <err.h>
#include <expr.hpp>
#include <diskio.hpp>
#include <typeinf.hpp>
#include <kernwin.hpp>

//--------------------------------------------------------------------------
// Variables to be used by built-in IDC functions
debmod_t *idc_debmod;
thid_t idc_thread;

//--------------------------------------------------------------------------
// Initialize static members
bool debmod_t::reuse_broken_connections = false;

//--------------------------------------------------------------------------
static const char *get_event_name(event_id_t id)
{
  switch ( id )
  {
    case NO_EVENT:       return "NO_EVENT";
    case THREAD_START:   return "THREAD_START";
    case STEP:           return "STEP";
    case SYSCALL:        return "SYSCALL";
    case WINMESSAGE:     return "WINMESSAGE";
    case PROCESS_DETACH: return "PROCESS_DETACH";
    case PROCESS_START:  return "PROCESS_START";
    case PROCESS_ATTACH: return "PROCESS_ATTACH";
    case PROCESS_SUSPEND: return "PROCESS_SUSPEND";
    case LIBRARY_LOAD:   return "LIBRARY_LOAD";
    case PROCESS_EXIT:   return "PROCESS_EXIT";
    case THREAD_EXIT:    return "THREAD_EXIT";
    case BREAKPOINT:     return "BREAKPOINT";
    case EXCEPTION:      return "EXCEPTION";
    case LIBRARY_UNLOAD: return "LIBRARY_UNLOAD";
    case INFORMATION:    return "INFORMATION";
    case TRACE_FULL:     return "TRACE_FULL";
    default:             return "???";
  }
}

//---------------------------------------------------------------------------
#if defined(__MAC__) || defined(__LINUX__) || defined(__ANDROID__)
int idaapi maclnx_launch_process(
        debmod_t *debmod,
        const char *path,
        const char *args,
        const char *startdir,
        int flags,
        const char *input_path,
        uint32 input_file_crc32,
        void **child_pid)
{
  // prepare full path if the input_path is relative
  char full_input[QMAXPATH];
  if ( startdir[0] != '\0' && !qisabspath(input_path) )
  {
    qmake_full_path(full_input, sizeof(full_input), input_path);
    input_path = full_input;
  }

  // input file specified in the database does not exist
  if ( input_path[0] != '\0' && !qfileexist(input_path) )
  {
    debmod->dwarning("AUTOHIDE NONE\nInput file is missing: %s", input_path);
    return -2;
  }

  // temporary thing, later we will retrieve the real file name
  // based on the process id
  debmod->input_file_path = input_path;
  debmod->is_dll = (flags & DBG_PROC_IS_DLL) != 0;

  if ( !qfileexist(path) )
  {
    debmod->dmsg("%s: %s\n", path, winerr(errno));
    return -1;
  }

  int mismatch = 0;
  if ( !debmod->check_input_file_crc32(input_file_crc32) )
    mismatch = CRC32_MISMATCH;

#ifdef __EA64__
  bool dbg_srv_64 = true;
#else
  bool dbg_srv_64 = false;
  if ( (flags & DBG_PROC_64BIT) != 0 )
  {
    debmod->dwarning("Cannot debug a 64bit process with the 32bit debugger server, sorry\n");
    return -1;
  }
#endif

  launch_process_params_t lpi;
  lpi.path = path;
  lpi.args = args;
  lpi.startdir = startdir[0] != '\0' ? startdir : NULL;
  lpi.flags = LP_NO_ASLR | LP_DETACH_TTY;
  if ( (flags & DBG_NO_TRACE) == 0 )
    lpi.flags |= LP_TRACE;

  if ( (flags & DBG_PROC_64BIT) != 0 )
  {
    lpi.flags |= LP_LAUNCH_64_BIT;
  }
  else if ( (flags & DBG_PROC_32BIT) != 0 )
  {
    lpi.flags |= LP_LAUNCH_32_BIT;
  }
  else
  {
    lpi.flags |= dbg_srv_64 ? LP_LAUNCH_64_BIT : LP_LAUNCH_32_BIT;
    debmod->dmsg("Launching as %sbit process\n", dbg_srv_64 ? "64" : "32");
  }

  qstring errbuf;
  *child_pid = launch_process(lpi, &errbuf);

  if ( *child_pid == NULL )
  {
    debmod->dmsg("launch_process: %s", errbuf.c_str());
    return -1;
  }
  return 1 | mismatch;
}
#endif

//--------------------------------------------------------------------------
debmod_t::debmod_t(void):
    debugger_flags(0),
    rpc(NULL),
    debug_debugger(false),
    is_dll(false),
    sp_idx(-1),
    pc_idx(-1),
    nregs(0),
    broken_connection(false),
    pid(-1)
{
  debapp_attrs.platform = "UNDEFINED";
  proclist.clear();
}

//--------------------------------------------------------------------------
bool debmod_t::same_as_oldmemcfg(const meminfo_vec_t &areas) const
{
  return old_areas == areas;
}

//--------------------------------------------------------------------------
void debmod_t::save_oldmemcfg(const meminfo_vec_t &areas)
{
  old_areas = areas;
}

//--------------------------------------------------------------------------
bool debmod_t::check_input_file_crc32(uint32 orig_crc)
{
  // take this opportunity to check that the derived class initialized
  // register related fields correctly
  QASSERT(30016, sp_idx != -1 && pc_idx != -1 && nregs > 0);

  if ( orig_crc == 0 )
    return true; // the database has no crc

  linput_t *li = open_linput(input_file_path.c_str(), false);
  if ( li == NULL )
    return false;

  uint32 crc = calc_file_crc32(li);
  close_linput(li);
  return crc == orig_crc;
}

//--------------------------------------------------------------------------
const exception_info_t *debmod_t::find_exception(int code)
{
  for ( const exception_info_t *ei = exceptions.begin();
        ei != exceptions.end();
        ++ei )
  {
    if ( ei->code == (uint)code )
      return ei;
  }
  return NULL;
}

//--------------------------------------------------------------------------
bool debmod_t::get_exception_name(int code, char *buf, size_t bufsize)
{
  const exception_info_t *ei = find_exception(code);
  if ( ei != NULL )
  {
    qstrncpy(buf, ei->name.c_str(), bufsize);
    return true;
  }
  qsnprintf(buf, bufsize, "%08X", code);
  return false;
}

//----------------------------------------------------------------------
int idaapi debmod_t::get_system_specific_errno(void) const
{
  // this code must be acceptable by winerr()
#ifdef __NT__
  return GetLastError();
#else
  return errno;
#endif
}

//----------------------------------------------------------------------
// Display a system error message. This function always returns false
bool debmod_t::deberr(const char *format, ...)
{
  if ( !debug_debugger )
    return false;

  int code = get_system_specific_errno();
  va_list va;
  va_start(va, format);
  dvmsg(0, rpc, format, va);
  va_end(va);
  dmsg(": %s\n", winerr(code));
  return false;
}

//--------------------------------------------------------------------------
// used to debug the debugger
void debmod_t::debdeb(const char *format, ...)
{
  if ( !debug_debugger )
    return;

  va_list va;
  va_start(va, format);
  dvmsg(0, rpc, format, va);
  va_end(va);
}

//--------------------------------------------------------------------------
void debmod_t::cleanup(void)
{
  input_file_path.qclear();
  old_areas.qclear();
  exceptions.qclear();
  clear_debug_names();
  handling_lowcnds.clear();
#ifdef ENABLE_LOWCNDS
  cndmap.clear();
#endif
  page_bpts.clear();
  pid = 0;
  is_dll = false;
}

//--------------------------------------------------------------------------
void idaapi debmod_t::dbg_set_exception_info(const exception_info_t *table, int qty)
{
  exceptions.qclear();
  exceptions.reserve(qty);
  for ( int i=0; i < qty; i++ )
    exceptions.push_back(*table++);
}

//--------------------------------------------------------------------------
char *debug_event_str(const debug_event_t *ev)
{
  static char buf[MAXSTR];
  return debug_event_str(ev, buf, sizeof(buf));
}

//--------------------------------------------------------------------------
char *debug_event_str(const debug_event_t *ev, char *buf, size_t bufsize)
{
  char *ptr = buf;
  char *end = buf + bufsize;
  ptr += qsnprintf(ptr, end-ptr, "%s ea=%a",
                   get_event_name(ev->eid),
                   ev->ea);
  switch ( ev->eid )
  {
  case PROCESS_START:  // New process started
  case PROCESS_ATTACH: // Attached to running process
  case LIBRARY_LOAD:   // New library loaded
    ptr += qsnprintf(ptr, end-ptr, " base=%a size=%a rebase=%a name=%s",
                     ev->modinfo.base,
                     ev->modinfo.size,
                     ev->modinfo.rebase_to,
                     ev->modinfo.name);
    break;
  case PROCESS_EXIT:   // Process stopped
  case THREAD_EXIT:    // Thread stopped
    ptr += qsnprintf(ptr, end-ptr, " exit_code=%d", ev->exit_code);
    break;
  case BREAKPOINT:     // Breakpoint reached
    ptr += qsnprintf(ptr, end-ptr, " hea=%a kea=%a", ev->bpt.hea, ev->bpt.kea);
    break;
  case EXCEPTION:      // Exception
    ptr += qsnprintf(ptr, end-ptr, " code=%x can_cont=%d ea=%a info=%s",
                     ev->exc.code,
                     ev->exc.can_cont,
                     ev->exc.ea,
                     ev->exc.info);
    break;
  case LIBRARY_UNLOAD: // Library unloaded
  case INFORMATION:    // User-defined information
    APPCHAR(ptr, end, ' ');
    APPEND(ptr, end, ev->info);
    break;
  default:
    break;
  }
  qsnprintf(ptr, end-ptr, " pid=%d tid=%d handled=%d",
            ev->pid,
            ev->tid,
            ev->handled);
  return buf;
}

//--------------------------------------------------------------------------
//lint -e{1536} Exposing low access member 'debmod_t::dn_names'
name_info_t *debmod_t::get_debug_names()
{
  return &dn_names;
}

//--------------------------------------------------------------------------
int debmod_t::set_debug_names()
{
  name_info_t *ni = get_debug_names();
  if ( ni == NULL || ni->addrs.empty() )
    return 1;
  int code = send_debug_names_to_ida(
        ni->addrs.begin(),
        ni->names.begin(),
        (int)ni->addrs.size());
  clear_debug_names();
  return code;
}

//--------------------------------------------------------------------------
void debmod_t::clear_debug_names()
{
  if ( dn_names.addrs.empty() )
    return;

  typedef qvector<char *> charptr_vec_t;
  charptr_vec_t::iterator it_end = dn_names.names.end();
  for ( charptr_vec_t::iterator it=dn_names.names.begin();it!=it_end;++it )
    qfree(*it);

  dn_names.names.clear();
  dn_names.addrs.clear();
}

//--------------------------------------------------------------------------
void debmod_t::save_debug_name(ea_t ea, const char *name)
{
  dn_names.addrs.push_back(ea);
  dn_names.names.push_back(qstrdup(name));
}

//--------------------------------------------------------------------------
bool debmod_t::continue_after_last_event(bool handled)
{
  last_event.handled = handled;
  return dbg_continue_after_event(&last_event) == 1;
}

//--------------------------------------------------------------------------
bool debmod_t::should_stop_appcall(thid_t, const debug_event_t *event, ea_t ea)
{
  switch ( event->eid )
  {
    case EXCEPTION:
      // exception on the stack (non-executable stack?)
      if ( event->exc.ea == ea )
        return true;
      // no break
    case BREAKPOINT:
      // reached the control breakpoint?
      if ( event->ea == ea )
        return true;
    default:
      break;
  }
  return false;
}

//--------------------------------------------------------------------------
// return top of the stack area usable by appcall. usually it is equal to the
// current esp, unless the area below the stack pointer is not usable
// (for example, AMD64 ABI required the "red zone" not to be modified)
ea_t debmod_t::calc_appcall_stack(const regvals_t &regvals)
{
  return ea_t(regvals[sp_idx].ival);
}

//--------------------------------------------------------------------------
ea_t idaapi debmod_t::dbg_appcall(
        ea_t func_ea,
        thid_t tid,
        int stkarg_nbytes,
        const struct regobjs_t *regargs,
        struct relobj_t *stkbytes,
        struct regobjs_t *retregs,
        qstring *errbuf,
        debug_event_t *_event,
        int options)
{
  enum
  {
    E_OK,          // Success
    E_READREGS,    // Failed to read registers
    E_NOSTACK,     // Failed to allocate stack frame
    E_REG_USED,    // The calling convention refers to reserved registers
    E_ARG_ALLOC,   // Failed to allocate memory for stack arguments
    E_WRITE_ARGS,  // Failed to setup stack arguments
    E_WRITE_REGS,  // Failed to setup register arguments
    E_HANDLE_EVENT,// Failed to handle debug event
    E_DEBUG_EVENT, // Could not get debug events
    E_RESUME,      // Failed to resume the application
    E_EXCEPTION,   // An exception has occured
    E_APPCALL_FROM_EXC, // Cannot issue an AppCall if last event was an exception
    E_TIMEOUT,     // Timeout
  };

  static const char *const errstrs[] =
  {
    "success",
    "failed to read registers",
    "failed to allocate stack frame",
    "the calling convention refers to reserved registers",
    "failed to allocate memory for stack arguments",
    "failed to setup stack arguments",
    "failed to setup register arguments",
    "failed to handle debug event",
    "could not get debug events",
    "failed to resume the application",
    "an exception has occured",
    "last event was an exception, cannot perform an appcall",
    "timeout",
  };

  // Save registers
  regval_t rv;

  bool brk = false;
  int err = E_OK;

  call_context_t &ctx = appcalls[tid].push_back();

  regval_map_t call_regs;
  ea_t args_sp = BADADDR;
  do
  {
    // In Win32, when WaitForDebugEvent() returns an exception
    // it seems that the OS remembers the exception context so that
    // the next call to ContinueDebugEvent() will work with the last exception context.
    // Now if we carry an AppCall when an exception was just reported:
    // - Appcall will change context
    // - Appcall's control bpt will generate an exception thus overriding the last exception context saved by the OS
    // - After Appcall, IDA kernel cannot really continue from the first exception because it was overwritten
    // Currently we will disallow Appcalls if last event is an exception
    if ( last_event.eid == EXCEPTION )
    {
      err = E_APPCALL_FROM_EXC;
      break;
    }
    // Save registers
    ctx.saved_regs.resize(nregs);
    if ( dbg_read_registers(tid, -1, ctx.saved_regs.begin()) != 1 )
    {
      err = E_READREGS;
      break;
    }

    // Get SP value
    ea_t org_sp = calc_appcall_stack(ctx.saved_regs);
    if ( org_sp == BADADDR )
    {
      err = E_NOSTACK;
      break;
    }

    // Stack contents
    bytevec_t stk;

    // Prepare control address
    // We will generate a BP code ptrsz aligned and push unto the stack
    // as the first argument. This is where we will set the control bpt.
    // Since the bpt is on the stack, two possible scenarios:
    // - BPT exception
    // - Access violation: trying to execute from NX page
    // In both cases we will catch an exception and learn what address was
    // involved.

    // - Save the ctrl address
    ea_t ctrl_ea = org_sp - debapp_attrs.addrsize;

    // - Compute the pointer where arguments will be allocated on the stack
    size_t stkbytes_size = align_up(stkbytes->size(), debapp_attrs.addrsize);
    args_sp = ctrl_ea - stkbytes_size;

    // align the stack pointer to 16 byte boundary (gcc compiled programs require it)
    args_sp &= ~15;
    ctx.ctrl_ea = args_sp + stkbytes_size;

    // Relocate the stack arguments
    if ( !stkbytes->relocate(args_sp, false) )
    {
      err = E_ARG_ALLOC;
      break;
    }

    // Prepare the stack.
    // The memory layout @SP before transfering to the function:
    // R = ret addr
    // A = args

    // - Append the return address (its value is the value of the ctrl code address)
    stk.append(&ctx.ctrl_ea, debapp_attrs.addrsize);

    // - Append the stack args
    stk.append(stkbytes->begin(), stkbytes->size());
    stk.resize(debapp_attrs.addrsize+stkbytes_size); // align up
    ctx.sp = args_sp - debapp_attrs.addrsize;
    if ( ctx.sp >= org_sp )
    { // underflow?
      err = E_NOSTACK;
      break;
    }

    int delta = finalize_appcall_stack(ctx, call_regs, stk);
    ctx.sp += delta; // nbytes inserted at the beginning of stk

    // Write the stack
    int nwrite = stk.size() - delta;
    if ( nwrite > 0 )
    {
      if ( dbg_write_memory(ctx.sp, stk.begin()+delta, nwrite) != nwrite )
      {
        err = E_WRITE_ARGS;
        break;
      }
      //show_hex(stk.begin()+delta, nwrite, "Written stack bytes to %a:\n", ctx.sp);
    }

    // ask the debugger to set a breakpoint
    dbg_add_bpt(BPT_SOFT, ctx.ctrl_ea, -1);

    // Copy arg registers to call_regs
    for ( size_t i=0; i < regargs->size(); i++ )
    {
      const regobj_t &ri = regargs->at(i);
      int reg_idx = ri.regidx;
      if ( reg_idx == sp_idx || reg_idx == pc_idx )
      {
        brk = true;
        err = E_REG_USED;
        break;
      }

      // Copy the register value
      if ( ri.size() <= sizeof(rv.fval) )
      {
        rv.clear();
        memcpy(rv.fval, ri.value.begin(), ri.size());
        if ( ri.relocate )
          rv.ival += args_sp;
      }
      else
      {
        bytevec_t &b = rv.set_bytes();
        b.resize(ri.size());
        memcpy(b.begin(), ri.value.begin(), ri.size());
        rv.rvtype = 0; // custom data format
      }
      call_regs[reg_idx] = rv;
    }
    if ( brk )
      break;

    // Set the stack pointer
    rv.clear();
    rv.ival = ctx.sp;
    call_regs[sp_idx] = rv;

    // Set the instruction pointer
    rv.ival = func_ea;
    call_regs[pc_idx] = rv;

    // Change all the registers in question
    for ( regval_map_t::iterator it = call_regs.begin();
          it != call_regs.end();
          ++it )
    {
      if ( dbg_write_register(tid, it->first, &it->second) != 1 )
      {
        err = E_WRITE_REGS;
        brk = true;
        break;
      }
      // Mark that we changed the regs already
      ctx.regs_spoiled = true;
    }
    if ( brk )
      break;

    // For manual appcall, we have done everything, just return now
    if ( (options & APPCALL_MANUAL) != 0 )
      break;

    // Resume the application
    // Since no* exception last occured**, we can safely say that the
    // debugger actually handled the exception.
    // * : We disallow appcalls if an exception last occured
    // **: Actually if an AppCall was issued then last event is an exception
    //     but we will mask it by calling continue_after_event(handled_by_debugger = true)
    if ( !continue_after_last_event(true) )
    {
      err = E_RESUME;
      break;
    }

    // We use this list to accumulate the events
    // We will give back the events at the end of the loop
    debug_event_t tmp;
    debug_event_t *event = _event != NULL ? _event : &tmp;

    // Determine timeout for get_debug_event()
    uint64 endtime = 0;
    int recalc_timeout = 0; // never recalc timeout
    int timeout_ms = TIMEOUT;
    if ( (options & APPCALL_TIMEOUT) != 0 )
    {
      timeout_ms = GET_APPCALL_TIMEOUT(options);
      if ( timeout_ms > 0 )
      {
        get_nsec_stamp(&endtime);
        endtime += timeout_ms * uint64(1000 * 1000);
      }
      recalc_timeout = 1; // recalc timeout after the first pass
    }

    while ( true )
    {
      if ( recalc_timeout )
      {
        if ( recalc_timeout != 2 )
        { // we will recalc timeout at the next iteration
          recalc_timeout = 2;
        }
        else
        {
          if ( timeout_ms > 0 )
          {
            // calculate the remaining timeout
            uint64 now;
            get_nsec_stamp(&now);
            timeout_ms = int64(endtime - now) / int64(1000 * 1000);
          }
          if ( timeout_ms <= 0 )
          { // timeout out waiting for the appcall to finish
            err = E_TIMEOUT;
            if ( dbg_prepare_to_pause_process() <= 0 )
              break; // could not even prepare to pause, nothing we can do :(
          }
        }
      }
      // Wait for debug events
      gdecode_t r = dbg_get_debug_event(event, timeout_ms);
      if ( r == GDE_NO_EVENT )
        continue;
      if ( r == GDE_ERROR )
      { // error getting debug event (network error, etc)
        err = E_DEBUG_EVENT;
        break;
      }

      // We may get three possible events related to our control breakpoint:
      // - Access violation type: because we try to execute non-executable code
      // - Or a BPT exception if the stack page happens to be executable
      // - Process exit
      if ( event->eid == PROCESS_EXIT )
      { // process is gone
        send_debug_event_to_ida(event, RQ_SILENT);
        args_sp = BADADDR;
        brk = true;
        break;
      }
      if ( err == E_TIMEOUT )
      {
        send_debug_event_to_ida(event, RQ_SILENT|RQ_SUSPEND);
        event->eid = NO_EVENT;
        last_event.eid = NO_EVENT;
        break;
      }
      if ( should_stop_appcall(tid, event, ctx.ctrl_ea) )
      {
        last_event.eid = NO_EVENT;
        break;
      }
      // Any other exception?
      if ( event->eid == EXCEPTION )
      {
        if ( (options & APPCALL_DEBEV) == 0 )
          *errbuf = event->exc.info; // Copy exception text to the user
        err = E_EXCEPTION;
        // When an exception happens during the appcall, we want to mask
        // the exception, because:
        // 1. we reset the EIP to its original location
        // 2. there is no exception handler for the appcall so we cannot really pass as unhandled
        // FIXME
        last_event.eid = NO_EVENT;
        last_event.handled = true;
        brk = true;
        break;
      }

      if ( send_debug_event_to_ida(event, RQ_SILENT|RQ_SUSPEND) != 0 )
      {
        err = E_HANDLE_EVENT;
        break;
      }
      dbg_continue_after_event(event);
      event->eid = NO_EVENT;
    }

    if ( brk || err != E_OK )
      break;

    // write the argument vector back because it could be spoiled by the application
    if ( stkarg_nbytes > 0 )
    {
      int nbytes = stkarg_nbytes;
      if ( nbytes > stkbytes->size() // wrong parameters
        || dbg_write_memory(args_sp, stkbytes->begin(), nbytes) != ssize_t(nbytes) )
      {
        err = E_WRITE_ARGS;
        break;
      }
    }

    // Retrieve the return value
    if ( retregs != NULL && !retregs->empty() )
    {
      regvals_t retr;
      retr.resize(nregs);
      if ( dbg_read_registers(tid, -1, retr.begin()) <= 0 )
      {
        err = E_READREGS;
        break;
      }
      for ( size_t i=0; i < retregs->size(); i++ )
      {
        regobj_t &r = retregs->at(i);
        regval_t &v = retr[r.regidx];
        memcpy(r.value.begin(), v.get_data(), r.value.size());
        r.relocate = false;
      }
    }
  } while ( false );

  if ( err != E_OK )
  {
    if ( err != E_EXCEPTION )
      *errbuf = errstrs[err];
    dbg_cleanup_appcall(tid);
    args_sp = BADADDR;
  }

  return args_sp;
}

//--------------------------------------------------------------------------
// Cleanup after appcall()
// The debugger module must keep the stack blob in the memory until this function
// is called. It will be called by the kernel for each successful call_app_func()
int idaapi debmod_t::dbg_cleanup_appcall(thid_t tid)
{
  call_contexts_t &calls = appcalls[tid];
  if ( calls.empty() )
    return 0;

  // remove the return breakpoint
  call_context_t &ctx = calls.back();
  if ( !preprocess_appcall_cleanup(tid, ctx) )
    return 0;

  dbg_del_bpt(BPT_SOFT, ctx.ctrl_ea, bpt_code.begin(), bpt_code.size());
  if ( ctx.regs_spoiled )
  {
    if ( !write_registers(tid, 0, ctx.saved_regs.size(), ctx.saved_regs.begin()) )
    {
      dmsg("Failed to restore registers!\n");
      return 0;
    }
  }

  calls.pop();
  return events.empty() ? 1 : 2;
}

//--------------------------------------------------------------------------
int debmod_t::resume_app_and_get_event(debug_event_t *dev)
{
  thid_t tid = dev->tid;
  int code = dbg_continue_after_event(dev);
  if ( code > 0 )
  {
    while ( true )
    {
      gdecode_t gc = dbg_get_debug_event(dev, TIMEOUT_INFINITY);
      if ( gc != GDE_NO_EVENT )
        break;
    }
    // is it in our thread?
    if ( tid != dev->tid )
    { // very odd! an event from another thread arrived
      if ( dev->eid != THREAD_START )
        dmsg("unexpected event from thread %d arrived (expected thread %d)\n", dev->tid, tid);
      code = 0; // indicate failure
    }
  }
  return code;
}

//--------------------------------------------------------------------------
int debmod_t::dbg_perform_single_step(debug_event_t *dev, const insn_t &)
{
  // all other threads must be frozen at this moment
  int code = dbg_set_resume_mode(dev->tid, RESMOD_INTO);
  if ( code > 0 )
    code = resume_app_and_get_event(dev);
  return code;
}

//--------------------------------------------------------------------------
// returns true-lowcnd was false, resumed the application
// nb: recursive calls to this function are not handled in any special way!
bool debmod_t::handle_lowcnd(lowcnd_t *lc, debug_event_t *event, int elc_flags)
{
  if ( (debugger_flags & DBG_FLAG_CAN_CONT_BPT) == 0 )
  {
    // difficult case: we have to reset pc, remove the bpt, single step, and resume the app
    QASSERT(616, !handling_lowcnds.has(lc->ea));
    handling_lowcnds.push_back(lc->ea);

    int code;
    if ( (elc_flags & ELC_KEEP_EIP) == 0 )
    {
      regval_t rv;
      rv._set_int(lc->ea);
      code = dbg_write_register(event->tid, pc_idx, &rv);
      if ( code <= 0 )
      {
        handling_lowcnds.del(lc->ea);
        return false;
      }
    }

    code = dbg_freeze_threads_except(event->tid);
    if ( code > 0 )
    {
      int bptlen = lc->type == BPT_SOFT ? lc->orgbytes.size() : lc->size;
      code = dbg_del_bpt(lc->type, lc->ea, lc->orgbytes.begin(), bptlen);
      if ( code > 0 )
      {
        code = dbg_perform_single_step(event, lc->cmd);
        if ( code <= 0 )
          dmsg("%a: failed to single step\n", event->ea); // may happen

        if ( dbg_add_bpt(lc->type, lc->ea, bptlen) <= 0 )
        {
          // if this fails, it may be because the breakpoint is invalid
          // at this time so we should notify IDA it isn't available
          // any more
          code = 0;
          dwarning("%a: could not restore deleted bpt\n", lc->ea); // odd
        }
      }
      if ( dbg_thaw_threads_except(event->tid) <= 0 )
      {
        dwarning("%d: could not resume suspended threads\n", event->tid); // odd
        code = 0;
      }
    }
    handling_lowcnds.del(lc->ea);
    if ( code <= 0 || event->eid != STEP )
      return false; // did not resume
  }
  if ( (elc_flags & ELC_KEEP_SUSP) != 0 )
    return true;
  return dbg_continue_after_event(event) > 0;
}

//--------------------------------------------------------------------------
// return lowcnd_t if its condition is not satisfied
lowcnd_t *debmod_t::get_failed_lowcnd(thid_t tid, ea_t ea)
{
#ifndef ENABLE_LOWCNDS
  qnotused(tid);
  qnotused(ea);
#else
  lowcnds_t::iterator p = cndmap.find(ea);
  if ( p != cndmap.end() )
  {
    bool ok = true;
    idc_value_t rv;
    char name[32];
    ::qsnprintf(name, sizeof(name), "__lc%a", ea);
    lowcnd_t &lc = p->second;
    lock_begin();
    {
      idc_debmod = this; // is required by compiler/interpreter
      idc_thread = tid;  // is required by          interpreter
      if ( !lc.compiled )
      {
        qstring func;
        func.sprnt("static %s() { return %s; }", name, lc.cndbody.begin());
        ok = CompileLineEx(func.begin(), NULL, 0, NULL, true);
        if ( ok )
          lc.compiled = true;
      }
      if ( ok )
        ok = Run(name, 0, NULL, &rv, NULL, 0);
    }
    lock_end();
    if ( !ok )
    {
      report_idc_error(ea, get_qerrno(), get_error_data(0), get_error_string(0));
      return NULL;
    }

    VarInt64(&rv);
    if ( rv.i64 == 0 )
      return &lc; // condition is not satisfied, resume
  }
#endif
  return NULL;
}

//--------------------------------------------------------------------------
bool debmod_t::evaluate_and_handle_lowcnd(debug_event_t *event, int elc_flags)
{
  bool resume = false;
  if ( event->eid == BREAKPOINT )
  {
    ea_t ea = event->bpt.kea != BADADDR ? event->bpt.kea
            : event->bpt.hea != BADADDR ? event->bpt.hea
            : event->ea;
    QASSERT(617, !handling_lowcnds.has(ea));
    lowcnd_t *lc = get_failed_lowcnd(event->tid, ea);
    if ( lc != NULL )
    { // condition is not satisfied, just make a single step and resume
      debdeb("%a: bptcnd yielded false\n", ea);
      event->handled = true;
      resume = handle_lowcnd(lc, event, elc_flags);
    }
  }
  return resume;
}

//--------------------------------------------------------------------------
int idaapi debmod_t::dbg_eval_lowcnd(thid_t tid, ea_t ea)
{
  return get_failed_lowcnd(tid, ea) == NULL;
}

//--------------------------------------------------------------------------
int idaapi debmod_t::dbg_update_lowcnds(
      const lowcnd_t *lowcnds,
      int nlowcnds)
{
#ifndef ENABLE_LOWCNDS
  qnotused(lowcnds);
  qnotused(nlowcnds);
  return 0;
#else
  for ( int i=0; i < nlowcnds; i++, lowcnds++ )
  {
    ea_t ea = lowcnds->ea;
    if ( lowcnds->cndbody.empty() )
      cndmap.erase(ea);
    else
      cndmap[ea] = *lowcnds;
  }
  return nlowcnds;
#endif
}

//--------------------------------------------------------------------------
// determine the future bpt size and read the original instruction from memory.
// if necessary, the bpt address may be adjusted.
// return the number of read bytes.
// this function is overloaded in arm debugger subclasses.
int debmod_t::read_bpt_orgbytes(ea_t *p_ea, int *p_len, uchar *buf, int bufsize)
{
  int len = *p_len;
  if ( (debugger_flags & DBG_FLAG_CAN_CONT_BPT) == 0 )
  { // we must save the original bytes before adding the bpt
    QASSERT(30017, bufsize >= len);
    if ( dbg_read_memory(*p_ea, buf, len) <= 0 )
      return -1;
  }
  else
  { // if the debuger can itself continue from bpts,
    // orgbytes will not be used by the kernel. however
    // we must return something because non-empty orgbytes mean
    // that a soft bpt is active. we return zeroes in b->orgbytes.
  }
  return len;
}

//--------------------------------------------------------------------------
int idaapi debmod_t::dbg_update_bpts(
      update_bpt_info_t *ubpts,
      int nadd,
      int ndel)
{
  // Write breakpoints to the process
  int cnt = 0;
  update_bpt_info_t *b;
  update_bpt_info_t *end = ubpts + nadd;
  for ( b=ubpts; b != end; b++ )
  {
    int code = b->code;
    if ( code != BPT_OK )
      continue; // should be BPT_SKIP
    int len;
    uchar buf[32];
    memset(buf, 0, sizeof(buf));
    int nread = 0;
    ea_t ea = b->ea;
    if ( b->type == BPT_SOFT )
    {
      len = bpt_code.size();
      nread = read_bpt_orgbytes(&ea, &len, buf, sizeof(buf));
      if ( nread < 0 )
        code = BPT_READ_ERROR;
    }
    else
    {
      len = b->size;
    }
    if ( code == BPT_OK )
    {
      code = dbg_add_bpt(b->type, ea, len);
      debdeb("dbg_add_bpt(type=%d, ea=%a, len=%d) => %d\n", b->type, ea, len, code);
      switch ( code )
      {
        case 2:
          code = BPT_PAGE_OK;
          break;
        case 1:
          code = BPT_OK;
          break;
        default:
          code = BPT_WRITE_ERROR;
          break;
      }
    }

    b->code = code;
    if ( code == BPT_OK )
    {
      cnt++;
      if ( nread > 0 )
        b->orgbytes = bytevec_t(buf, nread);
    }
  }

  // Delete breakpoints from the process.
  end += ndel;
  for ( ; b != end; b++ )
  {
    b->code = BPT_OK;
    int len = b->type == BPT_SOFT ? b->orgbytes.size() : b->size;
    int code = dbg_del_bpt(b->type, b->ea, b->orgbytes.begin(), len);
    debdeb("dbg_del_bpt(type=%d, ea=%a) => %d\n", b->type, b->ea, code);
    if ( code > 0 )
      cnt++;
    else
      b->code = BPT_WRITE_ERROR;
  }

  return cnt;
}

//--------------------------------------------------------------------------
// Find a page breakpoint that would cause an exception on the given range
// NB: we do not check the user-specified range but the real page range!
page_bpts_t::iterator debmod_t::find_page_bpt(
        ea_t ea,
        int size)
{
  page_bpts_t::iterator p = page_bpts.lower_bound(calc_page_base(ea));
  if ( p == page_bpts.end() || p->first >= ea+size )
  {
    if ( p == page_bpts.begin() )
      return page_bpts.end(); // not found
    --p;
  }
  ea_t page_ea = p->first;
  int page_len = p->second.real_len;
  if ( !interval::overlap(ea, size, page_ea, page_len) )
    p = page_bpts.end();
  return p;
}

//--------------------------------------------------------------------------
bool debmod_t::del_page_bpt(ea_t ea, bpttype_t type)
{
  page_bpts_t::iterator p = find_page_bpt(ea);
  if ( p == page_bpts.end() )
    return false; // could not find
  if ( p->second.ea != ea || p->second.type != type )
    return false; // not exact match

  dbg_enable_page_bpt(p, false);
  page_bpts.erase(p);
  return true;
}

//--------------------------------------------------------------------------
void debmod_t::enable_page_bpts(bool enable)
{
  for ( page_bpts_t::iterator p = page_bpts.begin(); p != page_bpts.end(); ++p )
    dbg_enable_page_bpt(p, enable);
}

//--------------------------------------------------------------------------
void debmod_t::set_platform(const char *platform_name)
{
  debapp_attrs.platform = platform_name;
}

//--------------------------------------------------------------------------
void debmod_t::dbg_get_debapp_attrs(debapp_attrs_t *out_pattrs) const
{
  *out_pattrs = debapp_attrs;
}

//--------------------------------------------------------------------------
bool debmod_t::restore_broken_breakpoints(void)
{
  debmodbpt_map_t::const_iterator p;
  for ( p = bpts.begin(); p != bpts.end(); ++p )
  {
    const debmod_bpt_t &bpt = p->second;
    if ( !dbg_write_memory(bpt.ea, bpt.saved, bpt.nsaved) )
      msg("Failed to restore broken breakpoint at 0x%a\n", bpt.ea);
  }
  bpts.clear();
  return true;
}


//--------------------------------------------------------------------------
void debmod_t::log_exception(
        const debug_event_t *ev,
        const exception_info_t *ei)
{
  if ( ei == NULL || (ei->flags & EXC_SILENT) == 0 )
  {
    if ( ev->exc.ea != BADADDR )
    {
      dmsg("%a: %s -> %a (exc.code %x, tid %d)\n",
           ev->ea, ev->exc.info, ev->exc.ea, ev->exc.code, ev->tid);
    }
    else
    {
      dmsg("%a: %s (exc.code %x, tid %d)\n",
           ev->ea, ev->exc.info, ev->exc.code, ev->tid);
    }
  }
}

//--------------------------------------------------------------------------
int idaapi debmod_t::dbg_rexec(const char *cmdline)
{
  msg("REXEC: %s\n", cmdline);
  return call_system(cmdline);
}

//--------------------------------------------------------------------------
// 1-ok, 0-failed
// input is valid only if n==0
int idaapi debmod_t::dbg_process_get_info(int n, const char *input, process_info_t *pinfo)
{
  if ( n == 0 )
  {
    input_file_path = input;
    proclist.clear();
    get_process_list(&proclist);
  }

  if ( n < 0 || n >= proclist.size() )
    return false;

  if ( pinfo != NULL )
    proclist[n].copy_to(pinfo);
  return true;
}

//--------------------------------------------------------------------------
int idaapi debmod_t::get_process_list(procvec_t *list)
{
  list->clear();
  return -1;
}
