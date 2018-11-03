//
// This file is included from other files, do not directly compile it.
// It contains the implementation of debugger plugin callback functions
//

#include <err.h>
#include <name.hpp>
#include <expr.hpp>
#include <segment.hpp>
#include <typeinf.hpp>

//---------------------------------------------------------------------------
//lint -esym(714, rebase_or_warn) not referenced
int rebase_or_warn(ea_t base, ea_t new_base)
{
  int code = rebase_program(new_base - base, MSF_FIXONCE);
  if ( code != MOVE_SEGM_OK )
  {
    msg("Failed to rebase program, error code %d\n", code);
    warning("IDA failed to rebase the program.\n"
      "Most likely it happened because of the debugger\n"
      "segments created to reflect the real memory state.\n\n"
      "Please stop the debugger and rebase the program manually.\n"
      "For that, please select the whole program and\n"
      "use Edit, Segments, Rebase program with delta 0x%08a",
      new_base - base);
  }
  return code;
}

//---------------------------------------------------------------------------
void idaapi s_stopped_at_debug_event(void)
{
  // Let the debugger module populate the names
  g_dbgmod.dbg_stopped_at_debug_event();
#ifndef RPC_CLIENT
  // Pass the debug names to the kernel
  g_dbgmod.set_debug_names();
#endif
}

//--------------------------------------------------------------------------
// This code is compiled for local debuggers (like win32_user.plw)
#ifndef RPC_CLIENT

ssize_t dvmsg(int code, rpc_engine_t *, const char *format, va_list va)
{
  if ( code == 0 )
    return vmsg(format, va);
  if ( code > 0 )
    vwarning(format, va);
  else
    verror(format, va);
  return 0;
}

void dmsg(rpc_engine_t *rpc, const char *format, va_list va)
{
  dvmsg(0, rpc, format, va);
}

void derror(rpc_engine_t *rpc, const char *format, va_list va)
{
  dvmsg(-1, rpc, format, va);
}

void dwarning(rpc_engine_t *rpc, const char *format, va_list va)
{
  dvmsg(1, rpc, format, va);
}

#endif // end of 'local debugger' code

bool lock_begin(void)
{
  return true;
}

bool lock_end(void)
{
  return true;
}

//--------------------------------------------------------------------------
void report_idc_error(
        rpc_engine_t *,
        ea_t ea,
        error_t code,
        ssize_t errval,
        const char *errprm)
{
  // Copy errval/errprm to the locations expected by qstrerror()
  if ( errprm != NULL && errprm != get_error_string(0) )
    QPRM(1, errprm);
  else if ( code == eOS )
    errno = errval;
  else
    set_error_data(0, errval);

  warning("AUTOHIDE NONE\n%a: %s", ea, qstrerror(code));
}

//--------------------------------------------------------------------------
int for_all_debuggers(debmod_visitor_t &v)
{
  return v.visit(&g_dbgmod);
}

gdecode_t idaapi s_get_debug_event(debug_event_t *event, int timeout_ms)
{
  return g_dbgmod.dbg_get_debug_event(event, timeout_ms);
}

int idaapi s_write_register(thid_t tid, int reg_idx, const regval_t *value)
{
  return g_dbgmod.dbg_write_register(tid, reg_idx, value);
}

int idaapi s_read_registers(thid_t tid, int clsmask, regval_t *values)
{
  return g_dbgmod.dbg_read_registers(tid, clsmask, values);
}

int idaapi s_is_ok_bpt(bpttype_t type, ea_t ea, int len)
{
  return g_dbgmod.dbg_is_ok_bpt(type, ea, len);
}

int idaapi s_update_bpts(update_bpt_info_t *bpts, int nadd, int ndel)
{
  return g_dbgmod.dbg_update_bpts(bpts, nadd, ndel);
}

int idaapi s_update_lowcnds(const lowcnd_t *lowcnds, int nlowcnds)
{
  return g_dbgmod.dbg_update_lowcnds(lowcnds, nlowcnds);
}

int idaapi s_eval_lowcnd(thid_t tid, ea_t ea)
{
  return g_dbgmod.dbg_eval_lowcnd(tid, ea);
}

int idaapi s_get_processes(procinfo_vec_t *proclist)
{
  return g_dbgmod.dbg_get_processes(proclist);
}

void idaapi s_set_debugging(bool _debug_debugger)
{
  g_dbgmod.dbg_set_debugging(_debug_debugger);
}

int idaapi s_init(void)
{
  g_dbgmod.debugger_flags = debugger.flags;
  return g_dbgmod.dbg_init();
}

int idaapi s_attach_process(pid_t process_id, int event_id, int flags)
{
  int rc = g_dbgmod.dbg_attach_process(process_id, event_id, flags);
  return rc;
}

int idaapi s_detach_process(void)
{
  return g_dbgmod.dbg_detach_process();
}

int idaapi s_prepare_to_pause_process(void)
{
  return g_dbgmod.dbg_prepare_to_pause_process();
}

int idaapi s_exit_process(void)
{
  return g_dbgmod.dbg_exit_process();
}

int idaapi s_continue_after_event(const debug_event_t *event)
{
  return g_dbgmod.dbg_continue_after_event(event);
}

void idaapi s_set_exception_info(const exception_info_t *info, int qty)
{
  g_dbgmod.dbg_set_exception_info(info, qty);
}

int idaapi s_thread_suspend(thid_t thread_id)
{
  return g_dbgmod.dbg_thread_suspend(thread_id);
}

int idaapi s_thread_continue(thid_t thread_id)
{
  return g_dbgmod.dbg_thread_continue(thread_id);
}

int idaapi s_set_resume_mode(thid_t thread_id, resume_mode_t resmod)
{
  return g_dbgmod.dbg_set_resume_mode(thread_id, resmod);
}

ssize_t idaapi s_read_memory(ea_t ea, void *buffer, size_t size)
{
  return g_dbgmod.dbg_read_memory(ea, buffer, size);
}

ssize_t idaapi s_write_memory(ea_t ea, const void *buffer, size_t size)
{
  return g_dbgmod.dbg_write_memory(ea, buffer, size);
}

int idaapi s_thread_get_sreg_base(ea_t *ea, thid_t thread_id, int sreg_value)
{
  return g_dbgmod.dbg_thread_get_sreg_base(ea, thread_id, sreg_value);
}

ea_t idaapi s_map_address(ea_t ea, const regval_t *regs, int regnum)
{
  return g_dbgmod.map_address(ea, regs, regnum);
}

//---------------------------------------------------------------------------
int idaapi s_get_memory_info(meminfo_vec_t &ranges)
{
  return g_dbgmod.dbg_get_memory_info(ranges);
}

//---------------------------------------------------------------------------
int idaapi s_start_process(
        const char *path,
        const char *args,
        const char *startdir,
        int flags,
        const char *input_path,
        uint32 input_file_crc32)
{
  int rc = g_dbgmod.dbg_start_process(path,
                                      args,
                                      startdir,
                                      flags,
                                      input_path,
                                      input_file_crc32);
  return rc;
}

//--------------------------------------------------------------------------
int idaapi s_open_file(const char *file, uint64 *fsize, bool readonly)
{
  return g_dbgmod.dbg_open_file(file, fsize, readonly);
}

//--------------------------------------------------------------------------
void idaapi s_close_file(int fn)
{
  return g_dbgmod.dbg_close_file(fn);
}

//--------------------------------------------------------------------------
ssize_t idaapi s_read_file(int fn, qoff64_t off, void *buf, size_t size)
{
  return g_dbgmod.dbg_read_file(fn, off, buf, size);
}

//--------------------------------------------------------------------------
ssize_t idaapi s_write_file(int fn, qoff64_t off, const void *buf, size_t size)
{
  return g_dbgmod.dbg_write_file(fn, off, buf, size);
}

//--------------------------------------------------------------------------
bool idaapi s_update_call_stack(thid_t tid, call_stack_t *trace)
{
  return g_dbgmod.dbg_update_call_stack(tid, trace);
}

//--------------------------------------------------------------------------
ea_t idaapi s_appcall(
        ea_t func_ea,
        thid_t tid,
        const struct func_type_data_t *fti,
        int /*nargs*/,
        const struct regobjs_t *regargs,
        struct relobj_t *stkargs,
        struct regobjs_t *retregs,
        qstring *errbuf,
        debug_event_t *event,
        int flags)
{
  return g_dbgmod.dbg_appcall(func_ea,
                              tid,
                              fti->stkargs,
                              regargs,
                              stkargs,
                              retregs,
                              errbuf,
                              event,
                              flags);
}

//--------------------------------------------------------------------------
int idaapi s_cleanup_appcall(thid_t tid)
{
  return g_dbgmod.dbg_cleanup_appcall(tid);
}

//--------------------------------------------------------------------------
int idaapi s_ioctl(
        int fn,
        const void *buf,
        size_t size,
        void **poutbuf,
        ssize_t *poutsize)
{
  return g_dbgmod.handle_ioctl(fn, buf, size, poutbuf, poutsize);
}

//--------------------------------------------------------------------------
bool idaapi s_enable_trace(thid_t tid, bool enable, int tracebit)
{
  return g_dbgmod.dbg_enable_trace(tid, enable, tracebit);
}

//--------------------------------------------------------------------------
bool idaapi s_is_tracing_enabled(thid_t tid, int tracebit)
{
  return g_dbgmod.dbg_is_tracing_enabled(tid, tracebit);
}

//--------------------------------------------------------------------------
int idaapi s_rexec(const char *cmdline)
{
  return g_dbgmod.dbg_rexec(cmdline);
}

//--------------------------------------------------------------------------
void idaapi s_get_debapp_attrs(debapp_attrs_t *out_pattrs)
{
  g_dbgmod.dbg_get_debapp_attrs(out_pattrs);
}

//--------------------------------------------------------------------------
bool idaapi s_get_srcinfo_path(qstring *path, ea_t base)
{
  return g_dbgmod.dbg_get_srcinfo_path(path, base);
}

//--------------------------------------------------------------------------
#ifdef REMOTE_DEBUGGER
bool s_close_remote()
{
  return g_dbgmod.close_remote();
}
bool s_open_remote(const char *hostname, int port_number, const char *password)
{
  return g_dbgmod.open_remote(hostname, port_number, password);
}
#else
bool s_open_remote(const char *, int, const char *)
{
  return true;
}

bool s_close_remote(void)
{
  return true;
}

#endif

//--------------------------------------------------------------------------
// Local debuggers must call setup_lowcnd_regfuncs() in order to handle
// register read/write requests from low level bpts.
void init_dbg_idcfuncs(bool init)
{
#if !defined(ENABLE_LOWCNDS) ||                 \
     defined(REMOTE_DEBUGGER) ||                \
     DEBUGGER_ID == DEBUGGER_ID_X86_IA32_BOCHS
  qnotused(init);
#else
  setup_lowcnd_regfuncs(init ? idc_get_reg_value : NULL,
                        init ? idc_set_reg_value : NULL);
#endif
}
