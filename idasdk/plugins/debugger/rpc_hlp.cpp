
#include <pro.h>
#include <typeinf.hpp>
#include "rpc_hlp.h"
using namespace std;

//--------------------------------------------------------------------------
const char *get_rpc_name(int code)
{
  static const char *const names[] =
  {
    "RPC_OK",                       //  0
    "RPC_UNK",                      //  1
    "RPC_MEM",                      //  2
    "RPC_OPEN",                     //  3
    "RPC_EVENT",                    //  4
    "RPC_EVOK",                     //  5
    NULL,                           //  6
    NULL,                           //  7
    NULL,                           //  8
    NULL,                           //  9
    "RPC_INIT",                     // 10
    "RPC_TERM",                     // 11
    "RPC_GET_PROCESSES",            // 12
    "RPC_START_PROCESS",            // 13
    "RPC_EXIT_PROCESS",             // 14
    "RPC_ATTACH_PROCESS",           // 15
    "RPC_DETACH_PROCESS",           // 16
    "RPC_GET_DEBUG_EVENT",          // 17
    "RPC_PREPARE_TO_PAUSE_PROCESS", // 18
    "RPC_STOPPED_AT_DEBUG_EVENT",   // 19
    "RPC_CONTINUE_AFTER_EVENT",     // 20
    "RPC_TH_SUSPEND",               // 21
    "RPC_TH_CONTINUE",              // 22
    "RPC_SET_RESUME_MODE",          // 23
    "RPC_GET_MEMORY_INFO",          // 24
    "RPC_READ_MEMORY",              // 25
    "RPC_WRITE_MEMORY",             // 26
    "RPC_UPDATE_BPTS",              // 27
    "RPC_UPDATE_LOWCNDS",           // 28
    "RPC_EVAL_LOWCND",              // 29
    "RPC_ISOK_BPT",                 // 30
    "RPC_READ_REGS",                // 31
    "RPC_WRITE_REG",                // 32
    "RPC_GET_SREG_BASE",            // 33
    "RPC_SET_EXCEPTION_INFO",       // 34
    "RPC_OPEN_FILE",                // 35
    "RPC_CLOSE_FILE",               // 36
    "RPC_READ_FILE",                // 37
    "RPC_WRITE_FILE",               // 38
    "RPC_IOCTL",                    // 39
    "RPC_UPDATE_CALL_STACK",        // 40
    "RPC_APPCALL",                  // 41
    "RPC_CLEANUP_APPCALL",          // 42
    "RPC_REXEC",                    // 43
    NULL,                           // 44
    NULL,                           // 45
    NULL,                           // 46
    NULL,                           // 47
    NULL,                           // 48
    NULL,                           // 49
    "RPC_SET_DEBUG_NAMES",          // 50
    "RPC_SYNC_STUB",                // 51
    "RPC_ERROR",                    // 52
    "RPC_MSG",                      // 53
    "RPC_WARNING",                  // 54
    "RPC_HANDLE_DEBUG_EVENT",       // 55
    "RPC_REPORT_IDC_ERROR",         // 56
  };
  CASSERT(qnumber(names) == 57);

  const char *name = NULL;
  if ( uint(code) < qnumber(names) )
    name = names[code];
  if ( name == NULL )
  {
    static char buf[16];
    qsnprintf(buf, sizeof(buf), "RPC_%d", code);
    name = buf;
  }
  return name;
}

//--------------------------------------------------------------------------
void finalize_packet(bytevec_t &cmnd)
{
  rpc_packet_t *rp = (rpc_packet_t *)cmnd.begin();
  rp->length = qhtonl(uint32(cmnd.size() - sizeof(rpc_packet_t)));
}

//--------------------------------------------------------------------------
void append_memory_info(bytevec_t &s, const memory_info_t *meminf)
{
  append_ea64(s, meminf->sbase);
  append_ea64(s, meminf->start_ea - (meminf->sbase << 4));
  append_ea64(s, meminf->size());
  append_dd(s, meminf->perm | (meminf->bitness<<4));
  append_str(s, meminf->name.c_str());
  append_str(s, meminf->sclass.c_str());
}

//--------------------------------------------------------------------------
void extract_memory_info(const uchar **ptr, const uchar *end, memory_info_t *meminf)
{
  meminf->sbase    = extract_ea64(ptr, end);
  meminf->start_ea = (meminf->sbase << 4) + extract_ea64(ptr, end);
  meminf->end_ea   = meminf->start_ea + extract_ea64(ptr, end);
  int v = extract_long(ptr, end);
  meminf->perm    = uchar(v) & SEGPERM_MAXVAL;
  meminf->bitness = uchar(v>>4);
  meminf->name    = extract_str(ptr, end);
  meminf->sclass  = extract_str(ptr, end);
}

//--------------------------------------------------------------------------
void append_scattered_segm(bytevec_t &s, const scattered_segm_t *ss)
{
  append_ea64(s, ss->start_ea);
  append_ea64(s, ss->end_ea);
  append_str(s, ss->name.c_str());
}

//--------------------------------------------------------------------------
void extract_scattered_segm(const uchar **ptr, const uchar *end, scattered_segm_t *ss)
{
  ss->start_ea = extract_ea64(ptr, end);
  ss->end_ea = extract_ea64(ptr, end);
  ss->name = extract_str(ptr, end);
}

//--------------------------------------------------------------------------
void append_process_info_vec(bytevec_t &s, const procinfo_vec_t *procs)
{
  size_t size = procs->size();
  append_dd(s, size);
  for ( size_t i = 0; i < size; i++ )
  {
    const process_info_t &pi = procs->at(i);
    append_dd(s, pi.pid);
    append_str(s, pi.name.c_str());
  }
}

//--------------------------------------------------------------------------
void extract_process_info_vec(const uchar **ptr, const uchar *end, procinfo_vec_t *procs)
{
  size_t size = extract_long(ptr, end);
  for ( size_t i = 0; i < size; i++ )
  {
    process_info_t &pi = procs->push_back();
    pi.pid = extract_long(ptr, end);
    pi.name = extract_str(ptr, end);
  }
}

//--------------------------------------------------------------------------
void append_module_info(bytevec_t &s, const module_info_t *modinf)
{
  append_str(s, modinf->name);
  append_ea64(s, modinf->base);
  append_ea64(s, modinf->size);
  append_ea64(s, modinf->rebase_to);
}

//--------------------------------------------------------------------------
void extract_module_info(const uchar **ptr, const uchar *end, module_info_t *modinf)
{
  char *name = extract_str(ptr, end);
  modinf->base = extract_ea64(ptr, end);
  modinf->size = extract_ea64(ptr, end);
  modinf->rebase_to = extract_ea64(ptr, end);
  qstrncpy(modinf->name, name, sizeof(modinf->name));
}

//--------------------------------------------------------------------------
void append_exception(bytevec_t &s, const e_exception_t *e)
{
  append_dd(s, e->code);
  append_dd(s, e->can_cont);
  append_ea64(s, e->ea);
  append_str(s, e->info);
}

//--------------------------------------------------------------------------
void extract_exception(const uchar **ptr, const uchar *end, e_exception_t *exc)
{
  exc->code     = extract_long(ptr, end);
  exc->can_cont = extract_long(ptr, end) != 0;
  exc->ea       = extract_ea64(ptr, end);
  char *exinf   = extract_str(ptr, end);
  qstrncpy(exc->info, exinf, sizeof(exc->info));
}

//--------------------------------------------------------------------------
void extract_debug_event(const uchar **ptr, const uchar *end, debug_event_t *ev)
{
  ev->eid     = event_id_t(extract_long(ptr, end));
  ev->pid     = extract_long(ptr, end);
  ev->tid     = extract_long(ptr, end);
  ev->ea      = extract_ea64(ptr, end);
  ev->handled = extract_long(ptr, end) != 0;
  switch ( ev->eid )
  {
    case NO_EVENT:       // Not an interesting event
    case THREAD_START:   // New thread started
    case STEP:           // One instruction executed
    case SYSCALL:        // Syscall (not used yet)
    case WINMESSAGE:     // Window message (not used yet)
    case PROCESS_DETACH: // Detached from process
    default:
      break;
    case PROCESS_START:  // New process started
    case PROCESS_ATTACH: // Attached to running process
    case LIBRARY_LOAD:   // New library loaded
      extract_module_info(ptr, end, &ev->modinfo);
      break;
    case PROCESS_EXIT:   // Process stopped
    case THREAD_EXIT:    // Thread stopped
      ev->exit_code = extract_long(ptr, end);
      break;
    case BREAKPOINT:     // Breakpoint reached
      extract_breakpoint(ptr, end, &ev->bpt);
      break;
    case EXCEPTION:      // Exception
      extract_exception(ptr, end, &ev->exc);
      break;
    case LIBRARY_UNLOAD: // Library unloaded
    case INFORMATION:    // User-defined information
      qstrncpy(ev->info, extract_str(ptr, end), sizeof(ev->info));
      break;
  }
}

//--------------------------------------------------------------------------
void append_debug_event(bytevec_t &s, const debug_event_t *ev)
{
  append_dd(s, ev->eid);
  append_dd(s, ev->pid);
  append_dd(s, ev->tid);
  append_ea64  (s, ev->ea);
  append_dd(s, ev->handled);
  switch ( ev->eid )
  {
    case NO_EVENT:       // Not an interesting event
    case THREAD_START:   // New thread started
    case STEP:           // One instruction executed
    case SYSCALL:        // Syscall (not used yet)
    case WINMESSAGE:     // Window message (not used yet)
    case PROCESS_DETACH: // Detached from process
    default:
      break;
    case PROCESS_START:  // New process started
    case PROCESS_ATTACH: // Attached to running process
    case LIBRARY_LOAD:   // New library loaded
      append_module_info(s, &ev->modinfo);
      break;
    case PROCESS_EXIT:   // Process stopped
    case THREAD_EXIT:    // Thread stopped
      append_dd(s, ev->exit_code);
      break;
    case BREAKPOINT:     // Breakpoint reached
      append_breakpoint(s, &ev->bpt);
      break;
    case EXCEPTION:      // Exception
      append_exception(s, &ev->exc);
      break;
    case LIBRARY_UNLOAD: // Library unloaded
    case INFORMATION:    // User-defined information
      append_str(s, ev->info);
      break;
  }
}

//--------------------------------------------------------------------------
exception_info_t *extract_exception_info(
        const uchar **ptr,
        const uchar *end,
        int qty)
{
  exception_info_t *extable = NULL;
  if ( qty > 0 )
  {
    extable = OPERATOR_NEW(exception_info_t, qty);
    for ( int i=0; i < qty; i++ )
    {
      extable[i].code  = extract_long(ptr, end);
      extable[i].flags = extract_long(ptr, end);
      extable[i].name  = extract_str(ptr, end);
      extable[i].desc  = extract_str(ptr, end);
    }
  }
  return extable;
}

//--------------------------------------------------------------------------
void append_exception_info(bytevec_t &s, const exception_info_t *table, int qty)
{
  for ( int i=0; i < qty; i++ )
  {
    append_dd(s, table[i].code);
    append_dd(s, table[i].flags);
    append_str(s, table[i].name.c_str());
    append_str(s, table[i].desc.c_str());
  }
}

//--------------------------------------------------------------------------
void extract_call_stack(const uchar **ptr, const uchar *end, call_stack_t *trace)
{
  trace->dirty = false;
  int n = extract_long(ptr, end);
  trace->resize(n);
  for ( int i=0; i < n; i++ )
  {
    call_stack_info_t &ci = (*trace)[i];
    ci.callea = extract_ea64(ptr, end);
    ci.funcea = extract_ea64(ptr, end);
    ci.fp     = extract_ea64(ptr, end);
    ci.funcok = extract_long(ptr, end) != 0;
  }
}

//--------------------------------------------------------------------------
void append_call_stack(bytevec_t &s, const call_stack_t &trace)
{
  int n = trace.size();
  append_dd(s, n);
  for ( int i=0; i < n; i++ )
  {
    const call_stack_info_t &ci = trace[i];
    append_ea64(s, ci.callea);
    append_ea64(s, ci.funcea);
    append_ea64(s, ci.fp);
    append_dd(s, ci.funcok);
  }
}

//--------------------------------------------------------------------------
void extract_regobjs(
        const uchar **ptr,
        const uchar *end,
        regobjs_t *regargs,
        bool with_values)
{
  int n = extract_long(ptr, end);
  regargs->resize(n);
  for ( int i=0; i < n; i++ )
  {
    regobj_t &ro = (*regargs)[i];
    ro.regidx = extract_long(ptr, end);
    int size = extract_long(ptr, end);
    ro.value.resize(size);
    if ( with_values )
    {
      ro.relocate = extract_long(ptr, end);
      extract_memory(ptr, end, ro.value.begin(), size);
    }
  }
}

//--------------------------------------------------------------------------
static void extract_relobj(
        const uchar **ptr,
        const uchar *end,
        relobj_t *stkargs)
{
  int n = extract_long(ptr, end);
  stkargs->resize(n);
  extract_memory(ptr, end, stkargs->begin(), n);

  stkargs->base = extract_ea64(ptr, end);

  n = extract_long(ptr, end);
  stkargs->ri.resize(n);
  extract_memory(ptr, end, stkargs->ri.begin(), n);
}

//--------------------------------------------------------------------------
void extract_appcall(
        const uchar **ptr,
        const uchar *end,
        regobjs_t *regargs,
        relobj_t *stkargs,
        regobjs_t *retregs)
{
  extract_regobjs(ptr, end, regargs, true);
  extract_relobj(ptr, end, stkargs);
  if ( retregs != NULL )
    extract_regobjs(ptr, end, retregs, false);
}

//--------------------------------------------------------------------------
void append_regobjs(bytevec_t &s, const regobjs_t &regargs, bool with_values)
{
  append_dd(s, regargs.size());
  for ( size_t i=0; i < regargs.size(); i++ )
  {
    const regobj_t &ro = regargs[i];
    append_dd(s, ro.regidx);
    append_dd(s, ro.value.size());
    if ( with_values )
    {
      append_dd(s, ro.relocate);
      append_memory(s, ro.value.begin(), ro.value.size());
    }
  }
}

//--------------------------------------------------------------------------
static void append_relobj(bytevec_t &s, const relobj_t &stkargs)
{
  append_dd(s, stkargs.size());
  append_memory(s, stkargs.begin(), stkargs.size());

  append_ea64(s, stkargs.base);

  append_dd(s, stkargs.ri.size());
  append_memory(s, stkargs.ri.begin(), stkargs.ri.size());
}

//--------------------------------------------------------------------------
void append_appcall(
        bytevec_t &s,
        const regobjs_t &regargs,
        const relobj_t &stkargs,
        const regobjs_t *retregs)
{
  append_regobjs(s, regargs, true);
  append_relobj(s, stkargs);
  if ( retregs != NULL )
    append_regobjs(s, *retregs, false);
}

//--------------------------------------------------------------------------
static void append_regval(bytevec_t &s, const regval_t *value)
{
  append_dd(s, value->rvtype+2);
  if ( value->rvtype == RVT_INT )
  {
    append_dq(s, value->ival+1);
  }
  else if ( value->rvtype == RVT_FLOAT )
  {
    append_memory(s, value->fval, sizeof(value->fval));
  }
  else
  {
    const bytevec_t &b = value->bytes();
    append_dd(s, b.size());
    append_memory(s, b.begin(), b.size());
  }
}

//--------------------------------------------------------------------------
static void extract_regval(const uchar **ptr, const uchar *end, regval_t *value)
{
  value->clear();
  value->rvtype = extract_long(ptr, end) - 2;
  if ( value->rvtype == RVT_INT )
  {
    value->ival = unpack_dq(ptr, end) - 1;
  }
  else if ( value->rvtype == RVT_FLOAT )
  {
    extract_memory(ptr, end, value->fval, sizeof(value->fval));
  }
  else
  {
    bytevec_t &b = value->_set_bytes();
    int size = extract_long(ptr, end);
    b.resize(size);
    extract_memory(ptr, end, b.begin(), size);
  }
}

//--------------------------------------------------------------------------
void extract_regvals(
        const uchar **ptr,
        const uchar *end,
        regval_t *values,
        int n,
        const uchar *regmap)
{
  for ( int i=0; i < n && *ptr < end; i++ )
    if ( regmap == NULL || test_bit(regmap, i) )
      extract_regval(ptr, end, values+i);
}

//--------------------------------------------------------------------------
void append_regvals(bytevec_t &s, const regval_t *values, int n, const uchar *regmap)
{
  for ( int i=0; i < n; i++ )
    if ( regmap == NULL || test_bit(regmap, i) )
      append_regval(s, values+i);
}

//--------------------------------------------------------------------------
void extract_debapp_attrs(
        const uchar **ptr,
        const uchar *end,
        debapp_attrs_t *attrs)
{
  attrs->addrsize = extract_long(ptr, end);
  attrs->platform = extract_str(ptr, end);
}

//--------------------------------------------------------------------------
void append_debapp_attrs(bytevec_t &s, const debapp_attrs_t *attrs)
{
  append_dd(s, attrs->addrsize);
  append_str(s, attrs->platform.c_str());
}
