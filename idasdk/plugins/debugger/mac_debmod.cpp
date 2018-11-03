#include "mac_debmod.h"
#include "consts.h"
#include <sys/utsname.h>
#include <mach/mach_vm.h>
#include <crt_externs.h>
#include "../../ldr/mach-o/common.h"

#if defined (__i386__) || defined(__x86_64__)
#define THREAD_STATE_NONE 13
#else
#error unknown platform
#endif

#ifdef __EA64__
#define DEB_SEGM_BITNESS 2
#define VM_USRSTACK VM_USRSTACK64
#define COMMPAGE_START 0x7FFFFFE00000ull
#else
#define DEB_SEGM_BITNESS 1
#define VM_USRSTACK VM_USRSTACK32
#define COMMPAGE_START 0xFFFF0000ul
#endif

//#define DEBUG_MAC_DEBUGGER
#define local static  // static is used for static data items

#define BPT_CODE_SIZE X86_BPT_SIZE
static const uchar dyld_opcode[BPT_CODE_SIZE] = { 0x55 };

mac_debmod_t::stored_signals_t mac_debmod_t::pending_signals;

mac_debmod_t::mac_debmod_t() : reader(this)
{
  exc_port = MACH_PORT_NULL;
  set_platform("macosx");
  dyld = BADADDR;
  dyld_infos = BADADDR;
  dyld_ranges = BADADDR;
  is64 = false;
}

mac_debmod_t::~mac_debmod_t()
{
}

local asize_t calc_image_size(const char *fname, bool is64, ea_t *expected_base);

extern boolean_t exc_server(
        mach_msg_header_t *InHeadP,
        mach_msg_header_t *OutHeadP);

#define COMPLAIN_IF_FAILED(name)                        \
      if ( err != KERN_SUCCESS )                        \
        msg(name ": %s\n", mach_error_string(err))

//--------------------------------------------------------------------------
bool mac_debmod_t::get_thread_state(thid_t tid, machine_thread_state_t *state)
{
  if ( is64 )
  {
    x86_thread_state64_t _state;
    if ( get_thread_state64(tid, &_state) )
    {
      state->__eax    = _state.__rax;
      state->__ebx    = _state.__rbx;
      state->__ecx    = _state.__rcx;
      state->__edx    = _state.__rdx;
      state->__edi    = _state.__rdi;
      state->__esi    = _state.__rsi;
      state->__ebp    = _state.__rbp;
      state->__esp    = _state.__rsp;
      state->__eip    = _state.__rip;
      state->__r8     = _state.__r8;
      state->__r9     = _state.__r9;
      state->__r10    = _state.__r10;
      state->__r11    = _state.__r11;
      state->__r12    = _state.__r12;
      state->__r13    = _state.__r13;
      state->__r14    = _state.__r14;
      state->__r15    = _state.__r15;
      state->__eflags = _state.__rflags;
      state->__cs     = _state.__cs;
      state->__fs     = _state.__fs;
      state->__gs     = _state.__gs;
      return true;
    }
  }
  else
  {
    x86_thread_state32_t _state;
    if ( get_thread_state32(tid, &_state) )
    {
      state->__eax    = _state.__eax;
      state->__ebx    = _state.__ebx;
      state->__ecx    = _state.__ecx;
      state->__edx    = _state.__edx;
      state->__edi    = _state.__edi;
      state->__esi    = _state.__esi;
      state->__ebp    = _state.__ebp;
      state->__esp    = _state.__esp;
      state->__eip    = _state.__eip;
      state->__eflags = _state.__eflags;
      state->__ss     = _state.__ss;
      state->__cs     = _state.__cs;
      state->__ds     = _state.__ds;
      state->__es     = _state.__es;
      state->__fs     = _state.__fs;
      state->__gs     = _state.__gs;
      return true;
    }
  }
  return false;
}

//--------------------------------------------------------------------------
bool mac_debmod_t::set_thread_state(thid_t tid, const machine_thread_state_t *state)
{
  bool ok = false;
  if ( is64 )
  {
    x86_thread_state64_t _state;
    _state.__rax    = state->__eax;
    _state.__rbx    = state->__ebx;
    _state.__rcx    = state->__ecx;
    _state.__rdx    = state->__edx;
    _state.__rdi    = state->__edi;
    _state.__rsi    = state->__esi;
    _state.__rbp    = state->__ebp;
    _state.__rsp    = state->__esp;
    _state.__rip    = state->__eip;
    _state.__r8     = state->__r8;
    _state.__r9     = state->__r9;
    _state.__r10    = state->__r10;
    _state.__r11    = state->__r11;
    _state.__r12    = state->__r12;
    _state.__r13    = state->__r13;
    _state.__r14    = state->__r14;
    _state.__r15    = state->__r15;
    _state.__rflags = state->__eflags;
    _state.__cs     = state->__cs;
    _state.__fs     = state->__fs;
    _state.__gs     = state->__gs;
    ok = set_thread_state64(tid, &_state);
  }
  else
  {
    x86_thread_state32_t _state;
    _state.__eax    = state->__eax;
    _state.__ebx    = state->__ebx;
    _state.__ecx    = state->__ecx;
    _state.__edx    = state->__edx;
    _state.__edi    = state->__edi;
    _state.__esi    = state->__esi;
    _state.__ebp    = state->__ebp;
    _state.__esp    = state->__esp;
    _state.__eip    = state->__eip;
    _state.__eflags = state->__eflags;
    _state.__ss     = state->__ss;
    _state.__cs     = state->__cs;
    _state.__ds     = state->__ds;
    _state.__es     = state->__es;
    _state.__fs     = state->__fs;
    _state.__gs     = state->__gs;
    ok = set_thread_state32(tid, &_state);
  }
  return ok;
}

//--------------------------------------------------------------------------
bool mac_debmod_t::get_float_state(thid_t tid, machine_float_state_t *state)
{
#define GET_FLOAT_STATE_COMMON(s1, s2)                                     \
  do                                                                       \
  {                                                                        \
    s1->__fpu_fcw       = *(uint16*)&s2.__fpu_fcw;                         \
    s1->__fpu_fsw       = *(uint16*)&s2.__fpu_fsw;                         \
    s1->__fpu_ftw       = s2.__fpu_ftw;                                    \
    s1->__fpu_fop       = s2.__fpu_fop;                                    \
    s1->__fpu_ip        = s2.__fpu_ip;                                     \
    s1->__fpu_cs        = s2.__fpu_cs;                                     \
    s1->__fpu_dp        = s2.__fpu_dp;                                     \
    s1->__fpu_ds        = s2.__fpu_ds;                                     \
    s1->__fpu_mxcsr     = s2.__fpu_mxcsr;                                  \
    s1->__fpu_mxcsrmask = s2.__fpu_mxcsrmask;                              \
    /* __fpu_stmm0 thru __fpu_stmm7 */                                     \
    memcpy(&s1->__fpu_stmm0, &s2.__fpu_stmm0, sizeof(_STRUCT_MMST_REG)*8); \
    /* __fpu_xmm0 thru __fpu_xmm7 */                                       \
    memcpy(&s1->__fpu_xmm0, &s2.__fpu_xmm0, sizeof(_STRUCT_XMM_REG)*8);    \
  }                                                                        \
  while ( false )

  if ( is64 )
  {
    x86_float_state64_t _state;
    if ( get_float_state64(tid, &_state) )
    {
      GET_FLOAT_STATE_COMMON(state, _state);
      /* __fpu_xmm8 thru __fpu_xmm15 */
      memcpy(&state->__fpu_xmm8, &_state.__fpu_xmm8, sizeof(_STRUCT_XMM_REG)*8);
      return true;
    }
  }
  else
  {
    x86_float_state32_t _state;
    if ( get_float_state32(tid, &_state) )
    {
      GET_FLOAT_STATE_COMMON(state, _state);
      return true;
    }
  }
  return false;
}

//--------------------------------------------------------------------------
bool mac_debmod_t::set_float_state(thid_t tid, const machine_float_state_t *state)
{
#define SET_FLOAT_STATE_COMMON(s1, s2)                                     \
  do                                                                       \
  {                                                                        \
    *(uint16*)&s1.__fpu_fcw = s2->__fpu_fcw;                               \
    *(uint16*)&s1.__fpu_fsw = s2->__fpu_fsw;                               \
    s1.__fpu_ftw            = s2->__fpu_ftw;                               \
    s1.__fpu_fop            = s2->__fpu_fop;                               \
    s1.__fpu_ip             = s2->__fpu_ip;                                \
    s1.__fpu_cs             = s2->__fpu_cs;                                \
    s1.__fpu_dp             = s2->__fpu_dp;                                \
    s1.__fpu_ds             = s2->__fpu_ds;                                \
    s1.__fpu_mxcsr          = s2->__fpu_mxcsr;                             \
    s1.__fpu_mxcsrmask      = s2->__fpu_mxcsrmask;                         \
    /* __fpu_stmm0 thru __fpu_stmm7 */                                     \
    memcpy(&s1.__fpu_stmm0, &s2->__fpu_stmm0, sizeof(_STRUCT_MMST_REG)*8); \
    /* __fpu_xmm0 thru __fpu_xmm7 */                                       \
    memcpy(&s1.__fpu_xmm0, &s2->__fpu_xmm0, sizeof(_STRUCT_XMM_REG)*8);    \
  }                                                                        \
  while ( false )

  bool ok = false;
  if ( is64 )
  {
    x86_float_state64_t _state;
    SET_FLOAT_STATE_COMMON(_state, state);
    /* __fpu_xmm8 thru __fpu_xmm15 */
    memcpy(&_state.__fpu_xmm8, &state->__fpu_xmm8, sizeof(_STRUCT_XMM_REG)*8);
    ok = set_float_state64(tid, &_state);
  }
  else
  {
    x86_float_state32_t _state;
    SET_FLOAT_STATE_COMMON(_state, state);
    ok = set_float_state32(tid, &_state);
  }
  return ok;
}

//--------------------------------------------------------------------------
bool mac_debmod_t::get_debug_state(thid_t tid, machine_debug_state_t *state)
{
#if __DARWIN_UNIX03
#define DRNAME(name) __##name
#else
#define DRNAME(name) name
#endif

#define GETDRS(s1, s2)          \
  do                            \
  {                             \
    s1->__dr0 = s2.DRNAME(dr0); \
    s1->__dr1 = s2.DRNAME(dr1); \
    s1->__dr2 = s2.DRNAME(dr2); \
    s1->__dr3 = s2.DRNAME(dr3); \
    s1->__dr4 = s2.DRNAME(dr4); \
    s1->__dr5 = s2.DRNAME(dr5); \
    s1->__dr6 = s2.DRNAME(dr6); \
    s1->__dr7 = s2.DRNAME(dr7); \
  }                             \
  while ( false )

  if ( is64 )
  {
    x86_debug_state64_t _state;
    if ( get_debug_state64(tid, &_state) )
    {
      GETDRS(state, _state);
      return true;
    }
  }
  else
  {
    x86_debug_state32_t _state;
    if ( get_debug_state32(tid, &_state) )
    {
      GETDRS(state, _state);
      return true;
    }
  }
  return false;
}

//--------------------------------------------------------------------------
bool mac_debmod_t::set_debug_state(thid_t tid, const machine_debug_state_t *state)
{
#define SETDRS(s1, s2)          \
  do                            \
  {                             \
    s1.DRNAME(dr0) = s2->__dr0; \
    s1.DRNAME(dr1) = s2->__dr1; \
    s1.DRNAME(dr2) = s2->__dr2; \
    s1.DRNAME(dr3) = s2->__dr3; \
    s1.DRNAME(dr4) = s2->__dr4; \
    s1.DRNAME(dr5) = s2->__dr5; \
    s1.DRNAME(dr6) = s2->__dr6; \
    s1.DRNAME(dr7) = s2->__dr7; \
  }                             \
  while ( false )

  bool ok = false;
  if ( is64 )
  {
    x86_debug_state64_t _state;
    SETDRS(_state, state);
    ok = set_debug_state64(tid, &_state);
  }
  else
  {
    x86_debug_state32_t _state;
    SETDRS(_state, state);
    ok = set_debug_state32(tid, &_state);
  }
  return ok;
}

//--------------------------------------------------------------------------
local const char *get_ptrace_name(int request)
{
  switch ( request )
  {
    case PT_TRACE_ME:    return "PT_TRACE_ME";    /* child declares it's being traced */
    case PT_READ_I:      return "PT_READ_I";      /* read word in child's I space */
    case PT_READ_D:      return "PT_READ_D";      /* read word in child's D space */
    case PT_READ_U:      return "PT_READ_U";      /* read word in child's user structure */
    case PT_WRITE_I:     return "PT_WRITE_I";     /* write word in child's I space */
    case PT_WRITE_D:     return "PT_WRITE_D";     /* write word in child's D space */
    case PT_WRITE_U:     return "PT_WRITE_U";     /* write word in child's user structure */
    case PT_CONTINUE:    return "PT_CONTINUE";    /* continue the child */
    case PT_KILL:        return "PT_KILL";        /* kill the child process */
    case PT_STEP:        return "PT_STEP";        /* single step the child */
    case PT_ATTACH:      return "PT_ATTACH";      /* trace some running process */
    case PT_DETACH:      return "PT_DETACH";      /* stop tracing a process */
    case PT_SIGEXC:      return "PT_SIGEXC";      /* signals as exceptions for current_proc */
    case PT_THUPDATE:    return "PT_THUPDATE";    /* signal for thread# */
    case PT_ATTACHEXC:   return "PT_ATTACHEXC";   /* attach to running process with signal exception */
    case PT_FORCEQUOTA:  return "PT_FORCEQUOTA";  /* Enforce quota for root */
    case PT_DENY_ATTACH: return "PT_DENY_ATTACH";
  }
  return "?";
}

//--------------------------------------------------------------------------
int32 mac_debmod_t::qptrace(int request, pid_t _pid, caddr_t addr, int data)
{
  int32 code = ptrace(request, _pid, addr, data);
  int saved_errno = errno;
//  if ( (request == PT_CONTINUE || request == PT_STEP) && int(addr) == 1 )
//    addr = (caddr_t)get_ip(_pid);
  debdeb("%s(%u, 0x%p, 0x%X) => 0x%X", get_ptrace_name(request), _pid, addr, data, code);
  if ( code == -1 )
    deberr("");
  else
    debdeb("\n");
  errno = saved_errno;
  return code;
}

//--------------------------------------------------------------------------
ida_thread_info_t *mac_debmod_t::get_thread(thid_t tid)
{
  threads_t::iterator p = threads.find(tid);
  if ( p == threads.end() )
    return NULL;
  return &p->second;
}

//--------------------------------------------------------------------------
uval_t mac_debmod_t::get_dr(thid_t tid, int idx)
{
  machine_debug_state_t dr_regs;
  if ( !get_debug_state(tid, &dr_regs) )
    return 0;

  switch ( idx )
  {
    case 0:
      return dr_regs.__dr0;
    case 1:
      return dr_regs.__dr1;
    case 2:
      return dr_regs.__dr2;
    case 3:
      return dr_regs.__dr3;
    case 4:
      return dr_regs.__dr4;
    case 5:
      return dr_regs.__dr5;
    case 6:
      return dr_regs.__dr6;
    case 7:
      return dr_regs.__dr7;
  }

  return 0;
}

//--------------------------------------------------------------------------
static void set_dr(machine_debug_state_t &dr_regs, int idx, uval_t value)
{
  switch ( idx )
  {
    case 0:
      dr_regs.__dr0 = value;
      break;
    case 1:
      dr_regs.__dr1 = value;
      break;
    case 2:
      dr_regs.__dr2 = value;
      break;
    case 3:
      dr_regs.__dr3 = value;
      break;
    case 4:
      dr_regs.__dr4 = value;
      break;
    case 5:
      dr_regs.__dr5 = value;
      break;
    case 6:
      dr_regs.__dr6 = value;
      break;
    case 7:
      dr_regs.__dr7 = value;
      break;
  }
}

//--------------------------------------------------------------------------
bool mac_debmod_t::set_dr(thid_t tid, int idx, uval_t value)
{
  machine_debug_state_t dr_regs;

  if ( !get_debug_state(tid, &dr_regs) )
    return false;

  ::set_dr(dr_regs, idx, value);

  return set_debug_state(tid, &dr_regs);
}

//--------------------------------------------------------------------------
ea_t mac_debmod_t::get_ip(thid_t tid)
{
  machine_thread_state_t state;
  if ( !get_thread_state(tid, &state) )
    return BADADDR;
  return state.__eip;
}

//--------------------------------------------------------------------------
bool mac_debmod_t::qthread_setsinglestep(ida_thread_info_t &ti)
{
  machine_thread_state_t cpu;
  if ( !get_thread_state(ti.tid, &cpu) )
    return false;

  ti.asked_step = ti.single_step;
  int bit = ti.single_step ? EFLAGS_TRAP_FLAG : 0;
  if ( ((cpu.__eflags ^ bit) & EFLAGS_TRAP_FLAG) == 0 )
    return KERN_SUCCESS;

  if ( ti.single_step )
    cpu.__eflags |= EFLAGS_TRAP_FLAG;
  else
    cpu.__eflags &= ~EFLAGS_TRAP_FLAG;

  return set_thread_state(ti.tid, &cpu);
}

//--------------------------------------------------------------------------
void my_mach_msg_t::display(const char *header)
{
#ifdef DEBUG_MAC_DEBUGGER
  msg("%s\n", header);
  msg("         msgh_bits       : 0x%x\n", hdr.msgh_bits);
  msg("         msgh_size       : 0x%x\n", hdr.msgh_size);
  msg("         msgh_remote_port: %d\n", hdr.msgh_remote_port);
  msg("         msgh_local_port : %d\n", hdr.msgh_local_port);
  msg("         msgh_reserved   : %d\n", hdr.msgh_reserved);
  msg("         msgh_id         : 0x%x\n", hdr.msgh_id);
  if ( hdr.msgh_size > 24 )
  {
    const uint32 *buf = ((uint32 *) this) + 6;
    msg("         data            :");
    int cnt = hdr.msgh_size / 4 - 6;
    for ( int i=0; i < cnt; i++ )
      msg(" %08x", buf[i]);
    msg("\n");
  }
#else
  qnotused(header);
#endif
}

// this function won't be called but is declared to avoid linker complaints
kern_return_t catch_exception_raise_state(
        mach_port_t /*exception_port*/,
        exception_type_t /*exception*/,
        const exception_data_t /*code*/,
        mach_msg_type_number_t /*codeCnt*/,
        int * /*flavor*/,
        const thread_state_t /*old_state*/,
        mach_msg_type_number_t /*old_stateCnt*/,
        thread_state_t /*new_state*/,
        mach_msg_type_number_t * /*new_stateCnt*/)
{
  return KERN_FAILURE;
}

// this function won't be called but is declared to avoid linker complaints
kern_return_t catch_exception_raise_state_identity(
        mach_port_t /*exception_port*/,
        mach_port_t /*thread*/,
        mach_port_t /*task*/,
        exception_type_t /*exception*/,
        exception_data_t /*code*/,
        mach_msg_type_number_t /*codeCnt*/,
        int * /*flavor*/,
        thread_state_t /*old_state*/,
        mach_msg_type_number_t /*old_stateCnt*/,
        thread_state_t /*new_state*/,
        mach_msg_type_number_t * /*new_stateCnt*/)
{
  return KERN_FAILURE;
}

// this function will be called by exc_server()
// we use exc_server() for 2 things:
//      - to decode mach message and extract exception information
//      - to actually handle the exception when we resume execution

static bool parse_mach_message;
static bool mask_exception;
static mach_exception_info_t local_exinf;

kern_return_t catch_exception_raise(
        mach_port_t /*exception_port*/,
        mach_port_t thread,
        mach_port_t task,
        exception_type_t exception,
        exception_data_t code_vector,
        mach_msg_type_number_t code_count)
{
  if ( parse_mach_message )
  {
    local_exinf.task_port      = task;
    local_exinf.thread_port    = thread;
    local_exinf.exception_type = exception;
    local_exinf.exception_data = code_vector;
    local_exinf.data_count     = code_count;
    return KERN_SUCCESS;
  }

  // handle the exception for real
  if ( mask_exception )
    return KERN_SUCCESS;

  return KERN_FAILURE;
}

//--------------------------------------------------------------------------
int mac_debmod_t::handle_bpts(debug_event_t *event, bool asked_step)
{
  int code = SIGTRAP;

  // Check for hardware breakpoints first.
  // If we do not handle a hwbpt immediately, dr6 stays set and
  // we discover it later, after resuming. This breaks everything.
  ea_t bpt_ea = event->ea;
  uval_t dr6val = get_dr(event->tid, 6);
  for ( int i=0; i < MAX_BPT; i++ )
  {
    if ( (dr6val & (1<<i)) != 0 )  // Hardware breakpoint 'i'
    {
      if ( hwbpt_ea[i] == get_dr(event->tid, i) )
      {
        event->eid     = BREAKPOINT;
        event->bpt.hea = hwbpt_ea[i];
        event->bpt.kea = BADADDR;
        set_dr(event->tid, 6, 0); // Clear the status bits
        code = 0;
        break;
      }
    }
  }
  // x86 returns EIP pointing to the next byte after CC. Take it into account:
  bpt_ea--;
  if ( code != 0 )
  {
    if ( asked_step )
    {
      event->eid = STEP;
      code = 0;
    }
    else if ( bpts.find(bpt_ea) != bpts.end() )
    {
      event->eid     = BREAKPOINT;
      event->bpt.hea = BADADDR;
      event->bpt.kea = BADADDR;
      event->ea = bpt_ea;
      code = 0;
    }
  }
  return code;
}

//--------------------------------------------------------------------------
// event->tid is filled upon entry
// returns true: created a new event in 'event'
bool mac_debmod_t::handle_signal(
        int code,
        debug_event_t *event,
        block_type_t block,
        const my_mach_msg_t *excmsg)
{
  ida_thread_info_t *ti = get_thread(event->tid);
  if ( ti == NULL )
  { // there is a rare race condition when a thread gets created just after
    // last call to update_threads(). check it once more
    update_threads();
    ti = get_thread(event->tid);
  }
  QASSERT(30075, ti != NULL);

  ti->child_signum = 0;
  ti->block = block;
  if ( block == bl_exception )
    ti->excmsg = *excmsg;

  event->pid          = pid;
  event->handled      = false;
  event->ea           = get_ip(event->tid);
  event->eid          = EXCEPTION;
  event->exc.code     = code;
  event->exc.can_cont = true;
  event->exc.ea       = BADADDR;

  if ( code == SIGSTOP )
  {
    if ( ti->pending_sigstop )
    {
      debdeb("got pending SIGSTOP, good!\n");
      ti->pending_sigstop = false;
      if ( ti->asked_step )
      { // not to lose an asked single step, do it again
        ti->single_step = true;
        qthread_setsinglestep(*ti);
      }
      my_resume_thread(*ti);
      return false;
    }
    if ( run_state == rs_pausing )
    {
      debdeb("successfully paused the process, good!\n");
      run_state = rs_running;
      event->eid = NO_EVENT;
    }
  }
  if ( event->eid == EXCEPTION )
  {
    bool suspend;
    const exception_info_t *ei = find_exception(code);
    if ( ei != NULL )
    {
      qsnprintf(event->exc.info, sizeof(event->exc.info), "got %s signal (%s)", ei->name.c_str(), ei->desc.c_str());
      suspend = should_suspend_at_exception(event, ei);
      event->handled = ei->handle();
      if ( code == SIGKILL && run_state >= rs_exiting )
      {
        event->handled = false;
        suspend = false;
      }
    }
    else
    {
      qsnprintf(event->exc.info, sizeof(event->exc.info), "got unknown signal #%d", code);
      suspend = true;
    }

    if ( code == SIGTRAP )
      code = handle_bpts(event, ti->asked_step);

    ti->run_handled = event->handled;
    ti->child_signum = code;
    if ( run_state != rs_pausing && evaluate_and_handle_lowcnd(event) )
      return false;
    if ( !suspend && event->eid == EXCEPTION )
    {
      log_exception(event, ei);
      my_resume_thread(*ti);
      return false;
    }
  }
  return true;
}

//--------------------------------------------------------------------------
bool mac_debmod_t::check_for_exception(
        int timeout,
        mach_exception_info_t *exinf,
        my_mach_msg_t *excmsg)
{
  if ( exited() )
    return false;

  int flags = MACH_RCV_MSG;
  if ( timeout != -1 )
    flags |= MACH_RCV_TIMEOUT;
  else
    timeout = MACH_MSG_TIMEOUT_NONE;

//  msg("check for exception, timeout %d, runstate=%d\n", timeout, run_state);

  kern_return_t err = mach_msg(&excmsg->hdr,
                               flags,
                               0,               // send size
                               sizeof(my_mach_msg_t),
                               exc_port,
                               timeout,         // timeout
                               MACH_PORT_NULL); // notify port
  if ( err != MACH_MSG_SUCCESS )
    return false;
  if ( excmsg->hdr.msgh_remote_port == -1 ) // remote task alive?
    return false;
  task_suspend(task);
  excmsg->display("received an exception, details:");

  lock_begin();
  {
    my_mach_msg_t reply_msg;
    parse_mach_message = true;
    memset(&local_exinf, 0, sizeof(local_exinf));
    bool ok = exc_server(&excmsg->hdr, &reply_msg.hdr);
    QASSERT(30076, ok);
    *exinf = local_exinf;
  }
  lock_end();
  return true;
}

//--------------------------------------------------------------------------
bool mac_debmod_t::my_resume_thread(ida_thread_info_t &ti)
{
  bool ok = true;

  // setsinglestep may fail after kill(), ignore the return code
  qthread_setsinglestep(ti);

  if ( ti.run_handled )
    ti.child_signum = 0;

  switch ( ti.block )
  {
    case bl_signal:
      if ( in_ptrace )
      {
        // we detach from the process and will handle the rest
        // using mach api
        int pt = ti.single_step ? PT_STEP : PT_CONTINUE;
        ok = qptrace(pt, pid, caddr_t(1), ti.child_signum) == 0;
      }
      else
      {
        kern_return_t err = thread_resume(ti.tid);
        COMPLAIN_IF_FAILED("thread_resume");
      }
      break;

    case bl_exception:
      // handle the exception with exc_server
      my_mach_msg_t reply_msg;
      lock_begin();
      {
        parse_mach_message = false;
        mask_exception = ti.child_signum == 0;
        ok = exc_server(&ti.excmsg.hdr, &reply_msg.hdr);
      }
      lock_end();

      if ( ok )
      {
        kern_return_t err;
        err = mach_msg(&reply_msg.hdr,
                       MACH_SEND_MSG,
                       reply_msg.hdr.msgh_size, // send size
                       0,
                       reply_msg.hdr.msgh_remote_port,
                       0,                  // timeout
                       MACH_PORT_NULL); // notify port
        COMPLAIN_IF_FAILED("mach_msg");
        ok = (err == KERN_SUCCESS);
      }
      task_resume(task);
      break;

    default:  // nothing to do, the process is already running
      break;
  }
  // syscalls may fail after SIGKILL, do not check the error code
  //QASSERT(30077, ok);
  ti.block = bl_none;
  ti.single_step = false;
  return true;
}

//--------------------------------------------------------------------------
int mac_debmod_t::exception_to_signal(const mach_exception_info_t *exinf)
{
  int code = exinf->exception_data[0];
  int sig = 0;
  switch ( exinf->exception_type )
  {
    case EXC_BAD_ACCESS:
      if ( code == KERN_INVALID_ADDRESS )
        sig = SIGSEGV;
      else
        sig = SIGBUS;
      break;

    case EXC_BAD_INSTRUCTION:
      sig = SIGILL;
      break;

    case EXC_ARITHMETIC:
      sig = SIGFPE;
      break;

    case EXC_EMULATION:
      sig = SIGEMT;
      break;

    case EXC_SOFTWARE:
      switch ( code )
      {
//        case EXC_UNIX_BAD_SYSCALL:
//          sig = SIGSYS;
//          break;
//        case EXC_UNIX_BAD_PIPE:
//          sig = SIGPIPE;
//          break;
//        case EXC_UNIX_ABORT:
//          sig = SIGABRT;
//          break;
        case EXC_SOFT_SIGNAL:
          sig = SIGKILL;
          break;
      }
      break;

    case EXC_BREAKPOINT:
      sig = SIGTRAP;
      break;
    case EXC_CRASH:
      sig = SIGABRT;
      break;
  }
  return sig;
}

//--------------------------------------------------------------------------
// check if there are any pending signals
bool mac_debmod_t::retrieve_pending_signal(int *status)
{
  bool has_pending_signal = false;
  if ( !pending_signals.empty() )
  {
    lock_begin();
    for ( stored_signals_t::iterator p=pending_signals.begin();
          p != pending_signals.end();
          ++p )
    {
      if ( p->pid == pid )
      {
        *status = p->status;
        pending_signals.erase(p);
        has_pending_signal = true;
        break;
      }
    }
    lock_end();
  }

  return has_pending_signal;
}

//--------------------------------------------------------------------------
pid_t mac_debmod_t::qwait(int *status, bool hang)
{
  pid_t ret;
  lock_begin();
  if ( retrieve_pending_signal(status) )
  {
    ret = pid;
  }
  else
  {
    int flags = hang ? 0 : WNOHANG;
    ret = ::qwait(status, pid, flags);
    if ( ret != pid && ret != 0 && ret != -1 )
    {
      stored_signal_t &ss = pending_signals.push_back();
      ss.pid = pid;
      ss.status = *status;
    }
  }
  lock_end();
  return ret;
}

//--------------------------------------------------------------------------
// timeout in milliseconds
// 0 - no timeout, return immediately
// -1 - wait forever
void mac_debmod_t::get_debug_events(int timeout_ms)
{
//  msg("waiting, numpend=%lu timeout=%d...\n", events.size(), timeout_ms);
//  for ( threads_t::iterator p=threads.begin(); p != threads.end(); ++p )
//    if ( p->second.blocked() )
//      msg("%d: blocked\n", p->first);

  int status;
  debug_event_t event;
  if ( !retrieve_pending_signal(&status) )
  {
    update_threads();

    // receive info about any exceptions in the program
    // an arbitrary limit of 32 loop iterations is needed if low level breakpoints
    // or automatically handled exceptions occur too often.
    my_mach_msg_t excmsg;
    mach_exception_info_t exinf;
    for ( int i=0;
          i < 32 && check_for_exception(timeout_ms, &exinf, &excmsg);
          i++ )
    {
      event.tid = exinf.thread_port;
      int sig = exception_to_signal(&exinf);
      debdeb("got exception for tid=%d sig=%d %s\n", event.tid, sig, strsignal(sig));
      if ( handle_signal(sig, &event, bl_exception, &excmsg) )
      {
        events.enqueue(event, IN_BACK);
        // do not break!
        // collect all exceptions and convert them to debug_event_t
        // if there was a breakpoint hit, convert it to debug_event_t as soon as
        // possible. if we pass control to the ida kernel, it may remove the
        // breakpoint and we won't recognize our breakpoint in the exception.
        // break;
      }
      timeout_ms = 0;
    }
    if ( !events.empty() )
      return;

    // check the signals
    pid_t wpid = qwait(&status, false);
    if ( wpid == -1 || wpid == 0 )
      return;
  }

  event.tid = maintid();
  if ( WIFSTOPPED(status) )
  {
    int code = WSTOPSIG(status);
    debdeb("SIGNAL %d: %s (stopped)\n", code, strsignal(code));
    if ( !handle_signal(code, &event, bl_signal, NULL) )
      return;
  }
  else
  {
    if ( WIFSIGNALED(status) )
    {
//      msg("SIGNAL: %s (terminated)\n", strsignal(WSTOPSIG(status)));
      event.exit_code = WSTOPSIG(status);
    }
    else
    {
//      msg("SIGNAL: %d (exited)\n", WEXITSTATUS(status));
      event.exit_code = WEXITSTATUS(status);
    }
    event.pid     = pid;
    event.ea      = BADADDR;
    event.handled = true;
    event.eid     = PROCESS_EXIT;
    run_state = rs_exited;
  }
//  msg("low got event: %s\n", debug_event_str(&event));
  events.enqueue(event, IN_BACK);
}

//--------------------------------------------------------------------------
void mac_debmod_t::handle_dyld_bpt(const debug_event_t *event)
{
  dmsg("handle dyld bpt, ea=%a\n", event->ea);
  update_dyld();

  machine_thread_state_t state;
  bool ok = get_thread_state(event->tid, &state);
  QASSERT(30078, ok);

  // emulate push ebp
  state.__esp -= debapp_attrs.addrsize;
  kern_return_t err = write_mem(state.__esp, &state.__ebp, debapp_attrs.addrsize);
  QASSERT(30080, err == KERN_SUCCESS);

  ok = set_thread_state(event->tid, &state);
  QASSERT(30081, ok);

  dbg_continue_after_event(event);
}

//--------------------------------------------------------------------------
gdecode_t idaapi mac_debmod_t::dbg_get_debug_event(debug_event_t *event, int timeout_ms)
{
  while ( true )
  {
    // are there any pending events?
    if ( events.retrieve(event) )
    {
      switch ( event->eid )
      {
        // if this is dyld bpt, do not return it to ida
        case BREAKPOINT:
          if ( event->ea == dyri.dyld_notify )
          {
            handle_dyld_bpt(event);
            continue;
          }
          break;

        case PROCESS_ATTACH:
          attaching = false;        // finally attached to it
          break;

        case THREAD_EXIT:           // thread completely disappeared,
                                    // can remove it from the list
          threads.erase(event->tid);
          break;

        default:
          break;
      }
      last_event = *event;
      if ( debug_debugger )
        debdeb("GDE1: %s\n", debug_event_str(event));
      return events.empty() ? GDE_ONE_EVENT : GDE_MANY_EVENTS;
    }

    if ( exited() )
      break;

    get_debug_events(timeout_ms);
    if ( events.empty() )
      break;
  }
  return GDE_NO_EVENT;
}

//--------------------------------------------------------------------------
bool mac_debmod_t::suspend_all_threads(void)
{
  /* Suspend the target process */
  kern_return_t err = task_suspend(task);
  return err == KERN_SUCCESS;
}

//--------------------------------------------------------------------------
void mac_debmod_t::resume_all_threads()
{
  kern_return_t err = task_resume(task);
  QASSERT(30082, err == KERN_SUCCESS);
}

//--------------------------------------------------------------------------
void mac_debmod_t::unblock_all_threads(void)
{
  for ( threads_t::iterator p=threads.begin(); p != threads.end(); ++p )
    my_resume_thread(p->second);
}

//--------------------------------------------------------------------------
int mac_debmod_t::dbg_freeze_threads_except(thid_t tid)
{
  for ( threads_t::iterator p=threads.begin(); p != threads.end(); ++p )
  {
    if ( p->first != tid )
    {
      kern_return_t err = thread_suspend(p->first);
      if ( err != KERN_SUCCESS )
        return 0;
    }
  }
  return 1;
}

//--------------------------------------------------------------------------
int mac_debmod_t::dbg_thaw_threads_except(thid_t tid)
{
  for ( threads_t::iterator p=threads.begin(); p != threads.end(); ++p )
  {
    if ( p->first != tid )
    {
      kern_return_t err = thread_resume(p->first);
      if ( err != KERN_SUCCESS )
      {
        if ( err == KERN_FAILURE )
          debdeb("Thread %d has suspend count of 0!\n", p->first);
        else if ( err == KERN_INVALID_ARGUMENT )
          debdeb("Invalid thread id %d passed\n", p->first);
        return 0;
      }
    }
  }
  return 1;
}

//--------------------------------------------------------------------------
// 1-ok, 0-failed
int idaapi mac_debmod_t::dbg_continue_after_event(const debug_event_t *event)
{
  if ( exited() )
  { // reap the last child status
    if ( pid != -1 )
    {
      debdeb("%d: reaping the child status\n", pid);
      int status;
      qwait(&status, true);
      pid = -1;
    }
    return true;
  }

  if ( event == NULL )
    return 0;

  ida_thread_info_t *ti = get_thread(event->tid);
  if ( ti != NULL )
    ti->run_handled = event->eid != EXCEPTION || event->handled;

  if ( debug_debugger )
  {
    debdeb("continue after event %s (%d pending, block type %d, sig#=%d,%shandled)\n",
           debug_event_str(event),
           int(events.size()),
           ti == NULL ? 0 : ti->block,
           ti == NULL ? 0 : ti->child_signum,
           ti != NULL && !ti->run_handled ? "un" : "");
  }

  if ( events.empty() && !attaching )
  {
    // if the event queue is empty, we can resume all blocked threads
    // here we resume only the threads blocked because of exceptions or signals
    // if the debugger kernel has suspended a thread for another reason, it
    // will stay suspended.
    if ( run_state == rs_pausing )
    { // no need to stop anymore, plan to ignore the sigstop
      ti->pending_sigstop = true;
      run_state = rs_running;
    }
    unblock_all_threads();
  }
  return 1;
}

//--------------------------------------------------------------------------
kern_return_t mac_debmod_t::read_mem(ea_t ea, void *buffer, int size, int *read_size)
{
  mach_vm_size_t data_count = 0;
  kern_return_t err = mach_vm_read_overwrite(task, ea, size, (vm_address_t)buffer, &data_count);
  if ( err != KERN_SUCCESS )
    debdeb("vm_read %d: ea=%a size=%d => (%s)\n", task, ea, size, mach_error_string(err));
//  show_hex(buffer, size, "data:\n");
  if ( read_size != NULL )
    *read_size = data_count;
  return err;
}

//--------------------------------------------------------------------------
kern_return_t mac_debmod_t::write_mem(ea_t ea, void *buffer, int size)
{
  kern_return_t err;
/*  vm_machine_attribute_val_t flush = MATTR_VAL_CACHE_FLUSH;
printf("buffer=%x size=%x\n", buffer, size);
  err = vm_machine_attribute (mach_task_self(), (vm_offset_t)buffer, size, MATTR_CACHE, &flush);
  QASSERT(30084, err == KERN_SUCCESS); // must succeed since it is our memory
*/
  err = mach_vm_write(task, ea, (vm_offset_t)buffer, size);
  if ( err != KERN_SUCCESS && err != KERN_PROTECTION_FAILURE )
    debdeb("vm_write %d: ea=%a, size=%d => %s\n", task, ea, size, mach_error_string(err));
  return err;
}

//--------------------------------------------------------------------------
bool mac_debmod_t::xfer_page(ea_t ea, void *buffer, int size, bool write)
{
  // get old memory protection
  mach_vm_address_t r_start = ea;
  mach_vm_size_t r_size;
  mach_port_t r_object_name;
  vm_region_basic_info_data_64_t r_data;
  mach_msg_type_number_t r_info_size = VM_REGION_BASIC_INFO_COUNT_64;
  kern_return_t err = mach_vm_region(task, &r_start, &r_size,
                                VM_REGION_BASIC_INFO_64,
                                (vm_region_info_t)&r_data, &r_info_size,
                                &r_object_name);
  if ( err != KERN_SUCCESS )
  {
    // this call fails for the commpage segment
    debdeb("%" FMT_64 "x: vm_region: %s\n", r_start, mach_error_string(err));
    return false;
  }

  if ( r_start > ea )
  {
    dmsg("%a: region start is higher %" FMT_64 "x\n", ea, r_start);
    return false;
  }

//  dmsg("%a: current=%d max=%d\n", ea, r_data.protection, r_data.max_protection);
  int bit = write ? VM_PROT_WRITE : VM_PROT_READ;
  // max permissions do not allow it? fail
  // strangely enough the kernel allows us to set any protection,
  // including protections bigger than max_protection. but after that it crashes
  // we have to verify it ourselves here.
  if ( (r_data.max_protection & bit) == 0 )
    return false;

  if ( (r_data.protection & bit) == 0 )
  {
    bit |= r_data.protection;
    // set the desired bit
    err = KERN_FAILURE;
    if ( write )
    {
      err = mach_vm_protect(task, r_start, r_size, 0, bit);
      if ( err != KERN_SUCCESS && (bit & VM_PROT_COPY) == 0 )
      {
        bit |= VM_PROT_COPY; // if failed, make a copy of the page
        goto LASTPROT;
      }
    }
    else
    {
LASTPROT:
      err = mach_vm_protect(task, r_start, r_size, 0, bit);
    }
    if ( err != KERN_SUCCESS )
    {
      debdeb("%d: could not set %s permission at %" FMT_64 "x\n",
                        task, write ? "write" : "read", r_start);
      return false;
    }
  }

  // attempt to xfer
  if ( write )
    err = write_mem(ea, buffer, size);
  else
    err = read_mem(ea, buffer, size, NULL);

  bool ok = (err == KERN_SUCCESS);
#if 1
  if ( ok && write )
  {
    // flush the cache
//    vm_machine_attribute_val_t flush = MATTR_VAL_CACHE_FLUSH;
    vm_machine_attribute_val_t flush = MATTR_VAL_OFF;
    err = mach_vm_machine_attribute(task, r_start, r_size, MATTR_CACHE, &flush);
    if ( err != KERN_SUCCESS )
    {
      static bool complained = false;
      if ( !complained )
      {
        complained = true;
        dmsg("Unable to flush data/instruction cache ea=0x%" FMT_64 "x size=%ld: %s\n",
                        r_start, long(r_size), mach_error_string(err));
      }
    }
    else
    {
//      msg("Success cache ea=0x%" FMT_64 "x size=%d\n", r_start, r_size);
    }
  }
#endif
  // restore old memory protection
  if ( (r_data.protection & bit) == 0 )
  {
    err = mach_vm_protect(task, r_start, r_size, 0, r_data.protection);
    QASSERT(30085, err == KERN_SUCCESS);
  }
  return ok;
}

//--------------------------------------------------------------------------
bool mac_debmod_t::xfer_memory(ea_t ea, void *buffer, int size, bool write)
{
  return xfer_page(ea, buffer, size, write);
}

//--------------------------------------------------------------------------
int mac_debmod_t::_read_memory(ea_t ea, void *buffer, int size, bool suspend)
{
  if ( exited() || pid <= 0 || size <= 0 )
    return -1;

//  debdeb("READ MEMORY %a:%d: START\n", ea, size);
  // stop all threads before accessing the process memory
  if ( suspend && !suspend_all_threads() )
    return -1;
  if ( exited() )
    return -1;

//  bool ok = xfer_memory(ea, buffer, size, false);
  int read_size;
  kern_return_t err = read_mem(ea, buffer, size, &read_size);
  bool ok = err == KERN_SUCCESS;

  if ( suspend )
    resume_all_threads();
//  debdeb("READ MEMORY %a:%d: END\n", ea, size);
  return ok ? read_size : 0;
}

//--------------------------------------------------------------------------
int mac_debmod_t::_write_memory(ea_t ea, const void *buffer, int size, bool suspend)
{
  if ( exited() || pid <= 0 || size <= 0 )
    return -1;

  // stop all threads before accessing the process memory
  if ( suspend && !suspend_all_threads() )
    return -1;
  if ( exited() )
    return -1;

  bool ok = xfer_memory(ea, (void*)buffer, size, true);

  if ( suspend )
    resume_all_threads();

  return ok ? size : 0;
}

//--------------------------------------------------------------------------
ssize_t idaapi mac_debmod_t::dbg_write_memory(ea_t ea, const void *buffer, size_t size)
{
  return _write_memory(ea, buffer, size, true);
}

//--------------------------------------------------------------------------
ssize_t idaapi mac_debmod_t::dbg_read_memory(ea_t ea, void *buffer, size_t size)
{
  return _read_memory(ea, buffer, size, true);
}

//--------------------------------------------------------------------------
void mac_debmod_t::add_dll(ea_t addr, const char *fname)
{
  asize_t size = calc_image_size(fname, is64, NULL);

  debug_event_t ev;
  ev.eid     = LIBRARY_LOAD;
  ev.pid     = pid;
  ev.tid     = maintid();
  ev.ea      = addr;
  ev.handled = true;
  qstrncpy(ev.modinfo.name, fname, sizeof(ev.modinfo.name));
  ev.modinfo.base = addr;
  ev.modinfo.size = size;
  ev.modinfo.rebase_to = BADADDR;
  if ( is_dll && stricmp(fname, input_file_path.c_str()) == 0 )
    ev.modinfo.rebase_to = addr;
  events.enqueue(ev, IN_FRONT);

  image_info_t ii(addr, size, fname);
  dlls.insert(std::make_pair(addr, ii));
  dlls_to_import.insert(addr);
}

//--------------------------------------------------------------------------
inline bool is_zeropage(const segment_command &sg)
{
  return sg.vmaddr == 0 && sg.fileoff == 0 && sg.initprot == 0;
}

//--------------------------------------------------------------------------
inline bool is_text_segment(const segment_command &sg)
{
  if ( is_zeropage(sg) )
    return false;
  const char *name = sg.segname;
  for ( int i=0; i < sizeof(sg.segname); i++, name++ )
    if ( *name != '_' )
      break;
  return strnicmp(name, "TEXT", 4) == 0;
}

//--------------------------------------------------------------------------
local asize_t calc_image_size(const char *fname, bool is64, ea_t *p_base)
{
  if ( p_base != NULL )
    *p_base = BADADDR;
  linput_t *li = open_linput(fname, false);
  if ( li == NULL )
    return 0;

  asize_t size = calc_macho_image_size_pc(li, is64, p_base);
  close_linput(li);
  return size;
}

//--------------------------------------------------------------------------
void mac_debmod_t::import_dll_to_database(ea_t imagebase)
{
  images_t::iterator p = dlls.find(imagebase);
  if ( p == dlls.end() )
    return;

  struct ida_local macho_importer_t : public macho_visitor_t
  {
    mac_debmod_t *md;
    macho_importer_t(mac_debmod_t *_md) : macho_visitor_t(MV_SYMBOLS), md(_md) {}
    void visit_symbol(ea_t ea, const char *name)
    {
      md->save_debug_name(ea, name);

#define HANDLE_DYLD_SYMBOL(varname, symname)                  \
      do                                                      \
      {                                                       \
        if ( md->varname == BADADDR && streq(name, symname) ) \
        {                                                     \
          md->dmsg("%a: address of " symname "\n", ea);       \
          md->varname = ea;                                   \
        }                                                     \
      }                                                       \
      while ( false )

      HANDLE_DYLD_SYMBOL(dyld_infos,  "_dyld_all_image_infos");
      HANDLE_DYLD_SYMBOL(dyld_ranges, "_dyld_shared_cache_ranges");

#undef HANDLE_DYLD_SYMBOL
    }
  };

  macho_importer_t mi(this);
  parse_macho_image(mi, p->second);
}

//--------------------------------------------------------------------------
void idaapi mac_debmod_t::dbg_stopped_at_debug_event(void)
{
  // we will take advantage of this event to import information
  // about the exported functions from the loaded dlls
  for ( easet_t::iterator p=dlls_to_import.begin(); p != dlls_to_import.end(); )
  {
    import_dll_to_database(*p);
    dlls_to_import.erase(p++);
  }
}

//--------------------------------------------------------------------------
void mac_debmod_t::cleanup(void)
{
  pid = 0;
  is_dll = false;
  run_state = rs_exited;
  dyld = BADADDR;
  dyld_infos = BADADDR;
  dyld_ranges = BADADDR;
  dyri.version = 0;  // not inited
  term_exception_ports();

  threads.clear();
  dlls.clear();
  dlls_to_import.clear();
  events.clear();
  attaching = false;
  is64 = false;

  bpts.clear();
  shared_cache_ranges.clear();

  inherited::cleanup();
}

//--------------------------------------------------------------------------
//
//      DEBUGGER INTERFACE FUNCTIONS
//
//--------------------------------------------------------------------------
bool mac_debmod_t::thread_exit_event_planned(thid_t tid)
{
  for ( eventlist_t::iterator p=events.begin(); p != events.end(); ++p )
  {
    if ( p->eid == THREAD_EXIT && p->tid == tid )
      return true;
  }
  return false;
}

//--------------------------------------------------------------------------
bool mac_debmod_t::update_threads(void)
{
  bool generated_events = false;
  thread_act_port_array_t threadList;
  mach_msg_type_number_t threadCount;
  kern_return_t err = task_threads(task, &threadList, &threadCount);
  std::set<int> live_tids;
  if ( err == KERN_SUCCESS )
  {
    QASSERT(30089, threadCount > 0);
    for ( int i=0; i < threadCount; i++ )
    {
      mach_port_t port = threadList[i];
      int tid = port;
      threads_t::iterator p = threads.find(tid);
      if ( p == threads.end() )
      {
        debug_event_t ev;
        ev.eid     = THREAD_START;
        ev.pid     = pid;
        ev.tid     = tid;
        ev.ea      = BADADDR;
        ev.handled = true;
        events.enqueue(ev, IN_FRONT);
        threads.insert(std::make_pair(tid, ida_thread_info_t(tid, port)));
        generated_events = true;
      }
      live_tids.insert(tid);
    }
    err = mach_vm_deallocate (mach_task_self(), (vm_address_t)threadList, threadCount * sizeof (thread_t));
    QASSERT(30090, err == KERN_SUCCESS);
    // remove dead threads
    for ( threads_t::iterator p=threads.begin(); p != threads.end(); ++p )
    {
      thid_t tid = p->first;
      if ( live_tids.find(tid) == live_tids.end() && !thread_exit_event_planned(tid) )
      {
        debug_event_t ev;
        ev.eid     = THREAD_EXIT;
        ev.pid     = pid;
        ev.tid     = tid;
        ev.ea      = BADADDR;
        ev.handled = true;
        events.enqueue(ev, IN_BACK);
        generated_events = true;
      }
    }
  }
  return generated_events;
}

//--------------------------------------------------------------------------
thid_t mac_debmod_t::init_main_thread(bool reattaching)
{
  thread_act_port_array_t threadList;
  mach_msg_type_number_t threadCount;
  kern_return_t err = task_threads(task, &threadList, &threadCount);
  QASSERT(30091, err == KERN_SUCCESS);
  QASSERT(30092, threadCount > 0);
  mach_port_t port = threadList[0]; // the first thread is the main thread
  thid_t tid = port;
  if ( !reattaching )
  {
    threads.insert(std::make_pair(tid, ida_thread_info_t(tid, port)));
    threads.begin()->second.block = bl_signal;
  }
  err = mach_vm_deallocate(mach_task_self(), (vm_address_t)threadList, threadCount * sizeof(thread_t));
  QASSERT(30093, err == KERN_SUCCESS);
  return tid;
}

//--------------------------------------------------------------------------
local kern_return_t save_exception_ports(task_t task, mach_exception_port_info_t *info)
{
  info->count = (sizeof (info->ports) / sizeof (info->ports[0]));
  return task_get_exception_ports(task,
                                  EXC_MASK_ALL,
                                  info->masks,
                                  &info->count,
                                  info->ports,
                                  info->behaviors,
                                  info->flavors);
}

//-------------------------------------------------------------------------
local kern_return_t restore_exception_ports(task_t task, const mach_exception_port_info_t *info)
{
  kern_return_t err = KERN_SUCCESS;
  for ( int i = 0; i < info->count; i++ )
  {
    err = task_set_exception_ports(task,
                                   info->masks[i],
                                   info->ports[i],
                                   info->behaviors[i],
                                   info->flavors[i]);
    if ( err != KERN_SUCCESS )
      break;
  }
  return err;
}

//-------------------------------------------------------------------------
void mac_debmod_t::init_exception_ports(void)
{
  kern_return_t err;

  // allocate a new port to receive exceptions
  err = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &exc_port);
  QASSERT(30094, err == KERN_SUCCESS);

  // add the 'send' right to send replies to threads
  err = mach_port_insert_right(mach_task_self(), exc_port, exc_port, MACH_MSG_TYPE_MAKE_SEND);
  QASSERT(30095, err == KERN_SUCCESS);

  // save old exception ports
  err = save_exception_ports(task, &saved_exceptions);
  QASSERT(30096, err == KERN_SUCCESS);

  // set new port for all exceptions
  err = task_set_exception_ports(task, EXC_MASK_SOFTWARE | EXC_MASK_BREAKPOINT, exc_port, EXCEPTION_DEFAULT, THREAD_STATE_NONE);
  QASSERT(30097, err == KERN_SUCCESS);

}

//-------------------------------------------------------------------------
void mac_debmod_t::term_exception_ports(void)
{
  if ( exc_port != MACH_PORT_NULL )
  {
    kern_return_t err = restore_exception_ports(mach_task_self(), &saved_exceptions);
    QASSERT(30098, err == KERN_SUCCESS);
    err = mach_port_deallocate(mach_task_self(), exc_port);
    QASSERT(30099, err == KERN_SUCCESS);
    exc_port = MACH_PORT_NULL;
  }
}

//-----------------------------------------------------------------------------
bool mac_debmod_t::verify_user_privilege()
{
  struct group *dev_group = getgrnam("_developer");
  if ( dev_group == NULL )
    return false;

  gid_t grouplist[NGROUPS_MAX];
  int ngroups = getgroups(NGROUPS_MAX, grouplist);
  for ( int i = 0; i < ngroups; i++ )
    if ( grouplist[i] == dev_group->gr_gid )
      return true;

  return false;
}

//-----------------------------------------------------------------------------
bool mac_debmod_t::verify_code_signature()
{
  SecCodeRef code = NULL;
  sec_code_janitor_t code_janitor(code);

  OSStatus status = SecCodeCopySelf(0, &code);
  if ( status != errSecSuccess )
    return false;

  status = SecCodeCheckValidity(code, kSecCSDefaultFlags, NULL);
  return status == errSecSuccess;
}

//-----------------------------------------------------------------------------
bool mac_debmod_t::acquire_taskport_right()
{
  OSStatus status;
  AuthorizationRef auth_ref = NULL;
  auth_ref_janitor_t ref_janitor(auth_ref);
  AuthorizationFlags auth_flags = kAuthorizationFlagExtendRights
    | kAuthorizationFlagPreAuthorize
    | (1 << 5) /* kAuthorizationFlagLeastPrivileged */;

  // create an authorization context
  status = AuthorizationCreate(
      NULL,
      kAuthorizationEmptyEnvironment,
      auth_flags,
      &auth_ref);

  if ( status != errAuthorizationSuccess )
    return false;

  AuthorizationItem taskport_items[] = { { "system.privilege.taskport" } };
  AuthorizationRights auth_rights = { 1, taskport_items };
  AuthorizationRights *out_rights = NULL;
  auth_rights_janitor_t rights_janitor(out_rights);

  // first try to authorize without credentials
  status = AuthorizationCopyRights(
      auth_ref,
      &auth_rights,
      kAuthorizationEmptyEnvironment,
      auth_flags,
      &out_rights);

  if ( status != errAuthorizationSuccess )
  {
    qstring user;
    qstring pass;

    if ( !qgetenv("MAC_DEBMOD_USER", &user)
      || !qgetenv("MAC_DEBMOD_PASS", &pass) )
    {
      return false;
    }

    AuthorizationItem credentials[] =
    {
      { kAuthorizationEnvironmentUsername },
      { kAuthorizationEnvironmentPassword },
      { kAuthorizationEnvironmentShared }
    };

    credentials[0].valueLength = user.length();
    credentials[0].value = user.begin();
    credentials[1].valueLength = pass.length();
    credentials[1].value = pass.begin();

    AuthorizationEnvironment env = { 3, credentials };

    // if we received rights in the previous call to AuthorizationCopyRights,
    // free it before we re-use the pointer
    rights_janitor.~janitor_t();

    status = AuthorizationCopyRights(
        auth_ref,
        &auth_rights,
        &env,
        auth_flags,
        &out_rights);

    bzero(user.begin(), user.length());
    bzero(pass.begin(), pass.length());

    return status == errAuthorizationSuccess;
  }

  return true;
}

//--------------------------------------------------------------------------
bool mac_debmod_t::handle_process_start(pid_t _pid)
{
  debdeb("handle process start %d\n", _pid);
  pid = _pid;

  int status;
  int k = qwait(&status, true);
  debdeb("qwait on %d: %x (ret=%d)\n", pid, status, k);
  QASSERT(30190, k == pid);

  cputype = get_process_cpu(pid);
  debapp_attrs.addrsize = get_cpu_bitness(cputype);
  is64 = debapp_attrs.addrsize == 8;
#ifndef __X64__
  if ( is64 )
  {
    dwarning("Process with pid %d is an x86_64 process. Please use mac_serverx64 to debug it.", pid);
    return false;
  }
#endif

  if ( !WIFSTOPPED(status) )
  {
    if ( WIFEXITED(status) )
    {
      int exitval = WEXITSTATUS(status);
      int err = int8(exitval);
      msg("process %d exited unexpectedly with code %d\n", _pid, exitval);
      if ( err < 0 )
        msg("possible cause: %s (%d)\n", strerror(-err), -err);
      warning("Process exited before debugging start.");
      return false;
    }
    else if ( WIFSIGNALED(status) )
    {
      msg("process %d stopped unexpectedly because of signal %d\n", _pid, WTERMSIG(status));
      warning("Process stopped before debugging start.");
      return false;
    }
    debdeb("not stopped?\n");
    return false;
  }
  if ( WSTOPSIG(status) != SIGTRAP && WSTOPSIG(status) != SIGSTOP )
  {
    warning("Got unexpected signal at debugging start.");
    msg("got signal %d? (expected SIGTRAP or SIGSTOP)\n", WSTOPSIG(status));
    return false;
  }

  /* Get the mach task for the target process */
  kern_return_t err = task_for_pid(mach_task_self(), pid, &task);
  if ( err == KERN_FAILURE ) // no access?
  {
#define OSX_DEBUGGER_HINT "For more info, please see the 'Mac OS X debugger' help entry (shortcut F1)."
    char **argv = *_NSGetArgv();
    const char *program = qbasename(argv[0]);
    if ( strstr(program, "server") == NULL )
      program = NULL; // runing local mac debugger module
    if ( program != NULL )
    {
      dwarning("Permission denied. Please ensure that '%s' is either codesigned or running as root.\n\n"
               OSX_DEBUGGER_HINT,
               program);
    }
    else
    {
      dwarning("Please run IDA with elevated permissons for local debugging.\n"
               "Another solution is to run mac_server and use localhost as\n"
               "the remote computer name.\n\n"
               OSX_DEBUGGER_HINT);
    }
    return false;
  }
  QASSERT(30100, err == KERN_SUCCESS);

  in_ptrace = true;
  thid_t tid = init_main_thread(false);
  debdeb("initially stopped at %a pid=%d tid=%d task=%d\n", get_ip(tid), pid, tid, task);
  run_state = rs_running;

  init_dyld();

  create_process_start_event(pid, tid);

  init_exception_ports();
  return true;
}

//--------------------------------------------------------------------------
void mac_debmod_t::create_process_start_event(pid_t _pid, thid_t tid)
{
  debug_event_t ev;
  ev.eid     = PROCESS_START;
  ev.pid     = _pid;
  ev.tid     = tid;
  ev.ea      = BADADDR;
  ev.handled = true;
  get_exec_fname(_pid, ev.modinfo.name, sizeof(ev.modinfo.name));
  debdeb("gotexe: %s\n", ev.modinfo.name);
  ev.modinfo.size = calc_image_size(ev.modinfo.name, is64, &ev.modinfo.base);
  events.enqueue(ev, IN_FRONT);
}

//--------------------------------------------------------------------------
int idaapi mac_debmod_t::dbg_start_process(
        const char *path,
        const char *args,
        const char *startdir,
        int flags,
        const char *input_path,
        uint32 input_file_crc32)
{
  void *child_pid;
  int code = maclnx_launch_process(this, path, args, startdir, flags,
                                   input_path, input_file_crc32, &child_pid);

  if ( code > 0
    && child_pid != NULL
    && !handle_process_start((ssize_t)child_pid) )
  {
    code = -1;
  }
  return code;
}

//--------------------------------------------------------------------------
void mac_debmod_t::create_process_attach_event(pid_t _pid)
{
  // generate the attach event
  debug_event_t ev;
  ev.eid     = PROCESS_ATTACH;
  ev.pid     = _pid;
  ev.tid     = maintid();
  ev.ea      = get_ip(ev.tid);
  ev.handled = true;
  get_exec_fname(_pid, ev.modinfo.name, sizeof(ev.modinfo.name));
  ev.modinfo.base = BADADDR;
  ev.modinfo.size = 0;
  ev.modinfo.rebase_to = BADADDR;
  events.enqueue(ev, IN_BACK);

  // generate THREAD_START events
  update_threads();

  // block the process until all generated events are processed
  attaching = true;
}

//--------------------------------------------------------------------------
// 1-ok, 0-failed
int idaapi mac_debmod_t::dbg_attach_process(pid_t _pid, int /*event_id*/, int /*flags*/)
{
  if ( qptrace(PT_ATTACH, _pid, NULL, NULL) == 0
    && handle_process_start(_pid) )
  {
    create_process_attach_event(_pid);
    return true;
  }
  return false;
}

//--------------------------------------------------------------------------
// 1-ok, 0-failed
int idaapi mac_debmod_t::dbg_detach_process(void)
{
  if ( dyri.dyld_notify != 0 )
  {
    // remove the dyld breakpoint
    int size = dbg_write_memory(dyri.dyld_notify, dyld_opcode, BPT_CODE_SIZE);
    QASSERT(30101, size == BPT_CODE_SIZE);
    dyri.dyld_notify = 0;
  }
  // cleanup exception ports
  term_exception_ports();
  if ( in_ptrace )
  {
    qptrace(PT_DETACH, pid, 0, 0);
    in_ptrace = false;
  }
  else
  {
    // let the process run
    unblock_all_threads();
  }
  debug_event_t ev;
  ev.eid     = PROCESS_DETACH;
  ev.pid     = pid;
  ev.tid     = maintid();
  ev.ea      = BADADDR;
  ev.handled = true;
  events.enqueue(ev, IN_BACK);
  return true;
}

//--------------------------------------------------------------------------
// if we have to do something as soon as we noticed the connection
// broke, this is the correct place
bool idaapi mac_debmod_t::dbg_prepare_broken_connection(void)
{
  broken_connection = true;
  return true;
}

//--------------------------------------------------------------------------
// 1-ok, 0-failed
int idaapi mac_debmod_t::dbg_prepare_to_pause_process(void)
{
  debdeb("remote_prepare_to_pause_process\n");
  if ( run_state >= rs_exiting )
    return false;
  run_state = rs_pausing;
  kill(pid, SIGSTOP);
  return true;
}

//--------------------------------------------------------------------------
// 1-ok, 0-failed
int idaapi mac_debmod_t::dbg_exit_process(void)
{
  // since debhtread is retrieving events in advance, we possibly
  // already received the PROCESS_EXIT event. Check for it
  if ( exited() )
  {
    debdeb("%d: already exited\n", pid);
    return true;
  }

  run_state = rs_exiting;
  bool ok = false;
  debdeb("%d: sending SIGKILL\n", pid );
  if ( kill(pid, SIGKILL) == 0 )
  {
    ok = true;
    unblock_all_threads();
  }
  else
  {
    debdeb("SIGKILL %d failed: %s\n", pid, strerror(errno));
  }
  return ok;
}

//--------------------------------------------------------------------------
// Set hardware breakpoints for one thread
bool mac_debmod_t::set_hwbpts(int hThread)
{
  machine_debug_state_t dr_regs;

  if ( !get_debug_state(hThread, &dr_regs) )
    return false;

  ::set_dr(dr_regs, 0, hwbpt_ea[0]);
  ::set_dr(dr_regs, 1, hwbpt_ea[1]);
  ::set_dr(dr_regs, 2, hwbpt_ea[2]);
  ::set_dr(dr_regs, 3, hwbpt_ea[3]);
  ::set_dr(dr_regs, 6, 0);
  ::set_dr(dr_regs, 7, dr7);
//  printf("set_hwbpts: DR0=%08lX DR1=%08lX DR2=%08lX DR3=%08lX DR7=%08lX => %d\n",
//         hwbpt_ea[0],
//         hwbpt_ea[1],
//         hwbpt_ea[2],
//         hwbpt_ea[3],
//         dr7,
//         ok);
  return set_debug_state(hThread, &dr_regs);
}

//--------------------------------------------------------------------------
bool mac_debmod_t::refresh_hwbpts(void)
{
  for ( threads_t::iterator p=threads.begin(); p != threads.end(); ++p )
    if ( !set_hwbpts(p->second.tid) )
      return false;
  return true;
}

//--------------------------------------------------------------------------
// 1-ok, 0-failed
int idaapi mac_debmod_t::dbg_add_bpt(bpttype_t type, ea_t ea, int len)
{
  if ( type == BPT_SOFT )
  {
    debmod_bpt_t dbpt(ea, len);
    if ( dbg_read_memory(ea, &dbpt.saved, len) == len
      && dbg_write_memory(ea, bpt_code.begin(), BPT_CODE_SIZE) == BPT_CODE_SIZE )
    {
      bpts[ea] = dbpt;
      return true;
    }
  }

  return add_hwbpt(type, ea, len);
}

//--------------------------------------------------------------------------
// 1-ok, 0-failed
int idaapi mac_debmod_t::dbg_del_bpt(bpttype_t type, ea_t ea, const uchar *orig_bytes, int len)
{
  // we update threads when we delete a breakpoint because it gives
  // better results: new threads are immediately added to the list of
  // known threads and properly suspended before "single step"
  update_threads();
  if ( orig_bytes != NULL )
  {
    if ( dbg_write_memory(ea, orig_bytes, len) == len )
    {
      bpts.erase(ea);
      return true;
    }
  }

  return del_hwbpt(ea, type);
}

//--------------------------------------------------------------------------
// 1-ok, 0-failed
int idaapi mac_debmod_t::dbg_thread_get_sreg_base(ea_t *pea, thid_t /*tid*/, int /*sreg_value*/)
{
  // assume all segments are based on zero
  *pea = 0;
  return true;
}

//--------------------------------------------------------------------------
// 1-ok, 0-failed
int idaapi mac_debmod_t::dbg_thread_suspend(thid_t tid)
{
  debdeb("remote_thread_suspend %d\n", tid);
  kern_return_t err = thread_suspend(tid);
  return err == KERN_SUCCESS;
}

//--------------------------------------------------------------------------
// 1-ok, 0-failed
int idaapi mac_debmod_t::dbg_thread_continue(thid_t tid)
{
  debdeb("remote_thread_continue %d\n", tid);
  kern_return_t err = thread_resume(tid);
  return err == KERN_SUCCESS;
}

//--------------------------------------------------------------------------
// 1-ok, 0-failed
int idaapi mac_debmod_t::dbg_set_resume_mode(thid_t tid, resume_mode_t resmod)
{
  if ( resmod != RESMOD_INTO )
    return false; // not supported

  ida_thread_info_t *t = get_thread(tid);
  if ( t == NULL )
    return false;
  t->single_step = true;
  return true;
}

//--------------------------------------------------------------------------
// 1-ok, 0-failed
int idaapi mac_debmod_t::dbg_read_registers(thid_t tid, int clsmask, regval_t *values)
{
  if ( values == NULL )
    return false;

  machine_thread_state_t cpu;
  if ( !get_thread_state(tid, &cpu) )
    return false;

  if ( (clsmask & X86_RC_GENERAL) != 0 )
  {
    values[R_EAX].ival    = uval_t(cpu.__eax);
    values[R_EBX].ival    = uval_t(cpu.__ebx);
    values[R_ECX].ival    = uval_t(cpu.__ecx);
    values[R_EDX].ival    = uval_t(cpu.__edx);
    values[R_ESI].ival    = uval_t(cpu.__esi);
    values[R_EDI].ival    = uval_t(cpu.__edi);
    values[R_EBP].ival    = uval_t(cpu.__ebp);
    values[R_ESP].ival    = uval_t(cpu.__esp);
    values[R_EIP].ival    = uval_t(cpu.__eip);
    values[R_EFLAGS].ival = uval_t(cpu.__eflags);
#ifdef __EA64__
    if ( is64 )
    {
      values[R64_R8].ival  = uval_t(cpu.__r8);
      values[R64_R9].ival  = uval_t(cpu.__r9);
      values[R64_R10].ival = uval_t(cpu.__r10);
      values[R64_R11].ival = uval_t(cpu.__r11);
      values[R64_R12].ival = uval_t(cpu.__r12);
      values[R64_R13].ival = uval_t(cpu.__r13);
      values[R64_R14].ival = uval_t(cpu.__r14);
      values[R64_R15].ival = uval_t(cpu.__r15);
    }
#endif
  }
  if ( (clsmask & X86_RC_SEGMENTS) != 0 )
  {
    values[R_CS].ival = uval_t(cpu.__cs);
    values[R_FS].ival = uval_t(cpu.__fs);
    values[R_GS].ival = uval_t(cpu.__gs);
    if ( is64 )
    {
      values[R_DS].ival = 0;
      values[R_ES].ival = 0;
      values[R_SS].ival = 0;
    }
    else
    {
      values[R_DS].ival = uval_t(cpu.__ds);
      values[R_ES].ival = uval_t(cpu.__es);
      values[R_SS].ival = uval_t(cpu.__ss);
    }
  }

  if ( (clsmask & (X86_RC_FPU|X86_RC_XMM|X86_RC_MMX)) != 0 )
  {
    machine_float_state_t fpu;
    if ( !get_float_state(tid, &fpu) )
      return false;

    if ( (clsmask & (X86_RC_FPU|X86_RC_MMX)) != 0 )
    {
      if ( (clsmask & X86_RC_FPU) != 0 )
      {
        values[R_CTRL].ival = fpu.__fpu_fcw;
        values[R_STAT].ival = fpu.__fpu_fsw;
        values[R_TAGS].ival = fpu.__fpu_ftw;
      }
      read_fpu_registers(values, clsmask, &fpu.__fpu_stmm0, 16);
    }
    if ( (clsmask & X86_RC_XMM) != 0 )
    {
      uchar *xptr = (uchar *)&fpu.__fpu_xmm0;
      for ( int i=R_XMM0; i < R_MXCSR; i++,xptr+=16 )
        values[i].set_bytes(xptr, 16);
      values[R_MXCSR].ival = fpu.__fpu_mxcsr;
    }
  }
  return true;
}

//--------------------------------------------------------------------------
inline int get_reg_class(int reg_idx)
{
  return get_x86_reg_class(reg_idx);
}

//--------------------------------------------------------------------------
// 1-ok, 0-failed
bool mac_debmod_t::patch_reg_context(
        machine_thread_state_t *cpu,
        machine_float_state_t *fpu,
        int reg_idx,
        const regval_t *value) const
{
  if ( value == NULL )
    return false;

  int regclass = get_reg_class(reg_idx);
  if ( (regclass & (X86_RC_GENERAL|X86_RC_SEGMENTS)) != 0 )
  {
    QASSERT(30102, cpu != NULL);
    switch ( reg_idx )
    {
#ifdef __EA64__
      case R64_R8:  if ( is64 ) { cpu->__r8  = value->ival; } break;
      case R64_R9:  if ( is64 ) { cpu->__r9  = value->ival; } break;
      case R64_R10: if ( is64 ) { cpu->__r10 = value->ival; } break;
      case R64_R11: if ( is64 ) { cpu->__r11 = value->ival; } break;
      case R64_R12: if ( is64 ) { cpu->__r12 = value->ival; } break;
      case R64_R13: if ( is64 ) { cpu->__r13 = value->ival; } break;
      case R64_R14: if ( is64 ) { cpu->__r14 = value->ival; } break;
      case R64_R15: if ( is64 ) { cpu->__r15 = value->ival; } break;
#endif
      case R_DS: if ( !is64 ) { cpu->__ds = value->ival; } break;
      case R_ES: if ( !is64 ) { cpu->__es = value->ival; } break;
      case R_SS: if ( !is64 ) { cpu->__ss = value->ival; } break;
      case R_CS:     cpu->__cs     = value->ival; break;
      case R_FS:     cpu->__fs     = value->ival; break;
      case R_GS:     cpu->__gs     = value->ival; break;
      case R_EAX:    cpu->__eax    = value->ival; break;
      case R_EBX:    cpu->__ebx    = value->ival; break;
      case R_ECX:    cpu->__ecx    = value->ival; break;
      case R_EDX:    cpu->__edx    = value->ival; break;
      case R_ESI:    cpu->__esi    = value->ival; break;
      case R_EDI:    cpu->__edi    = value->ival; break;
      case R_EBP:    cpu->__ebp    = value->ival; break;
      case R_ESP:    cpu->__esp    = value->ival; break;
      case R_EIP:    cpu->__eip    = value->ival; break;
      case R_EFLAGS: cpu->__eflags = value->ival; break;
      default: return false;
    }
  }
  else if ( (regclass & (X86_RC_FPU|X86_RC_MMX|X86_RC_XMM)) != 0 )
  {
    QASSERT(30103, fpu != NULL);
    if ( reg_idx >= R_XMM0 && reg_idx < R_MXCSR )
    {
      uchar *xptr = (uchar *)&fpu->__fpu_xmm0 + (reg_idx - R_XMM0) * 16;
      const void *vptr = value->get_data();
      size_t size = value->get_data_size();
      memcpy(xptr, vptr, qmin(size, 16));
    }
    else if ( reg_idx >= R_MMX0 && reg_idx <= R_MMX7 )
    {
      uchar *xptr = (uchar *)&fpu->__fpu_stmm0 + (reg_idx - R_MMX0) * sizeof(_STRUCT_MMST_REG);
      const void *vptr = value->get_data();
      size_t size = value->get_data_size();
      memcpy(xptr, vptr, qmin(size, 8));
    }
    else if ( reg_idx == R_MXCSR )
    {
      fpu->__fpu_mxcsr = value->ival;
    }
    else if ( reg_idx >= R_ST0+FPU_REGS_COUNT ) // FPU status registers
    {
      switch ( reg_idx )
      {
        case R_CTRL: fpu->__fpu_fcw = value->ival; break;
        case R_STAT: fpu->__fpu_fsw = value->ival; break;
        case R_TAGS: fpu->__fpu_ftw = value->ival; break;
      }
    }
    else // FPU floating point registers
    {
      uchar *fptr = (uchar *)&fpu->__fpu_stmm0;
      fptr += (reg_idx - R_ST0) * sizeof(_STRUCT_MMST_REG);
      memcpy(fptr, value->fval, 10);
    }
  }
  return true;
}

//--------------------------------------------------------------------------
// 1-ok, 0-failed
int idaapi mac_debmod_t::dbg_write_register(thid_t tid, int reg_idx, const regval_t *value)
{
  if ( value == NULL )
    return false;

  int regclass = get_reg_class(reg_idx);
  if ( (regclass & (X86_RC_GENERAL|X86_RC_SEGMENTS)) != 0 )
  {
    machine_thread_state_t cpu;
    if ( !get_thread_state(tid, &cpu) )
      return false;

    if ( !patch_reg_context(&cpu, NULL, reg_idx, value) )
      return false;

    return set_thread_state(tid, &cpu);
  }
  else if ( (regclass & (X86_RC_FPU|X86_RC_XMM)) != 0 )
  {
    machine_float_state_t fpu;
    if ( !get_float_state(tid, &fpu) )
      return false;

    if ( !patch_reg_context(NULL, &fpu, reg_idx, value) )
      return false;

    return set_float_state(tid, &fpu);
  }
  return false;
}

//--------------------------------------------------------------------------
bool idaapi mac_debmod_t::write_registers(
        thid_t tid,
        int start,
        int count,
        const regval_t *values,
        const int *indices)
{
  machine_thread_state_t cpu;
  bool got_regs = false;
  machine_float_state_t fpu;
  bool got_i387 = false;

  for ( int i=0; i < count; i++, values++ )
  {
    int idx = indices != NULL ? indices[i] : start+i;
    int regclass = get_reg_class(idx);
    if ( (regclass & (X86_RC_GENERAL|X86_RC_SEGMENTS)) != 0 )
    { // general register
      if ( !got_regs )
      {
        if ( !get_thread_state(tid, &cpu) )
          return false;
        got_regs = true;
      }
    }
    else if ( (regclass & (X86_RC_FPU|X86_RC_XMM)) != 0 )
    {
      if ( !got_i387 )
      {
        if ( !get_float_state(tid, &fpu) )
          return false;
        got_i387 = true;
      }
    }
    if ( !patch_reg_context(&cpu, &fpu, idx, values) )
      return false;
  }

  if ( got_regs && !set_thread_state(tid, &cpu) )
    return false;

  if ( got_i387 && !set_float_state(tid, &fpu) )
    return false;

  return true;
}

//--------------------------------------------------------------------------
// find a dll in the memory information array
bool mac_debmod_t::exist_dll(const dyriv_t &riv, ea_t base)
{
  // dyld is never unloaded
  if ( base == dyld )
    return true;
  for ( int i=0; i < riv.size(); i++ )
    if ( riv[i].addr == base )
      return true;
  return false;
}

//--------------------------------------------------------------------------
void mac_debmod_t::update_dyld(void)
{
//  dmsg("start: update_dyld at %a\n", dyld_infos);
  if ( dyld == BADADDR || dyld_infos == BADADDR )
    return; // dyld not there (static program?)

  if ( read_dyri() )
  {
    read_cache_ranges();

    QASSERT(30104, dyri.version >= 1);

    if ( dyri.num_info > 0 && dyri.info_array != 0 )
    {
      dyriv_t riv;
      riv.resize(dyri.num_info);
      int nbytes = dyri.num_info * sizeof(dyld_raw_info);
      if ( read_mem(dyri.info_array, riv.begin(), nbytes, NULL) != KERN_SUCCESS )
        return;

//      show_hex(riv.begin(), nbytes, "riv:\n");
      // remove unexisting dlls
      images_t::iterator p;
      for ( p=dlls.begin(); p != dlls.end(); )
      {
        if ( !exist_dll(riv, p->first) )
        {
          debug_event_t ev;
          ev.eid     = LIBRARY_UNLOAD;
          ev.pid     = pid;
          ev.tid     = maintid();
          ev.ea      = BADADDR;
          ev.handled = true;
          qstrncpy(ev.info, p->second.name.c_str(), sizeof(ev.info));
          events.enqueue(ev, IN_FRONT);
          dlls.erase(p++);
        }
        else
        {
          ++p;
        }
      }
      // add new dlls
      for ( int i=0; i < riv.size(); i++ )
      {
        // address zero is ignored
        if ( riv[i].addr == 0 )
          continue;
        p = dlls.find(riv[i].addr);
        if ( p == dlls.end() )
        {
          char buf[QMAXPATH];
          memset(buf, 0, sizeof(buf));
          read_mem(riv[i].name, buf, sizeof(buf), NULL); // may fail because we don't know exact size
          buf[sizeof(buf)-1] = '\0';
//          dmsg("dll name at %a is '%s'\n", ea_t(riv[i].addr), riv[i].name, buf);
          add_dll(riv[i].addr, buf);
        }
      }
    }
  }
//  dmsg("end: update_dyld\n");
}

//--------------------------------------------------------------------------
bool mac_debmod_t::read_dyri()
{
  // should be called only once we discovered dyld
  QASSERT(618, dyld_infos != BADADDR && dyld != BADADDR);

  uint32_t ver;
  bool ok = read_mem(dyld_infos, &ver, 4, NULL) == KERN_SUCCESS;
  if ( ok && ver != 0 )
  {
    // valid structure fields depending on the version
    static const size_t read_lengths[] =
    {
      qoffsetof(dyld_raw_infos, libSystemInitialized),     // 1
      qoffsetof(dyld_raw_infos, jitInfo),                  // 2
      qoffsetof(dyld_raw_infos, jitInfo),                  // 3
      qoffsetof(dyld_raw_infos, jitInfo),                  // 4
      qoffsetof(dyld_raw_infos, coreSymbolicationShmPage), // 5
      qoffsetof(dyld_raw_infos, systemOrderFlag),          // 6
      qoffsetof(dyld_raw_infos, uuidArrayCount),           // 7
      qoffsetof(dyld_raw_infos, dyldAllImageInfosAddress), // 8
      qoffsetof(dyld_raw_infos, initialImageCount),        // 9
      qoffsetof(dyld_raw_infos, errorKind),                // 10
      qoffsetof(dyld_raw_infos, sharedCacheSlide),         // 11
      qoffsetof(dyld_raw_infos, sharedCacheUUID),          // 12
      qoffsetof(dyld_raw_infos, sharedCacheBaseAddress),   // 13
      qoffsetof(dyld_raw_infos, sharedCacheBaseAddress),   // 14
      sizeof(dyld_raw_infos),                              // 15
    };
    size_t readsize = (ver - 1) < qnumber(read_lengths) ? read_lengths[ver - 1] : read_lengths[qnumber(read_lengths) - 1];
    ok = read_mem(dyld_infos, &dyri, readsize, NULL) == KERN_SUCCESS;
    memset((char*)&dyri + readsize, 0, sizeof(dyri) - readsize);
    if ( ok && ver >= 2 && dyld_infos != dyri.dyldAllImageInfosAddress )
    {
      // dyld hasn't relocated the fields yet, do it
      adiff_t slide = dyld_infos - dyri.dyldAllImageInfosAddress;
      dmsg("relocating dyld fields with slide %a\n", slide);
      if ( dyri.info_array != 0 )
        dyri.info_array += slide;
      if ( dyri.dyld_notify != 0 )
        dyri.dyld_notify += slide;
    }
  }
  return ok;
}

//--------------------------------------------------------------------------
bool mac_debmod_t::read_cache_ranges()
{
  shared_cache_ranges.clear();

  if ( dyld_ranges != BADADDR )
  {
    dyld_raw_ranges raw;
    if ( read_mem(dyld_ranges, &raw, sizeof(raw), NULL) != KERN_SUCCESS )
      return false;

    ea_t count = raw.sharedRegionsCount;
    for ( ea_t i = 0; i < count; i++ )
    {
      ea_t start = raw.ranges[i].start;
      ea_t size  = raw.ranges[i].length;
      dmsg("shared cache mapping: %a..%a\n", start, start+size);
      shared_cache_ranges.push_back(range_t(start, start+size));
    }
  }
  else if ( dyri.sharedCacheBaseAddress != 0 )
  {
    dmsg("dyri: version=%d, sharedCacheBaseAddress=%a, sharedCacheSlide=%a\n",
         dyri.version,
         ea_t(dyri.sharedCacheBaseAddress),
         ea_t(dyri.sharedCacheSlide));

    // _dyld_shared_cache_ranges is no longer present in dyld for OSX 10.13/iOS 11.
    // fall back to parsing the mappings in the dyld cache header.
    struct ida_local mapping_visitor_t : public dyld_cache_visitor_t
    {
      mac_debmod_t *dm;
      dyld_shared_cache_ranges_t *ranges;
      ea_t slide;

      mapping_visitor_t(mac_debmod_t *_dm, dyld_shared_cache_ranges_t *_ranges, ea_t _slide)
        : dyld_cache_visitor_t(DCV_MAPPINGS),
          dm(_dm),
          ranges(_ranges),
          slide(_slide) {}

      virtual void visit_mapping(ea_t _start_ea, ea_t _end_ea)
      {
        ea_t start_ea = _start_ea + slide;
        ea_t end_ea = _end_ea + slide;
        dm->dmsg("shared cache mapping: %a..%a\n", start_ea, end_ea);
        ranges->push_back(range_t(start_ea, end_ea));
      }
    };

    mapping_visitor_t mapv(this, &shared_cache_ranges, dyri.sharedCacheSlide);
    parse_dyld_cache_mem(dyri.sharedCacheBaseAddress, reader, mapv);
  }

  return !shared_cache_ranges.empty();
}

//--------------------------------------------------------------------------
int mac_debmod_t::visit_vm_regions(vm_region_visitor_t &rv)
{
  mach_vm_size_t size = 0;
  for ( mach_vm_address_t addr = 0; ; addr += size )
  {
    mach_port_t object_name; // unused
    vm_region_top_info_data_t info;
    mach_msg_type_number_t count = VM_REGION_TOP_INFO_COUNT;
    kern_return_t kr = mach_vm_region(task, &addr, &size, VM_REGION_TOP_INFO,
                        (vm_region_info_t)&info, &count, &object_name);

    debdeb("task=%d addr=%" FMT_64 "x size=%" FMT_64 "x err=%x\n", task, addr, size, kr);
    if ( kr != KERN_SUCCESS )
      break;

    mach_vm_address_t subaddr;
    mach_vm_size_t subsize = 0;
    mach_vm_address_t end = addr + size;
    for ( subaddr=addr; subaddr < end; subaddr += subsize )
    {
      natural_t depth = 1;
      vm_region_submap_info_data_64_t sinfo;
      count = VM_REGION_SUBMAP_INFO_COUNT_64;
      kr = mach_vm_region_recurse(task, &subaddr, &subsize, &depth,
                                    (vm_region_info_t)&sinfo, &count);
      if ( kr != KERN_SUCCESS )
        break;
      if ( subaddr >= end )
        break;

      memory_info_t mi;
      mi.start_ea = subaddr;
      mi.end_ea = subaddr + subsize;
      mi.bitness = DEB_SEGM_BITNESS;

      if ( sinfo.protection & 1 ) mi.perm |= SEGPERM_READ;
      if ( sinfo.protection & 2 ) mi.perm |= SEGPERM_WRITE;
      if ( sinfo.protection & 4 ) mi.perm |= SEGPERM_EXEC;

      int code = rv.visit_region(mi);
      if ( code != 0 )
        return code;
    }
  }

  return 0;
}

//--------------------------------------------------------------------------
bool mac_debmod_t::parse_macho_file(
        macho_visitor_t &mv,
        const image_info_t &ii) const
{
  const char *dllname = ii.name.c_str();

  linput_t *li = open_linput(dllname, false);
  if ( li == NULL )
    return false;

  bool ok = parse_macho_file_pc(ii.base, li, mv, is64);
  close_linput(li);
  return ok;
}

//--------------------------------------------------------------------------
void mac_debmod_t::parse_macho_image(macho_visitor_t &mv, const image_info_t &ii)
{
  if ( shared_cache_ranges.contains(ii.base) )
  {
    // we must avoid parsing libs from dyld_shared_cache on disk, since the libraries
    // stored on disk may not match the corresponding image in the cache.
    // (Ex: segment mapping might be different)
    parse_macho_mem_pc(ii.base, reader, mv, &strings, is64, true);
  }
  else if ( !parse_macho_file(mv, ii) )
  {
    // if parsing failed on disk, fall back to parsing the image in memory
    parse_macho_mem_pc(ii.base, reader, mv, NULL, is64, false);
  }
}

//--------------------------------------------------------------------------
void mac_debmod_t::init_dyld()
{
  debdeb("searching process memory for dyld...\n");
  struct dyld_finder_t : public vm_region_visitor_t
  {
    mac_debmod_t *dm;
    char fname[QMAXPATH];

    dyld_finder_t(mac_debmod_t *_dm) : dm(_dm) {}

    virtual int visit_region(memory_info_t &mi)
    {
      if ( is_dyld_header(mi.start_ea, dm->reader, fname, sizeof(fname), dm->is64) )
      {
        dm->dmsg("%a: located dyld header and file '%s'\n", mi.start_ea, fname);
        dm->dyld = mi.start_ea;
        return 1;
      }
      return 0;
    }
  };

  dyld_finder_t df(this);
  if ( visit_vm_regions(df) != 1 || dyld == BADADDR )
  {
    dwarning("failed to find dyld in the target process");
    return;
  }

  add_dll(dyld, df.fname);
  // immediately process it
  dbg_stopped_at_debug_event();

  if ( dyld_infos == BADADDR || !read_dyri() )
  {
    dwarning("failed to read _dyld_all_image_infos in the target process");
    return;
  }

  // set a breakpoint for library loads/unloads
  ea_t notify_ea = dyri.dyld_notify; // shut up the compiler
  dmsg("%a: setting bpt for library notifications\n", notify_ea);

  uchar opcode[BPT_CODE_SIZE];
  read_mem(notify_ea, opcode, sizeof(opcode), NULL);
  if ( memcmp(opcode, dyld_opcode, BPT_CODE_SIZE) != 0 )
    dwarning("Unexpected dyld_opcode in the debugger server (init_dyld): %x", *(uint32*)opcode);

  dbg_add_bpt(BPT_SOFT, notify_ea, -1);

  // process any previously loaded dlls
  update_dyld();
}

//--------------------------------------------------------------------------
/*local const char *get_share_mode_name(unsigned char sm, char *buf, size_t bufsize)
{
  switch ( sm )
  {
    case SM_COW:             return "COW";
    case SM_PRIVATE:         return "PRIVATE";
    case SM_EMPTY:           return "EMPTY";
    case SM_SHARED:          return "SHARED";
    case SM_TRUESHARED:      return "TRUESHARED";
    case SM_PRIVATE_ALIASED: return "PRIV_ALIAS";
    case SM_SHARED_ALIASED:  return "SHRD_ALIAS";
  }                               // 1234567890
  qsnprintf(buf, bufsize, "%x", sm);
  return buf;
}*/

//--------------------------------------------------------------------------
ssize_t mem_reader_t::read(ea_t ea, void *buffer, int size)
{
  return dm->dbg_read_memory(ea, buffer, size);
}

//--------------------------------------------------------------------------
void mac_debmod_t::clean_stack_regions(meminfo_vec_t &miv) const
{
  // It seems on some versions of OSX, mach_vm_region() can report a region
  // of size PAGE_SIZE that lies at the bottom of the user stack. I'm not sure if this
  // is a bug in the OS, some undocumented range internal to OSX, or maybe even a deliberate attempt
  // to confuse debuggers/hacking tools. Either way, IDA must ignore this region because if
  // it doesn't, the stack will be split across two segments which can break stack unwinding.
  for ( meminfo_vec_t::iterator p = miv.begin(); p != miv.end(); ++p )
  {
    // the erroneous region has size PAGE_SIZE
    if ( p->size() != PAGE_SIZE )
      continue;

    // check if this region is located somewhere near the default stack base.
    // from vm_param.h: ASLR can slide the stack down by up to 1 MB.
    range_t stack_range(VM_USRSTACK-0x100000, VM_USRSTACK);
    if ( !stack_range.contains(*p) )
      continue;

    // check if next region is beyond the default stack base.
    // (i.e. 'p' represents the bottom of the stack).
    meminfo_vec_t::const_iterator next = p;
    if ( ++next == miv.end() || next->start_ea < VM_USRSTACK )
      continue;

    // check if previous region is aligned with the erroneous region
    meminfo_vec_t::iterator prev = p;
    if ( prev == miv.begin() || (--prev)->end_ea != p->start_ea )
      continue;

    // we have found a bogus region at the bottom of the stack.
    // extend the previous region and remove this erroneous one.
    prev->end_ea = p->end_ea;
    miv.erase(p);
    break;
  }
}

//--------------------------------------------------------------------------
// merge 2 range sets
// high priority overrides what is defined in low priority
// FIXME: this function was stolen from ui/memregs.cpp. Since it's part
// of the ui we can't use it from the mac_server, and I'm not sure if it's
// worth moving it to the kernel.
static void merge(
        meminfo_vec_t &res,
        const meminfo_vec_t &low,
        const meminfo_vec_t &high)
{
  if ( low.empty() )
  {
    res = high;
    return;
  }

  if ( high.empty() )
  {
    res = low;
    return;
  }

  int l = 0;
  meminfo_vec_t tmp;
  ea_t end = 0;
  ea_t lea = low[0].start_ea;
  for ( int h=0; ; h++ )
  {
    ea_t hea = h < high.size() ? high[h].start_ea : BADADDR;
    if ( hea != end )
    {
      while ( l < low.size() && lea < hea )
      { // add ranges before the high priority range
        if ( low[l].end_ea > end )
        {
          tmp.push_back(low[l]);
          if ( end >= lea )
            tmp.back().start_ea = end;
          end = low[l].end_ea;
          if ( end > hea )
          {
            end = lea = hea;
            tmp.back().end_ea = end;
            break;
          }
        }
        l++;
        if ( l < low.size() )
          lea = low[l].start_ea;
      }
    }
    if ( h == high.size() )
      break;
    tmp.push_back(high[h]);
    end = high[h].end_ea;
  }
  tmp.swap(res);
}

//--------------------------------------------------------------------------
int mac_debmod_t::get_memory_info(meminfo_vec_t &out, bool suspend)
{
  if ( suspend && !suspend_all_threads() )
    return -1;
  if ( exited() )
    return -1;

  meminfo_vec_t sects;
  // parse section info for each loaded dll
  for ( images_t::const_iterator i = dlls.begin(); i != dlls.end(); ++i )
  {
    const image_info_t &ii = i->second;

    struct ida_local sect_finder_t : public macho_visitor_t
    {
      meminfo_vec_t &sects;
      const char *dllname;

      sect_finder_t(meminfo_vec_t &_sects, const char *path)
        : macho_visitor_t(MV_SECTIONS), sects(_sects), dllname(qbasename(path)) {}

      virtual void visit_section(ea_t start_ea, ea_t end_ea, const qstring &name, bool is_code)
      {
        memory_info_t &s = sects.push_back();
        s.name.sprnt("%s:%s", dllname, name.c_str());
        s.start_ea = start_ea;
        s.end_ea   = end_ea;
        s.sclass  = is_code ? "CODE" : "DATA";
        s.perm    = SEGPERM_READ | (is_code ? SEGPERM_EXEC : 0);
        s.bitness = DEB_SEGM_BITNESS;
      }
    };

    sect_finder_t sf(sects, ii.name.c_str());
    parse_macho_image(sf, ii);
  }

  std::sort(sects.begin(), sects.end());

  meminfo_vec_t regions;
  // collect other known vm regions (stack, heap, etc.)
  struct ida_local vm_region_collector_t : public vm_region_visitor_t
  {
    meminfo_vec_t &regions;
    vm_region_collector_t(meminfo_vec_t &_regions) : regions(_regions) {}
    virtual int visit_region(memory_info_t &r)
    {
      if ( r.start_ea == COMMPAGE_START )
        r.name = "COMMPAGE";
      regions.push_back(r);
      return 0;
    }
  };

  vm_region_collector_t rc(regions);
  visit_vm_regions(rc);
  std::sort(regions.begin(), regions.end());

  merge(out, regions, sects);
  // FIXME: eventually this should be removed and replaced with a general solution that
  // coagulates all user stack vm regions into one. However this would require us to identify exactly
  // which memory regions represent the user stack - a task that the OS purposefully makes difficult.
  // I'm not sure how we can do it without guessing. Also see issue IDA-1813.
  clean_stack_regions(out);

  if ( suspend )
    resume_all_threads();
  return 1;
}

//--------------------------------------------------------------------------
int idaapi mac_debmod_t::dbg_get_memory_info(meminfo_vec_t &ranges)
{
  int code = get_memory_info(ranges, true);
  if ( code == 1 )
  {
    if ( same_as_oldmemcfg(ranges) )
      code = -2;
    else
      save_oldmemcfg(ranges);
  }
  return code;
}

//--------------------------------------------------------------------------
int idaapi mac_debmod_t::dbg_get_scattered_image(scattered_image_t &si, ea_t base)
{
  if ( !shared_cache_ranges.contains(base) )
    return -1;

  struct ida_local segm_visitor_t : public macho_visitor_t
  {
    scattered_image_t &si;

    segm_visitor_t(scattered_image_t &_si)
      : macho_visitor_t(MV_SECTIONS), si(_si) {}

    virtual void visit_section(ea_t start_ea, ea_t end_ea, const qstring &name, bool)
    {
      scattered_segm_t &ss = si.push_back();
      ss.start_ea = start_ea;
      ss.end_ea = end_ea;
      ss.name = name;
    }
  };

  segm_visitor_t sv(si);
  return parse_macho_mem_pc(base, reader, sv, NULL, is64, true) ? 1 : -1;
}

//--------------------------------------------------------------------------
bool idaapi mac_debmod_t::dbg_get_image_uuid(bytevec_t *uuid, ea_t base)
{
  images_t::const_iterator p = dlls.find(base);
  if ( p == dlls.end() )
    return false;

  struct ida_local uuid_getter_t : public macho_visitor_t
  {
    bytevec_t *uuid;
    uuid_getter_t(bytevec_t *_uuid) : macho_visitor_t(MV_UUID), uuid(_uuid) {}
    virtual void visit_uuid(const bytevec_t &_uuid) { *uuid = _uuid; }
  };

  uuid_getter_t getter(uuid);
  parse_macho_image(getter, p->second);
  return true;
}

//--------------------------------------------------------------------------
ea_t idaapi mac_debmod_t::dbg_get_segm_start(ea_t base, const qstring &segname)
{
  images_t::const_iterator p = dlls.find(base);
  if ( p == dlls.end() )
    return BADADDR;

  struct ida_local segm_finder_t : public macho_visitor_t
  {
    ea_t *result;
    const qstring &segname;

    segm_finder_t(ea_t *_result, const qstring &_segname)
      : macho_visitor_t(MV_SEGMENTS), result(_result), segname(_segname) {}

    virtual void visit_segment(ea_t start_ea, ea_t, const qstring &name, bool)
    {
      if ( segname == name )
        *result = start_ea;
    }
  };

  ea_t result = BADADDR;
  segm_finder_t finder(&result, segname);
  parse_macho_image(finder, p->second);

  return result;
}

//--------------------------------------------------------------------------
void idaapi mac_debmod_t::dbg_set_debugging(bool _debug_debugger)
{
  debug_debugger = _debug_debugger;
}

//--------------------------------------------------------------------------
int idaapi mac_debmod_t::dbg_init(void)
{
  // remember if the input is a dll
  cleanup();
  cleanup_hwbpts();

  int ret = DBG_HAS_PROCGETINFO | DBG_HAS_DETACHPROC;

  // here we ensure that IDA can in fact debug other applications.
  // if not, we warn the user.
  if ( getuid() == 0 )
    return ret;

  if ( !verify_code_signature() )
  {
    msg("WARNING: This program must either be codesigned or run as root to debug mac applications.\n");
  }
  else if ( !verify_user_privilege() )
  {
    msg("WARNING: This program must be launched by a user in the _developer group in order to debug mac applications\n");
  }
  else if ( !acquire_taskport_right() )
  {
    msg("WARNING: The debugger could not acquire the necessary permissions from the OS to debug mac applications.\n"
        "You will likely have to specify the proper credentials at process start. To avoid this, you can set\n"
        "the MAC_DEBMOD_USER and MAC_DEBMOD_PASS environment variables.\n");
  }

  return ret;
}

//--------------------------------------------------------------------------
void idaapi mac_debmod_t::dbg_term(void)
{
  cleanup();
  cleanup_hwbpts();
}

//--------------------------------------------------------------------------
bool idaapi mac_debmod_t::thread_get_fs_base(
        thid_t /*tid*/,
        int /*reg_idx*/,
        ea_t * /*pea*/)
{
  return false;
}

//--------------------------------------------------------------------------
int idaapi mac_debmod_t::get_task_suspend_count(void)
{
  task_basic_info info;
  mach_msg_type_number_t task_info_count;
  kern_return_t err = task_info(task, TASK_BASIC_INFO, (task_info_t)&info, &task_info_count);
  debdeb("task_info(TASK_BASIC_INFO) returned %d\n", err);
  if ( err != KERN_FAILURE )
  {
    return info.suspend_count;
  }
  else
  {
    perror("get_task_suspend_count:task_info");
    return -1;
  }
}

//--------------------------------------------------------------------------
// recovering from a broken session consists in the following steps:
//
//  1 - Cleanup dlls previously recorded.
//  2 - Restore broken breakpoints.
//  3 - Generate PROCESS_START and PROCESS_ATTACH event.
//
bool idaapi mac_debmod_t::dbg_continue_broken_connection(pid_t _pid)
{
  debmod_t::dbg_continue_broken_connection(pid);
  bool ret = false;

  // cleanup previously recorded information
  dlls.clear();

  // restore broken breakpoints and continue like a normal attach
  if ( restore_broken_breakpoints() )
  {
    thid_t tid = init_main_thread(true);

    init_dyld();
    create_process_start_event(_pid, tid);
    create_process_attach_event(_pid);

    broken_connection = false;
    ret = true;
  }
  return ret;
}

//--------------------------------------------------------------------------
bool init_subsystem()
{
  mac_debmod_t::reuse_broken_connections = true;

  return true;
}

//--------------------------------------------------------------------------
bool term_subsystem()
{
  return true;
}

//--------------------------------------------------------------------------
debmod_t *create_debug_session()
{
  return new mac_debmod_t();
}
