/*
*  This is a userland linux debugger module
*
*  Functions unique for Linux
*
*  It can be compiled by gcc
*
*/

//#define LDEB            // enable debug print in this module

#include <sys/syscall.h>
#include <pthread.h>

#include <pro.h>
#include <prodir.h>
#include <fpro.h>
#include <err.h>
#include <ida.hpp>
#include <idp.hpp>
#include <idd.hpp>
#include <name.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <diskio.hpp>
#include "symelf.hpp"
#include "consts.h"
#include "linux_debmod.h"

#ifdef __ANDROID__
#  include <linux/elf.h>
#  include "android.hpp"
#  include "android.cpp"
#else
#  include <link.h>
#endif

#ifdef __ARM__

#if !defined(__ARMUCLINUX__) && !defined(__EA64__)
#define __HAVE_ARM_VFP__
#endif

#define user_regs_struct user_regs
#define user_fpregs_struct user_fpregs
static const uchar thumb16_bpt[] = { 0x10, 0xDE }; // UND #10
// we must use 32-bit breakpoints for 32bit instructions inside IT blocks (thumb mode)
// if we use a 16-bit breakpoint and the processor decides to skip it
// because the condition codes are not satisfied, we will end up skipping
// only half of the original 32-bit instruction
static const uchar thumb32_bpt[] = { 0xF0, 0xF7, 0x00, 0xA0 };
// This bit is combined with the software bpt size to indicate
// that 32bit bpt code should be used.
#define USE_THUMB32_BPT 0x80
static const uchar aarch64_bpt[] = AARCH64_BPT_CODE;
#endif

#ifdef __ARM__

#if defined(__HAVE_ARM_VFP__) && !defined(PTRACE_GETVFPREGS)
#define PTRACE_GETVFPREGS __ptrace_request(27)
#define PTRACE_SETVFPREGS __ptrace_request(28)
#endif

#if !defined(__ANDROID__)
struct user_vfp
{
  int64 fpregs[32];
  int32 fpscr;
};
#endif
typedef struct user_vfp user_vfp_regs_t;
// Program counter register
#  define PCREG_IDX R_PC
#  if defined(__X64__)
#    define AARCH64_X_REGS_NUM 31
#    define LRREG_IDX 30
#    define SPREG_IDX R_SP
#    define CPSR_IDX  R_PSR
#  else
#    define SPREG uregs[R_13]
#    define PCREG uregs[PCREG_IDX]
#    ifdef __HAVE_ARM_VFP__
#      define ARM_MAXREG R_D31
#    else
#      define ARM_MAXREG R_PSR
#    endif
#  endif
#  define CLASS_OF_INTREGS ARM_RC_GENERAL
#else
#  define CLASS_OF_INTREGS (X86_RC_GENERAL|X86_RC_SEGMENTS)
#  if defined(__X64__)
#    define SPREG rsp
#    define PCREG rip
#    define PCREG_IDX   R_EIP
#    define XMM_STRUCT  i387
#    define TAGS_REG    ftw
#    define CLASSES_STORED_IN_FPREGS (X86_RC_FPU|X86_RC_MMX|X86_RC_XMM) // fpregs keeps xmm&fpu
#  else
#    define SPREG esp
#    define PCREG eip
#    define PCREG_IDX   R_EIP
#    define XMM_STRUCT  x387
#    define TAGS_REG    twd
#    define CLASSES_STORED_IN_FPREGS (X86_RC_FPU|X86_RC_MMX)            // fpregs keeps only fpu
#  endif
#endif

#ifdef __ANDROID_X86__
#define user_fpxregs_struct user_fxsr_struct
#endif

static char getstate(int tid);

//--------------------------------------------------------------------------
linux_debmod_t::linux_debmod_t(void) :
  ta(NULL),
  complained_shlib_bpt(false),
  process_handle(INVALID_HANDLE_VALUE),
  thread_handle(INVALID_HANDLE_VALUE),
  exited(false),
  mapfp(NULL),
  npending_signals(0),
  may_run(false),
  requested_to_suspend(false),
  in_event(false),
  nptl_base(BADADDR)
{
  set_platform("linux");
}

/* This definition comes from prctl.h, but some kernels may not have it.  */
#ifndef PTRACE_ARCH_PRCTL
#define PTRACE_ARCH_PRCTL      __ptrace_request(30)
#endif
#pragma GCC diagnostic ignored "-Wswitch" // case values do not belong to...

//--------------------------------------------------------------------------
const char *get_ptrace_name(__ptrace_request request)
{
  switch ( request )
  {
    case PTRACE_TRACEME:    return "PTRACE_TRACEME";   /* Indicate that the process making this request should be traced.
                                                       All signals received by this process can be intercepted by its
                                                       parent, and its parent can use the other `ptrace' requests.  */
    case PTRACE_PEEKTEXT:   return "PTRACE_PEEKTEXT";  /* Return the word in the process's text space at address ADDR.  */
    case PTRACE_PEEKDATA:   return "PTRACE_PEEKDATA";  /* Return the word in the process's data space at address ADDR.  */
    case PTRACE_PEEKUSER:   return "PTRACE_PEEKUSER";  /* Return the word in the process's user area at offset ADDR.  */
    case PTRACE_POKETEXT:   return "PTRACE_POKETEXT";  /* Write the word DATA into the process's text space at address ADDR.  */
    case PTRACE_POKEDATA:   return "PTRACE_POKEDATA";  /* Write the word DATA into the process's data space at address ADDR.  */
    case PTRACE_POKEUSER:   return "PTRACE_POKEUSER";  /* Write the word DATA into the process's user area at offset ADDR.  */
    case PTRACE_CONT:       return "PTRACE_CONT";      /* Continue the process.  */
    case PTRACE_KILL:       return "PTRACE_KILL";      /* Kill the process.  */
    case PTRACE_SINGLESTEP: return "PTRACE_SINGLESTEP";/* Single step the process. This is not supported on all machines.  */
#ifdef PTRACE_GETREGS
    case PTRACE_GETREGS:    return "PTRACE_GETREGS";   /* Get all general purpose registers used by a processes. This is not supported on all machines.  */
    case PTRACE_SETREGS:    return "PTRACE_SETREGS";   /* Set all general purpose registers used by a processes. This is not supported on all machines.  */
    case PTRACE_GETFPREGS:  return "PTRACE_GETFPREGS"; /* Get all floating point registers used by a processes. This is not supported on all machines.  */
    case PTRACE_SETFPREGS:  return "PTRACE_SETFPREGS"; /* Set all floating point registers used by a processes. This is not supported on all machines.  */
#endif
#ifdef PTRACE_GETVFPREGS
    case PTRACE_GETVFPREGS: return "PTRACE_GETVFPREGS"; /* Get all vfp registers used by a processes.  This is not supported on all machines.  */
    case PTRACE_SETVFPREGS: return "PTRACE_SETVFPREGS"; /* Set all vfp registers used by a processes.  This is not supported on all machines.  */
#endif
    case PTRACE_ATTACH:     return "PTRACE_ATTACH";    /* Attach to a process that is already running. */
    case PTRACE_DETACH:     return "PTRACE_DETACH";    /* Detach from a process attached to with PTRACE_ATTACH.  */
#ifdef PTRACE_GETFPXREGS
    case PTRACE_GETFPXREGS: return "PTRACE_GETFPXREGS";/* Get all extended floating point registers used by a processes. This is not supported on all machines.  */
    case PTRACE_SETFPXREGS: return "PTRACE_SETFPXREGS";/* Set all extended floating point registers used by a processes. This is not supported on all machines.  */
#endif
    case PTRACE_SYSCALL:    return "PTRACE_SYSCALL";   /* Continue and stop at the next (return from) syscall.  */
    case PTRACE_ARCH_PRCTL: return "PTRACE_ARCH_PRCTL";
    case PTRACE_GETSIGINFO: return "PTRACE_GETSIGINFO";
    default:
      static char buf[MAXSTR];
      qsnprintf(buf, sizeof(buf), "%d", request);
      return buf;
  }
}

//--------------------------------------------------------------------------
static long qptrace(__ptrace_request request, pid_t pid, void *addr, void *data)
{
  long code = ptrace(request, pid, addr, data);
  if ( request != PTRACE_PEEKTEXT
    && request != PTRACE_PEEKUSER
    && (request != PTRACE_POKETEXT
     && request != PTRACE_POKEDATA
#ifdef PTRACE_SETREGS
     && request != PTRACE_SETREGS
     && request != PTRACE_GETREGS
     && request != PTRACE_SETFPREGS
     && request != PTRACE_GETFPREGS
#endif
#ifdef PTRACE_GETVFPREGS
     && request != PTRACE_GETVFPREGS
     && request != PTRACE_SETVFPREGS
#endif
#ifdef PTRACE_GETFPXREGS
     && request != PTRACE_SETFPXREGS
     && request != PTRACE_GETFPXREGS
#endif
     || code != 0) )
  {
//    int saved_errno = errno;
//    msg("%s(%u, 0x%X, 0x%X) => 0x%X\n", get_ptrace_name(request), pid, addr, data, code);
//    errno = saved_errno;
  }
  return code;
}

//--------------------------------------------------------------------------
#ifdef LDEB
void linux_debmod_t::log(thid_t tid, const char *format, ...)
{
  if ( tid != -1 )
  {
    thread_info_t *thif = get_thread(tid);
    if ( thif == NULL )
    {
      msg("    %d:       ** missing **\n", tid);
    }
    else
    {
      const char *name = "?";
      switch ( thif->state )
      {
        case RUNNING:        name = "RUN "; break;
        case STOPPED:        name = "STOP"; break;
        case DYING:          name = "DYIN"; break;
        case DEAD:           name = "DEAD"; break;
      }
      msg("    %d: %s %c%c S=%d U=%d ",
          thif->tid,
          name,
          thif->waiting_sigstop ? 'W' : ' ',
          thif->got_pending_status ? 'P' : ' ',
          thif->suspend_count,
          thif->user_suspend);
    }
  }
  va_list va;
  va_start(va, format);
  vmsg(format, va);
  va_end(va);
}

static const char *strevent(int status)
{
  int event = status >> 16;
  if ( WIFSTOPPED(status)
    && WSTOPSIG(status) == SIGTRAP
    && event != 0 )
  {
    switch ( event )
    {
      case PTRACE_EVENT_FORK:
        return " event=PTRACE_EVENT_FORK";
      case PTRACE_EVENT_VFORK:
        return " event=PTRACE_EVENT_VFORK";
      case PTRACE_EVENT_CLONE:
        return " event=PTRACE_EVENT_CLONE";
      case PTRACE_EVENT_EXEC:
        return " event=PTRACE_EVENT_EXEC";
      case PTRACE_EVENT_VFORK_DONE:
        return " event=PTRACE_EVENT_VFORK_DONE";
      case PTRACE_EVENT_EXIT:
        return " event=PTRACE_EVENT_EXIT";
      default:
        return " UNKNOWN event";
    }
  }
  return "";
}

static char *status_dstr(int status)
{
  static char buf[80];
  if ( WIFSTOPPED(status) )
  {
    int sig = WSTOPSIG(status);
    ::qsnprintf(buf, sizeof(buf), "stopped(%s)%s", strsignal(sig), strevent(status));
  }
  else if ( WIFSIGNALED(status) )
  {
    int sig = WTERMSIG(status);
    ::qsnprintf(buf, sizeof(buf), "terminated(%s)", strsignal(sig));
  }
  else if ( WIFEXITED(status) )
  {
    int code = WEXITSTATUS(status);
    ::qsnprintf(buf, sizeof(buf), "exited(%d)", code);
  }
  else
  {
    ::qsnprintf(buf, sizeof(buf), "status=%x\n", status);
  }
  return buf;
}

static void ldeb(const char *format, ...)
{
  va_list va;
  va_start(va, format);
  vmsg(format, va);
  va_end(va);
}

#else
#define log(tid, format, args...)
#define ldeb(format, args...) do {} while ( 0 )
#define status_dstr(status) "?"
#define strevent(status) ""
#endif

//--------------------------------------------------------------------------
static int qkill(int pid, int signo)
{
  ldeb("%d: sending signal %s\n", pid, signo == SIGSTOP ? "SIGSTOP"
                                     : signo == SIGKILL ? "SIGKILL" : "");
  int ret;
  errno = 0;
  static bool tkill_failed = false;
  if ( !tkill_failed )
  {
    ret = syscall(__NR_tkill, pid, signo);
    if ( ret != 0 && errno == ENOSYS )
    {
      errno = 0;
      tkill_failed = true;
    }
  }
  if ( tkill_failed )
    ret = kill(pid, signo);
  if ( ret != 0 )
    ldeb("  %s\n", strerror(errno));
  return ret;
}

//--------------------------------------------------------------------------
inline thread_info_t *linux_debmod_t::get_thread(thid_t tid)
{
  threads_t::iterator p = threads.find(tid);
  if ( p == threads.end() )
    return NULL;
  return &p->second;
}

//--------------------------------------------------------------------------
#if defined(__ARM__) && defined(__X64__)
inline bool ptrace_getregset(struct user_pt_regs *regset, thid_t tid)
{
  struct iovec iov;
  iov.iov_base = regset;
  iov.iov_len = sizeof (struct user_pt_regs);
  return qptrace(PTRACE_GETREGSET, tid, (void *)NT_PRSTATUS, &iov) == 0;
}
#endif

//--------------------------------------------------------------------------
static ea_t get_ip(thid_t tid)
{
  ea_t ea;
#if defined(__ARM__) && defined(__X64__)
  struct user_pt_regs regset;
  ea = ptrace_getregset(&regset, tid) ? regset.pc : BADADDR;
#else
  const size_t pcreg_off = qoffsetof(user, regs) + qoffsetof(user_regs_struct, PCREG);
  // In case 64bit IDA (__EA64__=1) is debugging a 32bit process:
  //  - size of ea_t is 64 bit
  //  - qptrace() returns a 32bit long value
  // Here we cast the return value to unsigned long to prevent
  // extending of the sign bit when convert 32bit long value to 64bit ea_t
  ea = (unsigned long)qptrace(PTRACE_PEEKUSER, tid, (void *)pcreg_off, 0);
#endif
  return ea;
}

#include "linux_threads.cpp"

//--------------------------------------------------------------------------
#ifndef __ARM__
static unsigned long get_dr(thid_t tid, int idx)
{
  uchar *offset = (uchar *)qoffsetof(user, u_debugreg) + idx*sizeof(unsigned long int);
  unsigned long value = qptrace(PTRACE_PEEKUSER, tid, (void *)offset, 0);
  // msg("dr%d => %a\n", idx, value);
  return value;
}

//--------------------------------------------------------------------------
static bool set_dr(thid_t tid, int idx, unsigned long value)
{
  uchar *offset = (uchar *)qoffsetof(user, u_debugreg) + idx*sizeof(unsigned long int);

  if ( value == (unsigned long)(-1) )
    value = 0;          // linux does not accept too high values
  // msg("dr%d <= %a\n", idx, value);
  return qptrace(PTRACE_POKEUSER, tid, offset, (void *)value) == 0;
}
#endif

//--------------------------------------------------------------------------
bool linux_debmod_t::del_pending_event(event_id_t id, const char *module_name)
{
  for ( eventlist_t::iterator p=events.begin(); p != events.end(); ++p )
  {
    if ( p->eid == id && streq(p->modinfo.name, module_name) )
    {
      events.erase(p);
      return true;
    }
  }
  return false;
}

//--------------------------------------------------------------------------
void linux_debmod_t::enqueue_event(const debug_event_t &ev, queue_pos_t pos)
{
  if ( ev.eid != NO_EVENT )
  {
    events.enqueue(ev, pos);
    may_run = false;
    ldeb("enqueued event, may not run!\n");
  }
}

//--------------------------------------------------------------------------
static inline void resume_dying_thread(int tid, int)
{
  qptrace(PTRACE_CONT, tid, 0, (void *)0);
}

//--------------------------------------------------------------------------
// we got a signal that does not belong to our thread. find the target thread
// and store the signal there
void linux_debmod_t::store_pending_signal(int _pid, int status)
{
  struct ida_local linux_signal_storer_t : public debmod_visitor_t
  {
    int pid;
    int status;
    linux_signal_storer_t(int p, int s) : pid(p), status(s) {}
    int visit(debmod_t *debmod)
    {
      linux_debmod_t *ld = (linux_debmod_t *)debmod;
      threads_t::iterator p = ld->threads.find(pid);
      if ( p != ld->threads.end() )
      {
        thread_info_t &ti = p->second;
        // normally we should not receive a new signal unless the process or the thread
        // exited. the exit signals may occur even if there is a pending signal.
        QASSERT(30185, !ti.got_pending_status || ld->exited || WIFEXITED(status));
        if ( ti.waiting_sigstop && WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP )
        {
          ti.waiting_sigstop = false;
          ld->set_thread_state(ti, STOPPED);
        }
        else
        {
          ti.got_pending_status = true;
          ti.pending_status = status;
          ld->npending_signals++;
        }
        return 1; // stop
      }
      else
      {
        // we are handling an event from a thread we recently removed, ignore this
        if ( ld->deleted_threads.has(pid) )
        {
          // do not store the signal but resume the thread and let it finish
          resume_dying_thread(pid, status);
          return 1;
        }
      }

      return 0; // continue
    }
  };
  linux_signal_storer_t lss(_pid, status);
  if ( !for_all_debuggers(lss) ) // uses lock_begin(), lock_end() to protect common data
  {
    if ( WIFSTOPPED(status) )
    {
      // we can get SIGSTOP for the new-born lwp before the parent get it
      // store pid to mark that we should not wait for SIGSTOP anymore
      seen_threads.push_back(_pid);
    }
    else if ( !WIFSIGNALED(status) )
    {
      // maybe it comes from a zombie?
      // if we terminate the process, there might be some zombie threads remaining(?)
      msg("  %d: failed to store pending status %x, killing unknown thread\n", _pid, status);
      qptrace(PTRACE_KILL, _pid, 0, 0);
    }
  }
}

//--------------------------------------------------------------------------
inline bool is_bpt_status(int status)
{
  if ( !WIFSTOPPED(status) )
    return false;
  int sig = WSTOPSIG(status);
#ifdef __ARM__
  return sig == SIGTRAP || sig == SIGILL;
#else
  return sig == SIGTRAP;
#endif
}

//--------------------------------------------------------------------------
// check if there are any pending signals for our process
bool linux_debmod_t::retrieve_pending_signal(pid_t *p_pid, int *status)
{
  if ( npending_signals == 0 )
    return false;

  lock_begin();

  // try to stick to the same thread as before
  threads_t::iterator p = threads.find(last_event.tid);
  if ( p != threads.end() )
  {
    thread_info_t &ti = p->second;
    if ( !ti.got_pending_status || ti.user_suspend > 0 || ti.suspend_count > 0 )
      p = threads.end();
  }

  // find a thread with a signal.
  if ( p == threads.end() )
  {
    for ( int i=0; i < 3; i++ )
    {
      for ( p=threads.begin(); p != threads.end(); ++p )
      {
        thread_info_t &ti = p->second;
        if ( ti.user_suspend > 0 || ti.suspend_count > 0 )
          continue;
        if ( ti.got_pending_status )
        {
          // signal priorities: STEP, SIGTRAP, others
          if ( i == 0 )
          {
            if ( !ti.single_step )
              continue;
          }
          else if ( i == 1 )
          {
            if ( !is_bpt_status(ti.pending_status) )
              continue;
          }
          break;
        }
      }
    }
  }

  bool got_pending_signal = false;
  if ( p != threads.end() )
  {
    *p_pid = p->first;
    *status = p->second.pending_status;
    p->second.got_pending_status = false;
    got_pending_signal = true;
    npending_signals--;
    QASSERT(30186, npending_signals >= 0);
    ldeb("-------------------------------\n");
    log(p->first, "qwait (pending signal): %s (may_run=%d)\n", status_dstr(*status), may_run);
  }
  lock_end();
  return got_pending_signal;
}

//--------------------------------------------------------------------------
// read a zero terminated string. try to avoid reading unreadable memory
bool linux_debmod_t::read_asciiz(tid_t tid, ea_t ea, char *buf, size_t bufsize, bool suspend)
{
  while ( bufsize > 0 )
  {
    int pagerest = 4096 - (ea % 4096); // number of bytes remaining on the page
    int nread = qmin(pagerest, bufsize);
    if ( !suspend && nread > 128 )
      nread = 128;      // most paths are short, try to read only 128 bytes
    nread = _read_memory(tid, ea, buf, nread, suspend);
    if ( nread < 0 )
      return false; // failed

    // did we read a zero byte?
    for ( int i=0; i < nread; i++ )
      if ( buf[i] == '\0' )
        return true;

    ea  += nread;
    buf += nread;
    bufsize -= nread;
  }
  return true; // odd, we did not find any zero byte. should we report success?
}

//--------------------------------------------------------------------------
// may add/del threads!
bool linux_debmod_t::gen_library_events(int /*tid*/)
{
  int s = events.size();
  meminfo_vec_t miv;
  if ( get_memory_info(miv, false) == 1 )
    handle_dll_movements(miv);
  return events.size() != s;
}

//--------------------------------------------------------------------------
bool linux_debmod_t::handle_hwbpt(debug_event_t *event)
{
#ifdef __ARM__
  qnotused(event);
#else

  uint32 dr6_value = get_dr(event->tid, 6);
  for ( int i=0; i < MAX_BPT; i++ )
  {
    if ( dr6_value & (1<<i) )  // Hardware breakpoint 'i'
    {
      if ( hwbpt_ea[i] == get_dr(event->tid, i) )
      {
        event->eid     = BREAKPOINT;
        event->bpt.hea = hwbpt_ea[i];
        event->bpt.kea = BADADDR;
        set_dr(event->tid, 6, 0); // Clear the status bits
        return true;
      }
    }
  }
#endif
  return false;
}

//--------------------------------------------------------------------------
inline ea_t calc_bpt_event_ea(const debug_event_t *event)
{
#ifdef __ARM__
  if ( event->exc.code == SIGTRAP || event->exc.code == SIGILL )
    return event->ea;
#else
  if ( event->exc.code == SIGTRAP )
//  || event->exc.code == SIGSEGV ) // NB: there was a bug in linux 2.6.10 when int3 was reported as SIGSEGV instead of SIGTRAP
  {
    return event->ea - 1;               // x86 reports the address after the bpt
  }
#endif
  return BADADDR;
}

//--------------------------------------------------------------------------
inline void linux_debmod_t::set_thread_state(thread_info_t &ti, thstate_t state)
{
  ti.state = state;
}

//--------------------------------------------------------------------------
static __inline void clear_tbit(thid_t tid)
{
#ifdef __ARM__
  qnotused(tid);
  return;
#else

  struct user_regs_struct regs;
  if ( qptrace(PTRACE_GETREGS, tid, 0, &regs) != 0 )
  {
    msg("clear_tbit: error reading registers for thread %d\n", tid);
    return;
  }

  if ( (regs.eflags & 0x100) != 0 )
  {
    regs.eflags &= ~0x100;
    if ( qptrace(PTRACE_SETREGS, tid, 0, &regs) == -1 )
      msg("clear_tbit: error writting registers for thread %d\n", tid);
  }

#endif
}

//--------------------------------------------------------------------------
bool linux_debmod_t::check_for_new_events(chk_signal_info_t *csi, bool *event_prepared)
{
  if ( event_prepared != NULL )
    *event_prepared = false;

  while ( true )
  {
    // even if we have pending events, check for new events first.
    // this improves multithreaded debugging experience because
    // we stick to the same thread (hopefully a new event arrives fast enough
    // if we are single stepping). if we first check pending events,
    // the user will be constantly switched from one thread to another.
    csi->pid = check_for_signal(&csi->status, -1, 0);
    if ( csi->pid <= 0 )
    { // no new events, do we have any pending events?
      if ( retrieve_pending_signal(&csi->pid, &csi->status) )
      {
        // check for extended event,
        // if any the debugger event can be prepared
        handle_extended_wait(event_prepared, *csi);
        break;
      }
      // if the timeout was zero, nothing else to do
      if ( csi->timeout_ms == 0 )
        return false;
      // ok, we will wait for new events for a while
      csi->pid = check_for_signal(&csi->status, -1, csi->timeout_ms);
      if ( csi->pid <= 0 )
        return false;
    }
    ldeb("-------------------------------\n");
    log(csi->pid, " => qwait: %s\n", status_dstr(csi->status));

    // check for extended event,
    // if any the debugger event can be prepared
    handle_extended_wait(event_prepared, *csi);

    if ( threads.find(csi->pid) != threads.end() )
      break;

    // when an application creates many short living threads we may receive events
    // from a thread we already removed so, do not store this pending signal, just
    // ignore it
    if ( !deleted_threads.has(csi->pid) )
    {
      // we are not interested in this pid
      log(csi->pid, "storing status %d\n", csi->status);
      store_pending_signal(csi->pid, csi->status);
    }
    else
    {
      // do not store the signal but resume the thread and let it finish
      resume_dying_thread(csi->pid, csi->status);
    }
    csi->timeout_ms = 0;
  }
  return true;
}

//--------------------------------------------------------------------------
// timeout in microseconds
// 0 - no timeout, return immediately
// -1 - wait forever
// returns: 1-ok, 0-failed
int linux_debmod_t::get_debug_event(debug_event_t *event, int timeout_ms)
{
  chk_signal_info_t csi(timeout_ms);

  // even if we have pending events, check for new events first.
  bool event_ready = false;
  if ( !check_for_new_events(&csi, &event_ready) )
    return false;

  pid_t tid = csi.pid;
  int status = csi.status;

  thread_info_t *thif = get_thread(tid);
  if ( thif == NULL )
  {
    // not our thread?!
    debdeb("EVENT FOR UNKNOWN THREAD %d, IGNORED...\n", tid);
    int sig = WIFSTOPPED(status) ? WSTOPSIG(status) : 0;
    qptrace(PTRACE_CONT, tid, 0, (void*)(size_t)(sig));
    return false;
  }
  QASSERT(30057, thif->state != STOPPED || exited || WIFEXITED(status) || WIFSIGNALED(status));

  event->tid = NO_EVENT; // start with empty event

  // if there was a pending event, it means that previously we did not resume
  // any threads, all of them are suspended
  set_thread_state(*thif, STOPPED);

  dbg_freeze_threads(NO_THREAD);
  may_run = false;

  // debugger event could be prepared during the check_for_new_events
  if ( event_ready )
    goto EVENT_READY; // report empty event to get called back immediately

  // dbg_freeze_threads may delete some threads and render our 'thif' pointer invalid
  thif = get_thread(tid);
  if ( thif == NULL )
  {
    debdeb("thread %d disappeared after freezing?!...\n", tid);
    goto EVENT_READY; // report empty event to get called back immediately
  }

  event->pid = process_handle;
  event->tid = tid;
  if ( exited )
  {
    event->ea = BADADDR;
  }
  else if ( WIFSIGNALED(status) )
  {
    siginfo_t info;
    qptrace(PTRACE_GETSIGINFO, tid, NULL, &info);
    event->ea = (ea_t)(size_t)info.si_addr;
  }
  else
  {
    event->ea = get_ip(event->tid);
  }
  event->handled = false;
  if ( WIFSTOPPED(status) )
  {
    ea_t proc_ip;
    bool suspend;
    const exception_info_t *ei;
    int code = WSTOPSIG(status);
    event->eid = EXCEPTION;
    event->exc.code     = code;
    event->exc.can_cont = true;
    event->exc.ea       = BADADDR;
    if ( code == SIGSTOP )
    {
      if ( thif->waiting_sigstop )
      {
        log(tid, "got pending SIGSTOP!\n");
        thif->waiting_sigstop = false;
        goto RESUME; // silently resume the application
      }
      // convert SIGSTOP into simple PROCESS_SUSPEND, this will avoid
      // a dialog box about the signal. I'm not sure that this is a good thing
      // (probably better to report exceptions in the output windows rather than
      // in dialog boxes), so I'll comment it out for the moment.
      //event->eid = PROCESS_SUSPEND;
    }

    ei = find_exception(code);
    if ( ei != NULL )
    {
      qsnprintf(event->exc.info, sizeof(event->exc.info), "got %s signal (%s)", ei->name.c_str(), ei->desc.c_str());
      suspend = should_suspend_at_exception(event, ei);
      if ( !suspend && ei->handle() )
        code = 0;               // mask the signal
    }
    else
    {
      qsnprintf(event->exc.info, sizeof(event->exc.info), "got unknown signal #%d", code);
      suspend = true;
    }
    proc_ip = calc_bpt_event_ea(event); // if bpt, calc its address from event->ea
    if ( proc_ip != BADADDR )
    { // this looks like a bpt-related exception. it occurred either because
      // of our bpt either it was generated by the app.
      // by default, reset the code so we don't send any SIGTRAP signal to the debugged
      // process *except* in the case where the program generated the signal by
      // itself
      code = 0;
      if ( proc_ip == shlib_bpt.bpt_addr && shlib_bpt.bpt_addr != 0 )
      {
        log(tid, "got shlib bpt %a\n", proc_ip);
        // emulate return from function
        if ( !emulate_retn(tid) )
        {
          msg("%a: could not return from the shlib breakpoint!\n", proc_ip);
          return true;
        }
        if ( !gen_library_events(tid) ) // something has changed in shared libraries?
        { // no, nothing has changed
          log(tid, "nothing has changed in dlls\n");
RESUME:
          if ( !requested_to_suspend && !in_event )
          {
            ldeb("autoresuming\n");
//            QASSERT(30177, thif->state == STOPPED);
            resume_app(NO_THREAD);
            return false;
          }
          log(tid, "app may not run, keeping it suspended (%s)\n",
                        requested_to_suspend ? "requested_to_suspend" :
                        in_event ? "in_event" : "has_pending_events");
          event->eid = PROCESS_SUSPEND;
          return true;
        }
        log(tid, "gen_library_events ok\n");
        event->eid = NO_EVENT;
      }
      else if ( (proc_ip == birth_bpt.bpt_addr && birth_bpt.bpt_addr != 0)
             || (proc_ip == death_bpt.bpt_addr && death_bpt.bpt_addr != 0) )
      {
        log(tid, "got thread bpt %a (%s)\n", proc_ip, proc_ip == birth_bpt.bpt_addr ? "birth" : "death");
        size_t s = events.size();
        thread_handle = tid; // for ps_pdread
        // NB! if we don't do this, some running threads can interfere with thread_db
        tdb_handle_messages(tid);
        // emulate return from function
        if ( !emulate_retn(tid) )
        {
          msg("%a: could not return from the thread breakpoint!\n", proc_ip);
          return true;
        }
        if ( s == events.size() )
        {
          log(tid, "resuming after thread_bpt\n");
          goto RESUME;
        }
        event->eid = NO_EVENT;
      }
      else
      {
        // according to the requirement of commdbg a LIBRARY_LOAD event
        // should not be reported with the same thread/IP immediately after
        // a BPT-related event (see idd.hpp)
        // Here we put to the queue all already loaded (but not reported)
        // libraries to be sent _before_ BPT (do it only if ELF interpreter
        // is not yet loaded, otherwise LIBRARY_LOAD events will be generated
        // by shlib_bpt and thus they can not conflict with regular BPTs
        if ( interp.empty() )
        {
          gen_library_events(tid);
          thif = get_thread(tid);
        }
        if ( !handle_hwbpt(event) )
        {
          if ( bpts.find(proc_ip) != bpts.end()
            && !handling_lowcnds.has(proc_ip) )
          {
            event->eid     = BREAKPOINT;
            event->bpt.hea = BADADDR;
            event->bpt.kea = BADADDR;
            event->ea      = proc_ip;
          }
          else if ( thif != NULL && thif->single_step )
          {
            event->eid = STEP;
          }
          else
          {
            // in case of unknown breakpoints (icebp, int3, etc...) we must remember the signal
            // unless it should be masked
            if ( ei == NULL || !ei->handle() )
              code = event->exc.code;
          }
        }
      }
    }
    thif = get_thread(tid);
    if ( thif == NULL )
      goto EVENT_READY; // report empty event to get called back immediately
    thif->child_signum = code;
    if ( !requested_to_suspend && evaluate_and_handle_lowcnd(event) )
      return false;
    if ( !suspend && event->eid == EXCEPTION )
    {
      log_exception(event, ei);
      log(tid, "resuming after exception %d\n", code);
      goto RESUME;
    }
  }
  else
  {
    if ( WIFSIGNALED(status) )
    {
      int sig = WTERMSIG(status);
      debdeb("SIGNALED pid=%d tid=%d signal='%s'(%d) pc=%a\n", event->pid, event->tid, strsignal(sig), sig, event->ea);
      event->exit_code = sig;
    }
    else
    {
      event->exit_code = WEXITSTATUS(status);
    }
    if ( threads.size() <= 1 || thif->tid == process_handle )
    {
      event->eid = PROCESS_EXIT;
      exited = true;
    }
    else
    {
      log(tid, "got a thread exit\n");
      event->eid = NO_EVENT;
      dead_thread(event->tid, DEAD);
    }
  }
EVENT_READY:
  log(tid, "low got event: %s, signum=%d\n", debug_event_str(event), thif->child_signum);
  thif = get_thread(tid);
  if ( thif != NULL )
    thif->single_step = false;
  last_event = *event;
  return true;
}

//--------------------------------------------------------------------------
gdecode_t idaapi linux_debmod_t::dbg_get_debug_event(debug_event_t *event, int timeout_ms)
{
  QASSERT(30059, !in_event || exited);
  while ( true )
  {
    // are there any pending events?
    if ( !events.empty() )
    {
      // get the first event and return it
      *event = events.front();
      events.pop_front();
      if ( event->eid == NO_EVENT )
        continue;
      log(-1, "GDE1(handling_lowcnds.size()=%" FMT_Z "): %s\n", handling_lowcnds.size(), debug_event_str(event));
      in_event = true;
      if ( handling_lowcnds.empty() )
      {
        ldeb("requested_to_suspend := 0\n");
        requested_to_suspend = false;
      }
      return events.empty() ? GDE_ONE_EVENT : GDE_MANY_EVENTS;
    }

    debug_event_t ev;
    if ( !get_debug_event(&ev, timeout_ms) )
      break;
    enqueue_event(ev, IN_BACK);
  }
  return GDE_NO_EVENT;
}

//--------------------------------------------------------------------------
// R is running
// S is sleeping in an interruptible wait
// D is waiting in uninterruptible disk sleep
// Z is zombie
// T is traced or stopped (on a signal)
// W is paging
static char getstate(int tid)
{
  char buf[QMAXPATH];
  qsnprintf(buf, sizeof(buf), "/proc/%u/status", tid);
  FILE *fp = fopenRT(buf);
  qstring line;
  if ( fp == NULL
    || qgetline(&line, fp) < 0
    || qgetline(&line, fp) < 0 )
  {
    // no file or file read error (e.g. was deleted after successful fopenRT())
    return ' ';
  }
  char st;
  if ( qsscanf(line.c_str(), "State:  %c", &st) != 1 )
    INTERR(30060);
  qfclose(fp);
  return st;
}

//--------------------------------------------------------------------------
bool linux_debmod_t::has_pending_events(void)
{
  if ( !events.empty() )
    return true;

  for ( threads_t::iterator p=threads.begin(); p != threads.end(); ++p )
  {
    thread_info_t &ti = p->second;
    if ( ti.got_pending_status && ti.user_suspend == 0 && ti.suspend_count == 0 )
      return true;
  }
  return false;
}

//--------------------------------------------------------------------------
int linux_debmod_t::dbg_freeze_threads(thid_t tid, bool exclude)
{
  ldeb("  freeze_threads(%s %d) handling_lowcnds.size()=%" FMT_Z "\n", exclude ? "exclude" : "only", tid, handling_lowcnds.size());
  // first send all threads the SIGSTOP signal, as fast as possible
  typedef qvector<thread_info_t *> queue_t;
  queue_t queue;
  qvector<thid_t> deadtids;
  for ( threads_t::iterator p=threads.begin(); p != threads.end(); ++p )
  {
    if ( (p->first == tid) == exclude )
      continue;
    thread_info_t &ti = p->second;
    if ( ti.is_running() )
    {
      if ( qkill(ti.tid, SIGSTOP) != 0 )
      {
        // In some cases the thread may already be dead but we are not aware
        // of it (for example, if many threads died at once, the events
        // will be queued and not processed yet.
        if ( errno == ESRCH )
          deadtids.push_back(ti.tid);
        else
          dmsg("failed to send SIGSTOP to thread %d: %s\n", ti.tid, strerror(errno));
        continue;
      }
      queue.push_back(&ti);
      ti.waiting_sigstop = true;
    }
    ti.suspend_count++;
  }
  // then wait for the SIGSTOP signals to arrive
  while ( !queue.empty() )
  {
    int status = 0;
    int stid = check_for_signal(&status, -1, exited ? -1 : 0);
    if ( stid > 0 )
    {
      // if more signals are to arrive, enable the waiter
      for ( queue_t::iterator p=queue.begin(); p != queue.end(); ++p )
      {
        thread_info_t &ti = **p;
        if ( ti.tid == stid )
        {
          if ( WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP )
          {
            // suspended successfully
            ti.waiting_sigstop = false;
            set_thread_state(ti, STOPPED);
          }
          else
          { // got another signal, SIGSTOP will arrive later
            store_pending_signal(stid, status);
          }
          stid = -1;
          queue.erase(p);
          break;
        }
      }
    }
    if ( stid > 0 ) // got a signal for some other thread
      store_pending_signal(stid, status);
  }

  // clean up dead threads
  for ( int i=0; i < deadtids.size(); i++ )
    dead_thread(deadtids[i], DEAD);

#ifdef LDEB
  for ( threads_t::iterator p=threads.begin(); p != threads.end(); ++p )
  {
    if ( (p->first == tid) != exclude )
    {
      thid_t tid2 = p->first;
      log(tid2, "suspendd (ip=%08a)\n", get_ip(tid2));
    }
  }
#endif
  return 1;
}

//--------------------------------------------------------------------------
int linux_debmod_t::dbg_thaw_threads(thid_t tid, bool exclude)
{
  int ok = 1;
  ldeb("  thaw_threads(%s %d), may_run=%d handlng_lowcnd.size()=%" FMT_Z " npending_signals=%d\n", exclude ? "exclude" : "only", tid, may_run, handling_lowcnds.size(), npending_signals);
  for ( threads_t::iterator p=threads.begin(); p != threads.end(); ++p )
  {
    if ( (p->first == tid) == exclude )
      continue;

    thread_info_t &ti = p->second;
    log(ti.tid, "(ip=%08a) ", get_ip(ti.tid));

    if ( ti.is_running() )
    {
      QASSERT(30188, ti.suspend_count == 0);
      ldeb("already running\n");
      continue;
    }

    if ( ti.suspend_count > 0 && --ti.suspend_count > 0 )
    {
      ldeb("suspended\n");
      continue;
    }
    if ( ti.user_suspend > 0 )
    {
      ldeb("user suspended\n");
      continue;
    }

    if ( ti.got_pending_status )
    {
      ldeb("have pending signal\n");
      continue;
    }

    if ( (!may_run && ti.state != DYING) || exited )
    {
      ldeb("!may_run\n");
      continue;
    }

    if ( ti.state == STOPPED || ti.state == DYING )
    {
      __ptrace_request request = ti.single_step ? PTRACE_SINGLESTEP : PTRACE_CONT;
#ifdef LDEB
      char ostate = getstate(ti.tid);
#endif
      ldeb("really resuming\n");
      if ( qptrace(request, ti.tid, 0, (void *)(size_t)(ti.child_signum)) != 0 && ti.state != DYING )
      {
        ldeb("    !! failed to resume thread (error %d)\n", errno);
        if ( getstate(ti.tid) != 'Z' )
        {
          ok = 0;
          continue;
        }
        // we have a zombie thread
        // report its death
        dead_thread(ti.tid, DYING);
      }
      if ( ti.state == DYING )
      {
        set_thread_state(ti, DEAD);
      }
      else
      {
        QASSERT(30178, ti.state == STOPPED);
        set_thread_state(ti, RUNNING);
      }
      ldeb("PTRACE_%s, signum=%d, old_state: '%c', new_state: '%c'\n", request == PTRACE_SINGLESTEP ? "SINGLESTEP" : "CONT", ti.child_signum, ostate, getstate(ti.tid));
    }
    else
    {
      ldeb("ti.state is not stopped or dying\n");
    }
  }
  return ok;
}

//--------------------------------------------------------------------------
bool linux_debmod_t::suspend_all_threads(void)
{
  return dbg_freeze_threads(NO_THREAD);
}

//--------------------------------------------------------------------------
bool linux_debmod_t::resume_all_threads(void)
{
  return dbg_thaw_threads(NO_THREAD);
}

//--------------------------------------------------------------------------
// 1-ok, 0-failed
int idaapi linux_debmod_t::dbg_continue_after_event(const debug_event_t *event)
{
  if ( event == NULL )
    return 0;

  int tid = event->tid;
  thread_info_t *t = get_thread(tid);
  if ( t == NULL && event->eid != THREAD_EXIT && !exited )
  {
    dwarning("could not find thread %d!\n", tid);
    return 0;
  }

  ldeb("continue after event %s%s\n", debug_event_str(event), has_pending_events() ? " (there are pending events)" : "");

  if ( t != NULL )
  {
    if ( event->eid != THREAD_START
      && event->eid != THREAD_EXIT
      && event->eid != LIBRARY_LOAD
      && event->eid != LIBRARY_UNLOAD
      && (event->eid != EXCEPTION || event->handled) )
    {
      t->child_signum = 0;
    }

    if ( t->state == DYING )
    {
      // this thread is about to exit; resume it so it can do so
      t->suspend_count = 0;
      t->user_suspend = 0;
      dbg_thaw_threads(t->tid, false);
    }
    else if ( t->state == DEAD )
    {
      // remove from internal list
      del_thread(event->tid);
    }

    // ensure TF bit is not set (if we aren't single stepping) after a SIGTRAP
    // because TF bit may still be set
    if ( event->eid == EXCEPTION && !t->single_step
      && event->exc.code == SIGTRAP && event->handled )
      clear_tbit(event->tid);
  }

  in_event = false;
  return resume_app(NO_THREAD);
}

//--------------------------------------------------------------------------
// if tid is specified, resume only it.
bool linux_debmod_t::resume_app(thid_t tid)
{
  may_run = !handling_lowcnds.empty() || !has_pending_events();
  if ( may_run && handling_lowcnds.empty() )
  {
    if ( !removed_bpts.empty() )
    {
      for ( easet_t::iterator p=removed_bpts.begin(); p != removed_bpts.end(); ++p )
        bpts.erase(*p);
      removed_bpts.clear();
    }
  }

  return tid == NO_THREAD
       ? resume_all_threads()
       : dbg_thaw_threads(tid, false);
}

// PTRACE_PEEKTEXT / PTRACE_POKETEXT operate on unsigned long values! (i.e. 4 bytes on x86 and 8 bytes on x64)
#define PEEKSIZE sizeof(unsigned long)

//--------------------------------------------------------------------------
int linux_debmod_t::_read_memory(int tid, ea_t ea, void *buffer, int size, bool suspend)
{
  if ( exited || process_handle == INVALID_HANDLE_VALUE )
    return 0;

  // stop all threads before accessing the process memory
  if ( suspend )
    suspend_all_threads();

  if ( tid == -1 )
    tid = process_handle;

  int read_size = 0;
  bool tried_mem = false;
  bool tried_peek = false;
  // don't use memory for short reads
  if ( size > 3 * PEEKSIZE )
  {
TRY_MEMFILE:
#ifndef __ANDROID__
    char filename[64];
    qsnprintf (filename, sizeof(filename), "/proc/%d/mem", tid);
    int fd = open(filename, O_RDONLY | O_LARGEFILE);
    if ( fd != -1 )
    {
      read_size = pread64(fd, buffer, size, ea);
      close(fd);
    }
    // msg("%d: pread64 %d:%a:%d => %d\n", tid, fd, ea, size, read_size);

#ifdef LDEB
    if ( read_size < size )
      perror("read_memory: pread64 failed");
#endif
#endif
    tried_mem = true;
  }

  if ( read_size != size && !tried_peek )
  {
    uchar *ptr = (uchar *)buffer;
    read_size = 0;
    tried_peek = true;
    while ( read_size < size )
    {
      const int shift = ea & (PEEKSIZE-1);
      int nbytes = shift == 0 ? PEEKSIZE : PEEKSIZE - shift;
      if ( nbytes > (size - read_size) )
        nbytes = size - read_size;
      errno = 0;
      unsigned long v = qptrace(PTRACE_PEEKTEXT, tid, (void *)(size_t)(ea-shift), 0);
      if ( errno != 0 )
      {
        ldeb("PEEKTEXT %d:%a => %s\n", tid, ea-shift, strerror(errno));
        break;
      }
      else
      {
        //msg("PEEKTEXT %d:%a => OK\n", tid, ea-shift);
      }
      if ( nbytes == PEEKSIZE )
      {
        *(unsigned long*)ptr = v;
      }
      else
      {
        v >>= shift*8;
        for ( int i=0; i < nbytes; i++ )
        {
          ptr[i] = uchar(v);
          v >>= 8;
        }
      }
      ptr  += nbytes;
      ea   += nbytes;
      read_size += nbytes;
    }
  }

  // sometimes PEEKTEXT fails but memfile succeeds... so try both
  if ( read_size < size && !tried_mem )
    goto TRY_MEMFILE;

  if ( suspend )
    resume_all_threads();
  // msg("READ MEMORY (%d): %d\n", tid, read_size);
  return read_size > 0 ? read_size : 0;
}

//--------------------------------------------------------------------------
int linux_debmod_t::_write_memory(int tid, ea_t ea, const void *buffer, int size, bool suspend)
{
  if ( exited || process_handle == INVALID_HANDLE_VALUE )
    return 0;

#ifndef LDEB
  if ( debug_debugger )
#endif
    show_hex(buffer, size, "WRITE MEMORY %a %d bytes:\n", ea, size);

  // stop all threads before accessing the process memory
  if ( suspend )
    suspend_all_threads();


  if ( tid == -1 )
    tid = process_handle;

  int ok = size;
  const uchar *ptr = (const uchar *)buffer;
  errno = 0;

  while ( size > 0 )
  {
    const int shift = ea & (PEEKSIZE-1);
    int nbytes = shift == 0 ? PEEKSIZE : PEEKSIZE - shift;
    if ( nbytes > size )
      nbytes = size;
    unsigned long word;
    memcpy(&word, ptr, qmin(sizeof(word), nbytes)); // use memcpy() to read unaligned bytes
    if ( nbytes != PEEKSIZE )
    {
      unsigned long old = qptrace(PTRACE_PEEKTEXT, tid, (void *)(size_t)(ea-shift), 0);
      if ( errno != 0 )
      {
        ok = 0;
        break;
      }
      unsigned long mask = ~0;
      mask >>= (PEEKSIZE - nbytes)*8;
      mask <<= shift*8;
      word <<= shift*8;
      word &= mask;
      word |= old & ~mask;
    }
    errno = 0;
    qptrace(PTRACE_POKETEXT, process_handle, (void *)(size_t)(ea-shift), (void *)word);
    if ( errno )
    {
      errno = 0;
      qptrace(PTRACE_POKEDATA, process_handle, (void *)(size_t)(ea-shift), (void *)word);
    }
    if ( errno )
    {
      ok = 0;
      break;
    }
    ptr  += nbytes;
    ea   += nbytes;
    size -= nbytes;
  }

  if ( suspend )
    resume_all_threads();

  return ok;
}

//--------------------------------------------------------------------------
ssize_t idaapi linux_debmod_t::dbg_write_memory(ea_t ea, const void *buffer, size_t size)
{
  return _write_memory(-1, ea, buffer, size, true);
}

//--------------------------------------------------------------------------
ssize_t idaapi linux_debmod_t::dbg_read_memory(ea_t ea, void *buffer, size_t size)
{
  return _read_memory(-1, ea, buffer, size, true);
}

//--------------------------------------------------------------------------
void linux_debmod_t::add_dll(ea_t base, asize_t size, const char *modname, const char *soname)
{
  debdeb("%a: new dll %s (soname=%s)\n", base, modname, soname);
  debug_event_t ev;
  ev.eid     = LIBRARY_LOAD;
  ev.pid     = process_handle;
  ev.tid     = process_handle;
  ev.ea      = base;
  ev.handled = true;
  qstrncpy(ev.modinfo.name, modname, sizeof(ev.modinfo.name));
  ev.modinfo.base = base;
  ev.modinfo.size = size;
  ev.modinfo.rebase_to = BADADDR;
  if ( is_dll && input_file_path == modname )
    ev.modinfo.rebase_to = base;
  enqueue_event(ev, IN_FRONT);

  image_info_t ii(base, ev.modinfo.size, modname, soname);
  dlls.insert(make_pair(ii.base, ii));
  dlls_to_import.insert(ii.base);
}

//#define DIFV_DEB
#include "../../plugins/dwarf/look_for_debug_file.cpp"

//--------------------------------------------------------------------------
bool linux_debmod_t::import_dll(image_info_t &ii, name_info_t &ni)
{
  struct dll_symbol_importer_t : public symbol_visitor_t
  {
    linux_debmod_t *ld;
    image_info_t &ii;
    name_info_t &ni;
    dll_symbol_importer_t(linux_debmod_t *_ld, image_info_t &_ii, name_info_t &_ni)
      : symbol_visitor_t(VISIT_SYMBOLS|VISIT_BUILDID|VISIT_DBGLINK),
      ld(_ld),
      ii(_ii),
      ni(_ni)
    {}
    int visit_symbol(ea_t ea, const char *name)
    {
      ea += ii.base;
      ni.addrs.push_back(ea);
      ni.names.push_back(qstrdup(name));
      ii.names[ea] = name;
      // every 10000th name send a message to ida - we are alive!
      if ( (ni.addrs.size() % 10000) == 0 )
        ld->dmsg("");
      return 0;
    }
    int visit_buildid(const char *buildid)
    {
      ii.buildid = buildid;
      ld->debdeb("Build ID '%s' of '%s'\n", buildid, ii.fname.c_str());
      return 0;
    }
    int visit_debuglink(const char *debuglink, uint32 crc)
    {
      ii.debuglink = debuglink;
      ii.dl_crc = crc;
      ld->debdeb("debuglink '%s' of '%s'\n", debuglink, ii.fname.c_str());
      return 0;
    }
  };
  if ( ii.base == BADADDR )
  {
    debdeb("Can't import symbols from %s: no imagebase\n", ii.fname.c_str());
    return false;
  }
  dll_symbol_importer_t dsi(this, ii, ni);
  return load_elf_symbols(ii.fname.c_str(), dsi) == 0;
}

//--------------------------------------------------------------------------
// enumerate names from the specified shared object and save the results
// we'll need to send it to IDA later
// if libname == NULL, enum all modules
void linux_debmod_t::enum_names(const char *libname)
{
  if ( dlls_to_import.empty() )
    return;

  for ( easet_t::iterator p=dlls_to_import.begin(); p != dlls_to_import.end(); )
  {
    images_t::iterator q = dlls.find(*p);
    if ( q != dlls.end() )
    {
      image_info_t &ii = q->second;
      if ( libname != NULL && strcmp(libname, ii.soname.c_str()) != 0 )
      {
        ++p;
        continue;
      }
      if ( stristr(ii.soname.c_str(), "libpthread") != NULL )
      { // keep nptl names in a separate list to be able to resolve them any time
        nptl_base = ii.base;
        import_dll(ii, nptl_names);
        // Try to locate file with the separate debug info.
        // FIXME: should we check that libpthread lacks symbols for libthread_db?
        // Library.so usually contains debuglink which points to itself,
        // so we need to avoid to load library.so another time.
        debug_info_file_visitor_t dif(
                debug_file_directory.c_str(),
                true,
                ii.fname.c_str(),
                ii.debuglink.c_str(),
                ii.dl_crc,
                ii.buildid.c_str());
        if ( dif.accept() != 0 && ii.fname != dif.fullpath )
        {
          debdeb("load separate debug info '%s'\n", dif.fullpath);
          image_info_t ii_deb(nptl_base, 0, dif.fullpath, "");
          import_dll(ii_deb, nptl_names);
        }
        pending_names.addrs.insert(pending_names.addrs.end(), nptl_names.addrs.begin(), nptl_names.addrs.end());
        pending_names.names.insert(pending_names.names.end(), nptl_names.names.begin(), nptl_names.names.end());
        for ( int i=0; i < nptl_names.names.size(); i++ )
          nptl_names.names[i] = qstrdup(nptl_names.names[i]);
      }
      else
      {
        import_dll(ii, pending_names);
      }
    }
    dlls_to_import.erase(p++);
  }
}

//--------------------------------------------------------------------------
ea_t linux_debmod_t::find_pending_name(const char *name)
{
  if ( name == NULL )
    return BADADDR;
  // enumerate pending names in reverse order. we need this to find the latest
  // resolved address for a name (on android, pthread_..() functions exist twice)
  for ( int i=pending_names.addrs.size()-1; i >= 0; --i )
    if ( streq(pending_names.names[i], name) )
      return pending_names.addrs[i];
  for ( int i=0; i < nptl_names.addrs.size(); ++i )
    if ( streq(nptl_names.names[i], name) )
      return nptl_names.addrs[i];
  return BADADDR;
}

//--------------------------------------------------------------------------
void idaapi linux_debmod_t::dbg_stopped_at_debug_event(void)
{
  // we will take advantage of this event to import information
  // about the exported functions from the loaded dlls
  enum_names();

  name_info_t &ni = *get_debug_names();
  ni = pending_names; // NB: ownership of name pointers is transferred
  pending_names.clear();
}

//--------------------------------------------------------------------------
void linux_debmod_t::cleanup(void)
{
  // if the process is still running, kill it, otherwise it runs uncontrolled
  // normally the process is dead at this time but may survive if we arrive
  // here after an interr.
  if ( process_handle != INVALID_HANDLE_VALUE )
    dbg_exit_process();
  process_handle = INVALID_HANDLE_VALUE;
  thread_handle  = INVALID_HANDLE_VALUE;
  is_dll = false;
  requested_to_suspend = false;
  in_event = false;

  threads.clear();
  dlls.clear();
  dlls_to_import.clear();
  events.clear();
  if ( mapfp != NULL )
  {
    qfclose(mapfp);
    mapfp = NULL;
  }

  complained_shlib_bpt = false;
  bpts.clear();

  tdb_delete();
  erase_internal_bp(birth_bpt);
  erase_internal_bp(death_bpt);
  erase_internal_bp(shlib_bpt);
  npending_signals = 0;
  interp.clear();
  exe_path.qclear();
  exited = false;

  for ( int i=0; i < nptl_names.names.size(); i++ )
    qfree(nptl_names.names[i]);
  nptl_names.clear();

  inherited::cleanup();
}

//--------------------------------------------------------------------------
//
//      DEBUGGER INTERFACE FUNCTIONS
//
//--------------------------------------------------------------------------
inline const char *skipword(const char *ptr)
{
  while ( !qisspace(*ptr) && *ptr != '\0' )
    ptr++;
  return ptr;
}

//--------------------------------------------------------------------------
// find a dll in the memory information array
static const memory_info_t *find_dll(const meminfo_vec_t &miv, const char *name)
{
  for ( int i=0; i < miv.size(); i++ )
    if ( miv[i].name == name )
      return &miv[i];
  return NULL;
}

//--------------------------------------------------------------------------
static memory_info_t *find_dll(meminfo_vec_t &miv, const char *name)
{
  return CONST_CAST(memory_info_t *)(find_dll(CONST_CAST(const meminfo_vec_t &)(miv), name));
}

//--------------------------------------------------------------------------
static const memory_info_t *find_basename_dll(const meminfo_vec_t &miv, const char *name)
{
  const char *dll_file = qbasename(name);
  if ( dll_file != NULL )
  {
    for ( int i=0; i < miv.size(); i++ )
    {
      const char *miv_file = qbasename(miv[i].name.c_str());
      if ( streq(miv_file, dll_file) )
        return &miv[i];
    }
  }
  return NULL;
}

//--------------------------------------------------------------------------
bool linux_debmod_t::add_shlib_bpt(const meminfo_vec_t &miv, bool attaching)
{
  if ( shlib_bpt.bpt_addr != 0 )
    return true;

  qstring interp_soname;
  if ( interp.empty() )
  {
    // find out the loader name
    struct interp_finder_t : public symbol_visitor_t
    {
      qstring interp;
      interp_finder_t(void) : symbol_visitor_t(VISIT_INTERP) {}
      int visit_symbol(ea_t, const char *) { return 0; } // unused
      int visit_interp(const char *name)
      {
        interp = name;
        return 2;
      }
    };
    interp_finder_t itf;
    const char *exename = exe_path.c_str();
    int code = load_elf_symbols(exename, itf);
    if ( code == 0 )
    { // no interpreter
      if ( !complained_shlib_bpt )
      {
        complained_shlib_bpt = true;
        dwarning("%s:\n"
                 "Could not find the elf interpreter name,\n"
                 "shared object events will not be reported", exename);
      }
      return false;
    }
    if ( code != 2 )
    {
      dwarning("%s: could not read symbols on remote computer", exename);
      return false;
    }
    char path[QMAXPATH];
    qmake_full_path(path, sizeof(path), itf.interp.c_str());
    interp_soname.swap(itf.interp);
    interp = path;
  }
  else
  {
    interp_soname = qbasename(interp.c_str());
  }

  // check if it is present in the memory map (normally it is)
  debdeb("INTERP: %s, SONAME: %s\n", interp.c_str(), interp_soname.c_str());
  const memory_info_t *mi = find_dll(miv, interp.c_str());
  if ( mi == NULL )
  {
    dwarning("%s: could not find in process memory", interp.c_str());
    return false;
  }

  asize_t size = calc_module_size(miv, mi);
  add_dll(mi->start_ea, size, interp.c_str(), interp_soname.c_str());

  // set bpt at r_brk
  enum_names(interp_soname.c_str()); // update the name list
  const char *bpt_name = "_r_debug";
  ea_t ea = find_pending_name(bpt_name);
  if ( ea != BADADDR )
  {
    struct r_debug rd;
    if ( _read_memory(-1, ea, &rd, sizeof(rd), false) == sizeof(rd) )
    {
      if ( rd.r_brk != 0 )
      {
        if ( !add_internal_bp(shlib_bpt, rd.r_brk) )
        {
          ea_t ea1 = rd.r_brk;
          debdeb("%a: could not set shlib bpt\n", ea1);
        }
      }
    }
  }
  if ( shlib_bpt.bpt_addr == 0 )
  {
    static const char *const shlib_bpt_names[] =
    {
      "r_debug_state",
      "_r_debug_state",
      "_dl_debug_state",
      "rtld_db_dlactivity",
      "_rtld_debug_state",
      NULL
    };

    for ( int i=0; i < qnumber(shlib_bpt_names); i++ )
    {
      bpt_name = shlib_bpt_names[i];
      ea = find_pending_name(bpt_name);
      if ( ea != BADADDR && ea != 0 )
      {
        if ( add_internal_bp(shlib_bpt, ea) )
          break;
        debdeb("%a: could not set shlib bpt (name=%s)\n", ea, bpt_name);
      }
    }
    if ( shlib_bpt.bpt_addr == 0 )
    {
#if defined(__ANDROID__) && !defined(__X64__)
      // Last attempt for old Android,
      // the modern Android doesn't need the special handling
      return add_android_shlib_bpt(miv, attaching);
#else
      qnotused(attaching);
      return false;
#endif
    }
  }
  debdeb("%a: added shlib bpt (%s)\n", shlib_bpt.bpt_addr, bpt_name);
  return true;
}

//--------------------------------------------------------------------------
void linux_debmod_t::add_thread(int tid)
{
  threads.insert(std::make_pair(tid, thread_info_t(tid)));
}

//--------------------------------------------------------------------------
void linux_debmod_t::del_thread(int tid)
{
  threads_t::iterator p = threads.find(tid);
  QASSERT(30064, p != threads.end());
  if ( p->second.got_pending_status )
    npending_signals--;
  threads.erase(p);

  if ( deleted_threads.size() >= 10 )
    deleted_threads.erase(deleted_threads.begin());

  deleted_threads.push_back(tid);
}

//--------------------------------------------------------------------------
bool linux_debmod_t::handle_process_start(pid_t _pid, attach_mode_t attaching)
{
  pid = _pid;
  deleted_threads.clear();
  process_handle = pid;
  add_thread(pid);
  int status;
  int options = 0;
  if ( attaching == AMT_ATTACH_BROKEN )
    options = WNOHANG;
  qwait(&status, pid, options); // (should succeed) consume SIGSTOP
  debdeb("process pid/tid: %d\n", pid);
  may_run = false;

  debug_event_t ev;
  ev.eid     = PROCESS_START;
  ev.pid     = pid;
  ev.tid     = pid;
  ev.ea      = get_ip(pid);
  ev.handled = true;
  get_exec_fname(pid, ev.modinfo.name, sizeof(ev.modinfo.name));
  ev.modinfo.base = BADADDR;
  ev.modinfo.size = 0;
  ev.modinfo.rebase_to = BADADDR;

  char fname[QMAXPATH];
  qsnprintf(fname, sizeof(fname), "/proc/%u/maps", pid);
  mapfp = fopenRT(fname);
  if ( mapfp == NULL )
  {
    dmsg("%s: %s\n", fname, winerr(errno));
    return false;               // if fails, the process did not start
  }

  exe_path = ev.modinfo.name;
  if ( !is_dll )
    input_file_path = exe_path;

  // find the executable base
  meminfo_vec_t miv;
  // init debapp_attrs.addrsize: 32bit application by default
  // get_memory_info() may correct it if meets a 64-bit address
  debapp_attrs.addrsize = 4;
  if ( get_memory_info(miv, false) <= 0 )
    INTERR(30065);

  if ( is_dll && find_dll(miv, input_file_path.c_str()) == NULL )
  {
    const memory_info_t *mi = find_basename_dll(miv, input_file_path.c_str());
    if ( mi != NULL )
      input_file_path = mi->name;
  }

  const memory_info_t *mi = find_dll(miv, ev.modinfo.name);
  if ( mi != NULL )
  {
    ev.modinfo.base = mi->start_ea;
    ev.modinfo.size = mi->end_ea - mi->start_ea;
    if ( !is_dll ) // exe files: rebase idb to the loaded address
      ev.modinfo.rebase_to = mi->start_ea;
  }
  else
  {
    if ( !is_dll )
      dmsg("%s: nowhere in the process memory?!\n", ev.modinfo.name);
  }

  if ( !add_shlib_bpt(miv, attaching) )
    dmsg("Could not set the shlib bpt, shared object events will not be handled\n");

  enqueue_event(ev, IN_BACK);
  if ( attaching )
  {
    ev.eid = PROCESS_ATTACH;
    enqueue_event(ev, IN_BACK);
    if ( !qgetenv("IDA_SKIP_SYMS", NULL) )
    {
      // collect exported names from the main module
      qstring soname;
      get_soname(ev.modinfo.name, &soname);
      image_info_t ii(ev.modinfo.base, ev.modinfo.size, ev.modinfo.name, soname);
      import_dll(ii, pending_names);
    }
  }
  return true;
}

//--------------------------------------------------------------------------
static void idaapi kill_all_processes(void)
{
  struct ida_local process_killer_t : public debmod_visitor_t
  {
    int visit(debmod_t *debmod)
    {
      linux_debmod_t *ld = (linux_debmod_t *)debmod;
      if ( ld->process_handle != INVALID_HANDLE_VALUE )
        qkill(ld->process_handle, SIGKILL);
      return 0;
    }
  };
  process_killer_t pk;
  for_all_debuggers(pk);
}

//--------------------------------------------------------------------------
int idaapi linux_debmod_t::dbg_start_process(
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
    && !handle_process_start(size_t(child_pid), AMT_NO_ATTACH) )
  {
    dbg_exit_process();
    code = -1;
  }
  return code;
}

//--------------------------------------------------------------------------
// 1-ok, 0-failed
int idaapi linux_debmod_t::dbg_attach_process(pid_t _pid, int /*event_id*/, int flags)
{
  is_dll = (flags & DBG_PROC_IS_DLL) != 0;
  if ( qptrace(PTRACE_ATTACH, _pid, NULL, NULL) == 0
    && handle_process_start(_pid, AMT_ATTACH_NORMAL) )
  {
    gen_library_events(_pid); // detect all loaded libraries
    return true;
  }
  qptrace(PTRACE_DETACH, _pid, NULL, NULL);
  return false;
}

//--------------------------------------------------------------------------
void linux_debmod_t::cleanup_signals(void)
{
  for ( threads_t::iterator p=threads.begin(); p != threads.end(); ++p )
  {
    // can not leave pending sigstop, try to recieve and handle it
    if ( p->second.waiting_sigstop )
    {
      thread_info_t &ti = p->second;
      ldeb("cleanup_signals:\n");
      log(ti.tid, "must be STOPPED\n");
      QASSERT(30181, ti.state == STOPPED);
      qptrace(PTRACE_CONT, ti.tid, 0, 0);
      int status;
      int tid = check_for_signal(&status, ti.tid, -1);
      if ( tid != ti.tid )
        msg("%d: failed to clean up pending SIGSTOP\n", tid);
    }
  }
}

//--------------------------------------------------------------------------
void linux_debmod_t::cleanup_breakpoints(void)
{
  erase_internal_bp(birth_bpt);
  erase_internal_bp(death_bpt);
  erase_internal_bp(shlib_bpt);
}

//--------------------------------------------------------------------------
// 1-ok, 0-failed
int idaapi linux_debmod_t::dbg_detach_process(void)
{
  // restore only internal breakpoints and signals
  cleanup_breakpoints();
  cleanup_signals();

  bool had_pid = false;
  bool ok = true;
  log(-1, "detach all threads.\n");
  for ( threads_t::iterator p=threads.begin(); ok && p != threads.end(); ++p )
  {
    thread_info_t &ti = p->second;
    if ( ti.tid == process_handle )
      had_pid = true;

    ok = qptrace(PTRACE_DETACH, ti.tid, NULL, NULL) == 0;
    log(-1, "detach tid %d: ok=%d\n", ti.tid, ok);
  }

  if ( ok && !had_pid )
  {
    // if pid was not in the thread list, detach it separately
    ok = qptrace(PTRACE_DETACH, process_handle, NULL, NULL) == 0;
    log(-1, "detach pid %d: ok=%d\n", process_handle, ok);
  }
  if ( ok )
  {
    debug_event_t ev;
    ev.eid     = PROCESS_DETACH;
    ev.pid     = process_handle;
    ev.tid     = process_handle;
    ev.ea      = BADADDR;
    ev.handled = true;
    enqueue_event(ev, IN_BACK);
    in_event = false;
    exited = true;
    threads.clear();
    process_handle = INVALID_HANDLE_VALUE;
    return 1;
  }
  return 0;
}

//--------------------------------------------------------------------------
// if we have to do something as soon as we noticed the connection
// broke, this is the correct place
bool idaapi linux_debmod_t::dbg_prepare_broken_connection(void)
{
  broken_connection = true;
  return true;
}

//--------------------------------------------------------------------------
// 1-ok, 0-failed
int idaapi linux_debmod_t::dbg_prepare_to_pause_process(void)
{
  if ( events.empty() )
  {
    qkill(process_handle, SIGSTOP);
    thread_info_t &ti = threads.begin()->second;
    ti.waiting_sigstop = true;
  }
  may_run = false;
  requested_to_suspend = true;
  ldeb("requested_to_suspend := 1\n");

  return true;
}

//--------------------------------------------------------------------------
// 1-ok, 0-failed
int idaapi linux_debmod_t::dbg_exit_process(void)
{
  ldeb("------- exit process\n");
  bool ok = true;
  // suspend all threads to avoid problems (for example, killing a
  // thread may resume another thread and it can throw an exception because
  // of that)
  suspend_all_threads();
  for ( threads_t::iterator p=threads.begin(); p != threads.end(); ++p )
  {
    thread_info_t &ti = p->second;
    if ( ti.state == STOPPED )
    {
      if ( qptrace(PTRACE_KILL, ti.tid, 0, (void*)SIGKILL) != 0 && errno != ESRCH )
      {
        dmsg("PTRACE_KILL %d: %s\n", ti.tid, strerror(errno));
        ok = false;
      }
    }
    else
    {
      if ( ti.tid != INVALID_HANDLE_VALUE && qkill(ti.tid, SIGKILL) != 0 && errno != ESRCH )
      {
        dmsg("SIGKILL %d: %s\n", ti.tid, strerror(errno));
        ok = false;
      }
    }
    if ( ok )
    {
      set_thread_state(ti, RUNNING);
      ti.suspend_count = 0;
      ti.suspend_count = 0;
    }
  }
  if ( ok )
    process_handle = INVALID_HANDLE_VALUE;
  may_run = true;
  exited = true;
  return ok;
}

//--------------------------------------------------------------------------
// Set hardware breakpoints for one thread
bool linux_debmod_t::set_hwbpts(HANDLE hThread)
{
#ifdef __ARM__
  qnotused(hThread);
  return false;
#else
  bool ok = set_dr(hThread, 0, hwbpt_ea[0])
         && set_dr(hThread, 1, hwbpt_ea[1])
         && set_dr(hThread, 2, hwbpt_ea[2])
         && set_dr(hThread, 3, hwbpt_ea[3])
         && set_dr(hThread, 6, 0)
         && set_dr(hThread, 7, dr7);
  // msg("set_hwbpts: DR0=%a DR1=%a DR2=%a DR3=%a DR7=%a => %d\n",
  //       hwbpt_ea[0],
  //       hwbpt_ea[1],
  //       hwbpt_ea[2],
  //       hwbpt_ea[3],
  //       dr7,
  //       ok);
  return ok;
#endif
}

//--------------------------------------------------------------------------
bool linux_debmod_t::refresh_hwbpts(void)
{
  for ( threads_t::iterator p=threads.begin(); p != threads.end(); ++p )
    if ( !set_hwbpts(p->second.tid) )
      return false;
  return true;
}

//--------------------------------------------------------------------------
bool linux_debmod_t::erase_internal_bp(internal_bpt &bp)
{
  bool ok = bp.bpt_addr == 0 || dbg_del_bpt(BPT_SOFT, bp.bpt_addr, bp.saved, bp.nsaved);
  bp.bpt_addr = 0;
  bp.nsaved = 0;
  return ok;
}

//--------------------------------------------------------------------------
bool linux_debmod_t::add_internal_bp(internal_bpt &bp, ea_t addr)
{
  int len = -1;
  int nread = sizeof(bp.saved);
#ifdef __ARM__
  if ( (addr & 1) != 0 )
  {
    len = 2;
    addr--;
  }
  else
  {
    len = 4;
  }
  CASSERT(sizeof(bp.saved) >= 4);
  nread = len;
#endif
  if ( _read_memory(-1, addr, bp.saved, nread) == nread )
  {
    if ( dbg_add_bpt(BPT_SOFT, addr, len) )
    {
      bp.bpt_addr = addr;
      bp.nsaved = nread;
      return true;
    }
  }
  return false;
}

//--------------------------------------------------------------------------
// 1-ok, 0-failed
int idaapi linux_debmod_t::dbg_add_bpt(bpttype_t type, ea_t ea, int len)
{
  ldeb("%a: add bpt (size=%d)\n", ea, len);
  if ( type == BPT_SOFT )
  {
    const uchar *bptcode = bpt_code.begin();
#ifdef __ARM__
# ifdef __X64__
    if ( len < 0 )
      len = bpt_code.size();
    bptcode = aarch64_bpt;
# else
    if ( len < 0 )
    { // unknown mode. we have to decide between thumb and arm bpts
      // ideally we would decode the instruction and try to determine its mode
      // unfortunately we do not have instruction decoder in arm server.
      // besides, it can not really help.
      // just check for some known opcodes. this is bad but i do not know
      // how to do better.

      len = 4; // default to arm mode
      uchar opcodes[2];
      if ( dbg_read_memory(ea, opcodes, sizeof(opcodes)) == sizeof(opcodes) )
      {
        static const uchar ins1[] = { 0x70, 0x47 }; // BX      LR
        static const uchar ins3[] = { 0x00, 0xB5 }; // PUSH    {LR}
        static const uchar ins2[] = { 0x00, 0xBD }; // POP     {PC}
        static const uchar *const ins[] = { ins1, ins2, ins3 };
        for ( int i=0; i < qnumber(ins); i++ )
        {
          const uchar *p = ins[i];
          if ( opcodes[0] == p[0] && opcodes[1] == p[1] )
          {
            len = 2;
            break;
          }
        }
      }
    }
    if ( len == 2 )
    {
      bptcode = thumb16_bpt;
    }
    else if ( len == (2 | USE_THUMB32_BPT) )
    { // thumb32 bpt
      len = 4;
      bptcode = thumb32_bpt;
    }
# endif
#else
    if ( len < 0 )
      len = bpt_code.size();
#endif
    QASSERT(30066, len > 0 && len <= bpt_code.size());
    debmod_bpt_t dbpt(ea, len);
    if ( dbg_read_memory(ea, &dbpt.saved, len) && dbg_write_memory(ea, bptcode, len) == len )
    {
      bpts[ea] = dbpt;
      removed_bpts.erase(ea);
      return true;
    }
  }

#ifndef __ARM__
  return add_hwbpt(type, ea, len);
#else
  return false;
#endif
}

//--------------------------------------------------------------------------
#ifdef __ARM__
int linux_debmod_t::read_bpt_orgbytes(ea_t *p_ea, int *p_len, uchar *buf, int bufsize)
{
  int nread = inherited::read_bpt_orgbytes(p_ea, p_len, buf, bufsize);
  // for thumb mode we have to decide between 16-bit and 32-bit bpt
  if ( nread > 0 && *p_len == 2 )
  {
    uint16 opcode = buf[0] | (buf[1] << 8);
    if ( is_32bit_thumb_insn(opcode) )
    {
      if ( dbg_read_memory(*p_ea+2, &buf[2], 2) <= 0 ) // read the remaining 2 bytes
        return -1;
      nread = 4;
      *p_len |= USE_THUMB32_BPT; // ask for thumb32 bpt
    }
  }
  return nread;
}
#endif

//--------------------------------------------------------------------------
// 1-ok, 0-failed
int idaapi linux_debmod_t::dbg_del_bpt(bpttype_t type, ea_t ea, const uchar *orig_bytes, int len)
{
  ldeb("%a: del bpt (size=%d) exited=%d\n", ea, len, exited);
  if ( orig_bytes != NULL )
  {
    if ( dbg_write_memory(ea, orig_bytes, len) == len )
    {
      removed_bpts.insert(ea);
      return true;
    }
  }

#ifdef __ARM__
  qnotused(type);
  return false;
#else
  return del_hwbpt(ea, type);
#endif
}

//--------------------------------------------------------------------------
// 1-ok, 0-failed
int idaapi linux_debmod_t::dbg_thread_get_sreg_base(ea_t *pea, thid_t tid, int sreg_value)
{
#ifdef __ARM__
  qnotused(tid);
  qnotused(sreg_value);
  qnotused(pea);
  return 0;
#else
  // find out which selector we're asked to retrieve
  struct user_regs_struct regs;
  if ( qptrace(PTRACE_GETREGS, tid, 0, &regs) != 0 )
    return 0;

#ifdef __X64__
#define INTEL_REG(reg) reg
#else
#define INTEL_REG(reg) x##reg
#endif

  if ( sreg_value == regs.INTEL_REG(fs) )
    return thread_get_fs_base(tid, R_FS, pea);
  else if ( sreg_value == regs.INTEL_REG(gs) )
    return thread_get_fs_base(tid, R_GS, pea);
  else
    *pea = 0; // all other selectors (cs, ds) usually have base of 0...
  return 1;
#endif
}

//--------------------------------------------------------------------------
// 1-ok, 0-failed
int idaapi linux_debmod_t::dbg_thread_suspend(thid_t tid)
{
  thread_info_t *ti = get_thread(tid);
  if ( ti == NULL )
    return false;
  if ( !dbg_freeze_threads(tid, false) )
    return false;
  ti->user_suspend++;
  return true;
}

//--------------------------------------------------------------------------
// 1-ok, 0-failed
int idaapi linux_debmod_t::dbg_thread_continue(thid_t tid)
{
  thread_info_t *ti = get_thread(tid);
  if ( ti == NULL )
    return false;
  if ( ti->user_suspend > 0 )
  {
    if ( --ti->user_suspend > 0 )
      return true;
  }
  return dbg_thaw_threads(tid, false);
}

//--------------------------------------------------------------------------
// 1-ok, 0-failed
int idaapi linux_debmod_t::dbg_set_resume_mode(thid_t tid, resume_mode_t resmod)
{
  if ( resmod != RESMOD_INTO )
    return 0; // not supported

  thread_info_t *t = get_thread(tid);
  if ( t == NULL )
    return false;
  t->single_step = true;
  return true;
}

#ifdef __ARM__
# ifdef __X64__
//--------------------------------------------------------------------------
// AArch64
//--------------------------------------------------------------------------
bool linux_debmod_t::emulate_retn(int tid)
{
  struct user_pt_regs regset;
  struct iovec iov;
  iov.iov_base = &regset;
  iov.iov_len = sizeof (struct user_pt_regs);
  if ( qptrace(PTRACE_GETREGSET, tid, (void *)NT_PRSTATUS, &iov) != 0 )
    return false;

  // emulate BX LR
  regset.pc = regset.regs[LRREG_IDX];    // PC <- LR

  return qptrace(PTRACE_SETREGSET, tid, (void *)NT_PRSTATUS, &iov) == 0;
}

//--------------------------------------------------------------------------
int idaapi linux_debmod_t::dbg_read_registers(thid_t tid, int clsmask, regval_t *values)
{
  if ( values == NULL || (clsmask & ARM_RC_GENERAL) == 0 )
    return 0;

  struct user_pt_regs regset;
  if ( !ptrace_getregset(&regset, tid) )
    return 0;

  for ( int i=0; i < AARCH64_X_REGS_NUM; ++i )
    values[i].ival = regset.regs[i];
  values[SPREG_IDX].ival = regset.sp;
  values[PCREG_IDX].ival = regset.pc;
  values[CPSR_IDX ].ival = regset.pstate;   // 32-bit
  return 1;
}

//--------------------------------------------------------------------------
void patch_reg(struct user_pt_regs *regset, int idx, const regval_t *value)
{
  if ( idx < AARCH64_X_REGS_NUM )
    regset->regs[idx] = value->ival;
  else if ( idx == SPREG_IDX )
    regset->sp = value->ival;
  else if ( idx == PCREG_IDX )
    regset->pc = value->ival;
  else
    regset->pstate = value->ival;   // 32-bit
}

//--------------------------------------------------------------------------
int idaapi linux_debmod_t::dbg_write_register(thid_t tid, int reg_idx, const regval_t *value)
{
  if ( value == NULL || reg_idx < 0 || reg_idx > CPSR_IDX )
    return 0;

  struct user_pt_regs regset;
  struct iovec iov;
  iov.iov_base = &regset;
  iov.iov_len = sizeof (struct user_pt_regs);
  if ( qptrace(PTRACE_GETREGSET, tid, (void *)NT_PRSTATUS, &iov) != 0 )
    return 0;

  if ( reg_idx == PCREG_IDX )
    ldeb("NEW EIP: %08" FMT_64 "X\n", value->ival);

  patch_reg(&regset, reg_idx, value);

  return qptrace(PTRACE_SETREGSET, tid, (void *)NT_PRSTATUS, &iov) == 0;
}

//--------------------------------------------------------------------------
bool idaapi linux_debmod_t::write_registers(
        thid_t tid,
        int start,
        int count,
        const regval_t *values,
        const int *indices)
{
  if ( values == NULL )
    return 0;

  struct user_pt_regs regset;
  struct iovec iov;
  iov.iov_base = &regset;
  iov.iov_len = sizeof (struct user_pt_regs);
  if ( qptrace(PTRACE_GETREGSET, tid, (void *)NT_PRSTATUS, &iov) != 0 )
    return 0;

  for ( int i=0; i < count; ++i, ++values )
  {
    int idx = indices != NULL ? indices[i] : start + i;
    if ( idx > CPSR_IDX )
      return 0;
    patch_reg(&regset, idx, values);
  }

  return qptrace(PTRACE_SETREGSET, tid, (void *)NT_PRSTATUS, &iov) == 0;
}

# else  // __ARM__ && !__X64__

//--------------------------------------------------------------------------
// ARM (32-bit)
//--------------------------------------------------------------------------
bool linux_debmod_t::emulate_retn(int tid)
{
  struct user_regs_struct regs;
  qptrace(PTRACE_GETREGS, tid, 0, &regs);
  // emulate BX LR
  int tbit = regs.uregs[14] & 1;
  regs.PCREG = regs.uregs[14] & ~1;    // PC <- LR
  setflag(regs.uregs[16], 1<<5, tbit); // Set/clear T bit in PSR
  return qptrace(PTRACE_SETREGS, tid, 0, &regs) == 0;
}

#ifdef __HAVE_ARM_VFP__
//----------------------------------------------------------------------------
static void convert_vfp_registers(regval_t *values, user_vfp_regs_t *registers)
{
  for ( int i = R_D0; i <= R_D31; i++ )
    values[i].set_bytes((uchar*)(&registers->fpregs[i-R_D0]), sizeof(int64));
  values[R_FPSCR].ival = registers->fpscr;
}
#endif

//--------------------------------------------------------------------------
int idaapi linux_debmod_t::dbg_read_registers(thid_t tid, int clsmask, regval_t *values)
{
  if ( values == NULL || (clsmask & ARM_RC_ALL) == 0 )
    return 0;

  if ( (clsmask & ARM_RC_GENERAL) != 0 )
  {
    struct user_regs_struct regs;
    if ( qptrace(PTRACE_GETREGS, tid, 0, &regs) != 0 )
      return 0;

    values[R_R0].ival     = regs.uregs[0];
    values[R_R1].ival     = regs.uregs[1];
    values[R_R2].ival     = regs.uregs[2];
    values[R_R3].ival     = regs.uregs[3];
    values[R_R4].ival     = regs.uregs[4];
    values[R_R5].ival     = regs.uregs[5];
    values[R_R6].ival     = regs.uregs[6];
    values[R_R7].ival     = regs.uregs[7];
    values[R_R8].ival     = regs.uregs[8];
    values[R_R9].ival     = regs.uregs[9];
    values[R_R10].ival    = regs.uregs[10];
    values[R_R11].ival    = regs.uregs[11];
    values[R_R12].ival    = regs.uregs[12];
    values[R_SP].ival     = regs.uregs[13];
    values[R_LR].ival     = regs.uregs[14];
    values[R_PC].ival     = regs.uregs[15];
    values[R_PSR].ival    = regs.uregs[16];
  }

#ifdef __HAVE_ARM_VFP__
  if ( (clsmask & ARM_RC_VFP) != 0 )
  {
    user_vfp_regs_t vfp_regs;
    memset(&vfp_regs, 0, sizeof(vfp_regs));
    if ( qptrace(PTRACE_GETVFPREGS, tid, 0, &vfp_regs) != 0 && clsmask == ARM_RC_VFP )
      return 0;

    convert_vfp_registers(values, &vfp_regs);
  }
#endif

  return 1;
}

//--------------------------------------------------------------------------
int idaapi linux_debmod_t::dbg_write_register(thid_t tid, int reg_idx, const regval_t *value)
{
  struct user_regs_struct regs;
  if ( value == NULL || reg_idx < 0 || reg_idx > ARM_MAXREG )
    return 0;
#ifdef __HAVE_ARM_VFP__
  if ( reg_idx < R_D0 )
  {
#endif
    if ( qptrace(PTRACE_GETREGS, tid, 0, &regs) != 0 )
      return 0;

    if ( reg_idx == PCREG_IDX )
      ldeb("NEW EIP: %08" FMT_64 "X\n", value->ival);

    // patch
    regs.uregs[reg_idx] = value->ival;

    return qptrace(PTRACE_SETREGS, tid, 0, &regs) == 0;
#ifdef __HAVE_ARM_VFP__
  }
  else
  {
    user_vfp_regs_t vfp_regs;
    memset(&vfp_regs, 0, sizeof(vfp_regs));
    if ( qptrace(PTRACE_GETVFPREGS, tid, 0, &vfp_regs) != 0 )
      return 0;

    if ( reg_idx == R_FPSCR )
      vfp_regs.fpscr = int32(value->ival);
    else
      vfp_regs.fpregs[reg_idx-R_D0] = *((int64*)(value->get_data()));

    return qptrace(PTRACE_SETVFPREGS, tid, 0, &vfp_regs) == 0;
  }
#endif
}

//--------------------------------------------------------------------------
bool idaapi linux_debmod_t::write_registers(
        thid_t tid,
        int start,
        int count,
        const regval_t *values,
        const int *indices)
{
  if ( values == NULL )
    return 0;

  struct user_regs_struct regs;
  if ( qptrace(PTRACE_GETREGS, tid, 0, &regs) != 0 )
    return 0;
#ifdef __HAVE_ARM_VFP__
  user_vfp_regs_t vfp_regs;
  bool have_vfp = true;
  if ( qptrace(PTRACE_GETVFPREGS, tid, 0, &vfp_regs) != 0 )
      have_vfp = false;
#endif
  for ( int i=0; i < count; ++i, ++values )
  {
    int idx = indices != NULL ? indices[i] : start + i;
    if ( idx < R_D0 )
    {
      regs.uregs[idx] = values->ival;
    }
#ifdef __HAVE_ARM_VFP__
    else if ( have_vfp )
    {
      if ( idx == R_FPSCR )
        vfp_regs.fpscr = int32(values->ival);
      else
        vfp_regs.fpregs[idx-R_D0] = *((int64*)(values->get_data()));
    }
#endif
  }

  int code = qptrace(PTRACE_SETREGS, tid, 0, &regs);
#ifdef __HAVE_ARM_VFP__
  if ( have_vfp )
    code = code || qptrace(PTRACE_SETVFPREGS, tid, 0, &vfp_regs);
#endif
  return code == 0;
}

# endif
#else     // !__ARM__

//--------------------------------------------------------------------------
// X86/X64
//--------------------------------------------------------------------------
bool linux_debmod_t::emulate_retn(int tid)
{
  struct user_regs_struct regs;
  qptrace(PTRACE_GETREGS, tid, 0, &regs);
  if ( _read_memory(tid, regs.SPREG, &regs.PCREG, sizeof(regs.PCREG), false) != sizeof(regs.PCREG) )
  {
    log(-1, "%d: reading return address from %a failed\n", tid, ea_t(regs.SPREG));
    if ( tid == process_handle )
      return false;
    if ( _read_memory(process_handle, regs.SPREG, &regs.PCREG, sizeof(regs.PCREG), false) != sizeof(regs.PCREG) )
    {
      log(-1, "%d: reading return address from %a failed (2)\n", process_handle, ea_t(regs.SPREG));
      return false;
    }
  }
  regs.SPREG += sizeof(regs.PCREG);
  log(-1, "%d: retn to %a\n", tid, ea_t(regs.PCREG));
  return qptrace(PTRACE_SETREGS, tid, 0, &regs) == 0;
}

//-------------------------------------------------------------------------
enum
{
  TAG_VALID = 0,
  TAG_ZERO = 1,
  TAG_SPECIAL = 2,
  TAG_EMPTY = 3,
};

//--------------------------------------------------------------------------
int idaapi linux_debmod_t::dbg_read_registers(thid_t tid, int clsmask, regval_t *values)
{
  if ( values == NULL )
    return 0;

  struct user_regs_struct regs;
  if ( qptrace(PTRACE_GETREGS, tid, 0, &regs) != 0 )
    return false;

#ifdef __X64__
#define SRCREG_XAX rax
#define SRCREG_XBX rbx
#define SRCREG_XCX rcx
#define SRCREG_XDX rdx
#define SRCREG_XSI rsi
#define SRCREG_XBP rbp
#define SRCREG_XSP rsp
#define SRCREG_XDI rdi
#define SRCREG_XIP rip
#define SRCREG_XCS cs
#define SRCREG_XDS ds
#define SRCREG_XES es
#define SRCREG_XFS fs
#define SRCREG_XGS gs
#define SRCREG_XSS ss
#else
#define SRCREG_XAX eax
#define SRCREG_XBX ebx
#define SRCREG_XCX ecx
#define SRCREG_XDX edx
#define SRCREG_XSI esi
#define SRCREG_XBP ebp
#define SRCREG_XSP esp
#define SRCREG_XDI edi
#define SRCREG_XIP eip
#define SRCREG_XCS xcs
#define SRCREG_XDS xds
#define SRCREG_XES xes
#define SRCREG_XFS xfs
#define SRCREG_XGS xgs
#define SRCREG_XSS xss
#endif

#if defined(__EA64__)
  if ( (clsmask & X86_RC_GENERAL) != 0 )
  {
    values[R_EAX].ival    = regs.SRCREG_XAX;
    values[R_EBX].ival    = regs.SRCREG_XBX;
    values[R_ECX].ival    = regs.SRCREG_XCX;
    values[R_EDX].ival    = regs.SRCREG_XDX;
    values[R_ESI].ival    = regs.SRCREG_XSI;
    values[R_EDI].ival    = regs.SRCREG_XDI;
    values[R_EBP].ival    = regs.SRCREG_XBP;
    values[R_ESP].ival    = regs.SRCREG_XSP;
    values[R_EIP].ival    = regs.SRCREG_XIP;
#ifdef __X64__
    values[R64_R8 ].ival  = regs.r8;
    values[R64_R9 ].ival  = regs.r9;
    values[R64_R10].ival  = regs.r10;
    values[R64_R11].ival  = regs.r11;
    values[R64_R12].ival  = regs.r12;
    values[R64_R13].ival  = regs.r13;
    values[R64_R14].ival  = regs.r14;
    values[R64_R15].ival  = regs.r15;
#endif // __X64__
    values[R_EFLAGS].ival = regs.eflags;
  }
  if ( (clsmask & X86_RC_SEGMENTS) != 0 )
  {
    values[R_CS    ].ival = regs.SRCREG_XCS;
    values[R_DS    ].ival = regs.SRCREG_XDS;
    values[R_ES    ].ival = regs.SRCREG_XES;
    values[R_FS    ].ival = regs.SRCREG_XFS;
    values[R_GS    ].ival = regs.SRCREG_XGS;
    values[R_SS    ].ival = regs.SRCREG_XSS;
  }
#else
  if ( (clsmask & X86_RC_GENERAL) != 0 )
  {
    values[R_EAX   ].ival = uint32(regs.SRCREG_XAX);
    values[R_EBX   ].ival = uint32(regs.SRCREG_XBX);
    values[R_ECX   ].ival = uint32(regs.SRCREG_XCX);
    values[R_EDX   ].ival = uint32(regs.SRCREG_XDX);
    values[R_ESI   ].ival = uint32(regs.SRCREG_XSI);
    values[R_EDI   ].ival = uint32(regs.SRCREG_XDI);
    values[R_EBP   ].ival = uint32(regs.SRCREG_XBP);
    values[R_ESP   ].ival = uint32(regs.SRCREG_XSP);
    values[R_EIP   ].ival = uint32(regs.SRCREG_XIP);
    values[R_EFLAGS].ival = uint32(regs.eflags);
  }
  if ( (clsmask & X86_RC_SEGMENTS) != 0 )
  {
    values[R_CS    ].ival = uint32(regs.SRCREG_XCS);
    values[R_DS    ].ival = uint32(regs.SRCREG_XDS);
    values[R_ES    ].ival = uint32(regs.SRCREG_XES);
    values[R_FS    ].ival = uint32(regs.SRCREG_XFS);
    values[R_GS    ].ival = uint32(regs.SRCREG_XGS);
    values[R_SS    ].ival = uint32(regs.SRCREG_XSS);
  }
#endif

#ifdef __X64__
  // 64-bit version uses one struct to return xmm & fpu
  if ( (clsmask & (X86_RC_XMM|X86_RC_FPU|X86_RC_MMX)) != 0 )
  {
    struct user_fpregs_struct i387;
    if ( qptrace(PTRACE_GETFPREGS, tid, 0, &i387) != 0 )
      return false;

    if ( (clsmask & (X86_RC_FPU|X86_RC_MMX)) != 0 )
    {
      bool fpu = (clsmask & X86_RC_FPU) != 0;
      if ( fpu )
      {
        values[R_CTRL].ival = i387.cwd;
        values[R_STAT].ival = i387.swd;
        values[R_TAGS].ival = i387.ftw;
      }
      read_fpu_registers(
              values,
              clsmask,
              i387.st_space, sizeof(i387.st_space)/8);

      if ( fpu )
      {
        // fix 'ftag':
        // ---
        // Byte 4 is used for an abridged version of the x87 FPU Tag
        // Word (FTW). The following items describe its usage:
        // — For each j, 0 <= j <= 7, FXSAVE saves a 0 into bit j of
        //   byte 4 if x87 FPU data register STj has a empty tag;
        //   otherwise, FXSAVE saves a 1 into bit j of byte 4.
        // (...)
        // ---
        // See also the opposite conversion when writing registers
        // (look for 'abridged'.)
        uchar abridged = values[R_TAGS].ival & 0xff;
        int top = ((values[R_STAT].ival) >> 11) & 0x7;
        ushort ftag = 0;
        for ( int st_idx = 7; st_idx >= 0; --st_idx )
        {
          ushort tag = TAG_EMPTY;
          const uchar *p = (const uchar *) &values[R_ST0 + st_idx].ival;
          if ( (abridged & (1 << st_idx)) != 0 )
          {
            int actual_st = R_ST0 + ((st_idx + 8 - top) % 8);
            p = (const uchar *) &values[actual_st].ival;
            bool integer = (p[7] & 0x80) != 0;
            uint32 exp = ((p[9] & 0x7f) << 8) | p[8];
            uint32 frac0 = ((p[3] << 24) | (p[2] << 16) | (p[1] << 8) | p[0]);
            uint32 frac1 = (((p[7] & 0x7f) << 24) | (p[6] << 16) | (p[5] << 8) | p[4]);
            if ( exp == 0x7fff )
              tag = TAG_SPECIAL;
            else if ( exp == 0 )
              tag = (frac0 == 0 && frac1 == 0 && !integer) ? TAG_ZERO : TAG_SPECIAL;
            else
              tag = integer ? TAG_VALID : TAG_SPECIAL;
          }
          ftag |= tag << (2 * st_idx);
        }
        values[R_TAGS].ival = ftag;
      }
    }
    if ( (clsmask & X86_RC_XMM) != 0 )
    {
      uchar *xptr = (uchar *)i387.xmm_space;
      for ( int i=R_XMM0; i < R_MXCSR; i++,xptr+=16 )
        values[i].set_bytes(xptr, 16);
      values[R_MXCSR].ival = i387.mxcsr;
    }
  }
#else
  // 32-bit version uses two different structures to return xmm & fpu
  if ( (clsmask & X86_RC_XMM) != 0 )
  {
    struct user_fpxregs_struct x387;
    if ( qptrace(PTRACE_GETFPXREGS, tid, 0, &x387) != 0 )
      return false;

    uchar *xptr = (uchar *)x387.xmm_space;
    for ( int i=R_XMM0; i < R_MXCSR; i++,xptr+=16 )
      values[i].set_bytes(xptr, 16);
    values[R_MXCSR].ival = x387.mxcsr;
  }
  if ( (clsmask & (X86_RC_FPU|X86_RC_MMX)) != 0 )
  {
    struct user_fpregs_struct i387;
    if ( qptrace(PTRACE_GETFPREGS, tid, 0, &i387) != 0 )
      return false;

    if ( (clsmask & X86_RC_FPU) != 0 )
    {
      values[R_CTRL].ival = uint32(i387.cwd);
      values[R_STAT].ival = uint32(i387.swd);
      values[R_TAGS].ival = uint32(i387.twd);
    }
    read_fpu_registers(values, clsmask, i387.st_space, sizeof(i387.st_space)/8);
  }
#endif
  return true;
}

//--------------------------------------------------------------------------
// 1-ok, 0-failed
static bool patch_reg_context(
        struct user_regs_struct *regs,
        struct user_fpregs_struct *i387,
        struct user_fpxregs_struct *x387,
        int reg_idx,
        const regval_t *value)
{
  if ( value == NULL )
    return false;

#if defined(__X64__)
  qnotused(x387);
#endif

  int regclass = get_x86_reg_class(reg_idx);
  if ( (regclass & (X86_RC_GENERAL|X86_RC_SEGMENTS)) != 0 )
  {
    if ( regs == NULL )
      return false;
    switch ( reg_idx )
    {
#if defined(__EA64__)
      case R_CS:     regs->SRCREG_XCS = value->ival; break;
      case R_DS:     regs->SRCREG_XDS = value->ival; break;
      case R_ES:     regs->SRCREG_XES = value->ival; break;
      case R_FS:     regs->SRCREG_XFS = value->ival; break;
      case R_GS:     regs->SRCREG_XGS = value->ival; break;
      case R_SS:     regs->SRCREG_XSS = value->ival; break;
      case R_EAX:    regs->SRCREG_XAX = value->ival; break;
      case R_EBX:    regs->SRCREG_XBX = value->ival; break;
      case R_ECX:    regs->SRCREG_XCX = value->ival; break;
      case R_EDX:    regs->SRCREG_XDX = value->ival; break;
      case R_ESI:    regs->SRCREG_XSI = value->ival; break;
      case R_EDI:    regs->SRCREG_XDI = value->ival; break;
      case R_EBP:    regs->SRCREG_XBP = value->ival; break;
      case R_ESP:    regs->SRCREG_XSP = value->ival; break;
      case R_EIP:    regs->SRCREG_XIP = value->ival; break;
#ifdef __X64__
      case R64_R8:   regs->r8     = value->ival; break;
      case R64_R9 :  regs->r9     = value->ival; break;
      case R64_R10:  regs->r10    = value->ival; break;
      case R64_R11:  regs->r11    = value->ival; break;
      case R64_R12:  regs->r12    = value->ival; break;
      case R64_R13:  regs->r13    = value->ival; break;
      case R64_R14:  regs->r14    = value->ival; break;
      case R64_R15:  regs->r15    = value->ival; break;
#endif // __X64__
#else
      case R_CS:     regs->SRCREG_XCS = value->ival; break;
      case R_DS:     regs->SRCREG_XDS = value->ival; break;
      case R_ES:     regs->SRCREG_XES = value->ival; break;
      case R_FS:     regs->SRCREG_XFS = value->ival; break;
      case R_GS:     regs->SRCREG_XGS = value->ival; break;
      case R_SS:     regs->SRCREG_XSS = value->ival; break;
      case R_EAX:    regs->SRCREG_XAX = value->ival; break;
      case R_EBX:    regs->SRCREG_XBX = value->ival; break;
      case R_ECX:    regs->SRCREG_XCX = value->ival; break;
      case R_EDX:    regs->SRCREG_XDX = value->ival; break;
      case R_ESI:    regs->SRCREG_XSI = value->ival; break;
      case R_EDI:    regs->SRCREG_XDI = value->ival; break;
      case R_EBP:    regs->SRCREG_XBP = value->ival; break;
      case R_ESP:    regs->SRCREG_XSP = value->ival; break;
      case R_EIP:    regs->SRCREG_XIP = value->ival; break;
#endif
      case R_EFLAGS: regs->eflags = value->ival; break;
    }
  }
  else if ( (regclass & X86_RC_XMM) != 0 )
  {
    if ( XMM_STRUCT == NULL )
      return false;
    if ( reg_idx == R_MXCSR )
    {
      XMM_STRUCT->mxcsr = value->ival;
    }
    else
    {
      uchar *xptr = (uchar *)XMM_STRUCT->xmm_space + (reg_idx - R_XMM0) * 16;
      const void *vptr = value->get_data();
      size_t size = value->get_data_size();
      memcpy(xptr, vptr, qmin(size, 16));
    }
  }
  else if ( (regclass & X86_RC_FPU) != 0 )
  { // FPU register
    if ( i387 == NULL )
      return false;
    if ( reg_idx >= R_ST0+FPU_REGS_COUNT ) // FPU status registers
    {
      switch ( reg_idx )
      {
        case R_CTRL:   i387->cwd = value->ival; break;
        case R_STAT:   i387->swd = value->ival; break;
        case R_TAGS:
#ifdef __X64__
          // => abridged
          // See also the opposite conversion when reading registers
          // (look for 'abridged'.)
          //
          // NOTE: This assumes that i387->swd _IS UP-TO-DATE_. If it
          // has to be overwritten later in the same batch of updates,
          // its new value won't be used here.
          {
            ushort expanded = value->ival;
            uchar tags = 0;
            int top = (i387->swd >> 11) & 0x7;
            for ( int st_idx = 7; st_idx >= 0; --st_idx )
              if ( ((expanded >> 2 * st_idx) & 3) != TAG_EMPTY )
                tags |= uchar(1 << ((st_idx + 8 - top) % 8));
            i387->TAGS_REG = tags;
          }
#else
          i387->TAGS_REG = value->ival;
#endif
          break;
      }
    }
    else // FPU floating point register
    {
      uchar *fpu_float = (uchar *)i387->st_space;
      fpu_float += (reg_idx-R_ST0) * sizeof(i387->st_space)/8;
      memcpy(fpu_float, value->fval, 10);
    }
  }
  else if ( (regclass & X86_RC_MMX) != 0 )
  {
    if ( i387 == NULL )
      return false;
    uchar *fpu_float = (uchar *)i387->st_space;
    fpu_float += (reg_idx-R_MMX0) * sizeof(i387->st_space)/8;
    memcpy(fpu_float, value->get_data(), 8);
  }
  return true;
}

//--------------------------------------------------------------------------
// 1-ok, 0-failed
int idaapi linux_debmod_t::dbg_write_register(thid_t tid, int reg_idx, const regval_t *value)
{
  if ( value == NULL )
    return false;

  bool ret = false;
  int regclass = get_x86_reg_class(reg_idx);
  if ( (regclass & CLASS_OF_INTREGS) != 0 )
  {
    struct user_regs_struct regs;
    if ( qptrace(PTRACE_GETREGS, tid, 0, &regs) != 0 )
      return false;

    if ( reg_idx == PCREG_IDX )
    {
      ldeb("NEW EIP: %08" FMT_64 "X\n", value->ival);
    }

    if ( !patch_reg_context(&regs, NULL, NULL, reg_idx, value) )
      return false;

    ret = qptrace(PTRACE_SETREGS, tid, 0, &regs) != -1;
  }
  else if ( (regclass & CLASSES_STORED_IN_FPREGS) != 0 )
  {
    struct user_fpregs_struct i387;
    if ( qptrace(PTRACE_GETFPREGS, tid, 0, &i387) != 0 )
      return false;

    if ( !patch_reg_context(NULL, &i387, NULL, reg_idx, value) )
      return false;

    ret = qptrace(PTRACE_SETFPREGS, tid, 0, &i387) != -1;
  }
#ifndef __X64__ // only for 32-bit debugger we have to handle xmm registers separately
  else if ( (regclass & X86_RC_XMM) != 0 )
  {
    struct user_fpxregs_struct x387;
    if ( qptrace(PTRACE_GETFPXREGS, tid, 0, &x387) != 0 )
      return false;

    if ( !patch_reg_context(NULL, NULL, &x387, reg_idx, value) )
      return false;

    ret = qptrace(PTRACE_SETFPXREGS, tid, 0, &x387) != -1;
  }
#endif
  return ret;
}

//--------------------------------------------------------------------------
bool idaapi linux_debmod_t::write_registers(
        thid_t tid,
        int start,
        int count,
        const regval_t *values,
        const int *indices)
{
  struct user_regs_struct regs;
  struct user_fpregs_struct i387;
#if !defined( __X64__)
  // only for 32-bit debugger we have to handle xmm registers separately
  struct user_fpxregs_struct x387;
#define X387_PTR &x387
#else
#define X387_PTR NULL
#endif
  bool got_regs = false;
  bool got_i387 = false;
#ifndef __X64__
  bool got_x387 = false;
#endif

  for ( int i=0; i < count; i++, values++ )
  {
    int idx = indices != NULL ? indices[i] : start+i;
    int regclass = get_x86_reg_class(idx);
    if ( (regclass & CLASS_OF_INTREGS) != 0 )
    { // general register
      if ( !got_regs )
      {
        if ( qptrace(PTRACE_GETREGS, tid, 0, &regs) != 0 )
          return false;
        got_regs = true;
      }
    }
    else if ( (regclass & CLASSES_STORED_IN_FPREGS) != 0 )
    { // fpregs register
      if ( !got_i387 )
      {
        if ( qptrace(PTRACE_GETFPREGS, tid, 0, &i387) != 0 )
          return false;
        got_i387 = true;
      }
    }
#ifndef __X64__
    else if ( (regclass & X86_RC_XMM) != 0 )
    {
      if ( !got_x387 )
      {
        if ( qptrace(PTRACE_GETFPXREGS, tid, 0, &x387) != 0 )
          return false;
        got_x387 = true;
      }
    }
#endif
    if ( !patch_reg_context(&regs, &i387, X387_PTR, idx, values) )
      return false;
  }

  if ( got_regs && qptrace(PTRACE_SETREGS, tid, 0, &regs) == -1 )
    return false;

#ifndef __X64__
  // The order of the following calls is VERY IMPORTANT so as PTRACE_SETFPXREGS
  // can spoil FPU registers.
  // The subsequent call to PTRACE_SETFPREGS will correct them.
  // Could it be better to get rid of PTRACE_SETFPREGS and use
  // PTRACE_SETFPXREGS for both FPU and XMM registers instead?
  if ( got_x387 )
  {
    if ( qptrace(PTRACE_SETFPXREGS, tid, 0, &x387) == -1 )
      return false;
  }
#endif
  if ( got_i387 )
  {
    if ( qptrace(PTRACE_SETFPREGS, tid, 0, &i387) == -1 )
      return false;
  }

  return true;
}
#endif // !__ARM__

//--------------------------------------------------------------------------
// find DT_SONAME of a elf image directly from the memory
bool linux_debmod_t::get_soname(const char *fname, qstring *soname)
{
  struct dll_soname_finder_t : public symbol_visitor_t
  {
    qstring *soname;
    dll_soname_finder_t(qstring *res) : symbol_visitor_t(VISIT_DYNINFO), soname(res) {}
    virtual int visit_dyninfo(uint64 tag, const char *name, uint64 /*value*/)
    {
      if ( tag == DT_SONAME )
      {
        *soname = name;
        return 1;
      }
      return 0;
    }
  };

  dll_soname_finder_t dsf(soname);
  return load_elf_symbols(fname, dsf) == 1;
}

//--------------------------------------------------------------------------
asize_t linux_debmod_t::calc_module_size(const meminfo_vec_t &miv, const memory_info_t *mi)
{
  QASSERT(30067, miv.begin() <= mi && mi < miv.end());
  ea_t start = mi->start_ea;
  ea_t end   = mi->end_ea;
  if ( end == 0 )
    return 0; // unknown size
  const qstring &name = mi->name;
  while ( ++mi != miv.end() )
  {
    if ( name != mi->name )
      break;
    end = mi->end_ea;
  }
  QASSERT(30068, end > start);
  return end - start;
}

//--------------------------------------------------------------------------
// may add/del threads!
void linux_debmod_t::handle_dll_movements(const meminfo_vec_t &_miv)
{
  ldeb("handle_dll_movements\n");

  // first, merge memory ranges by module
  meminfo_vec_t miv;
  for ( size_t i = 0, n = _miv.size(); i < n; ++i )
  {
    const memory_info_t &src = _miv[i];

    // See if we already registered a module with that name.
    memory_info_t *target = find_dll(miv, src.name.c_str());
    if ( target != NULL )
    {
      // Found one. Let's make sure it contains our addresses.
      target->extend(src.start_ea);
      target->extend(src.end_ea);
    }
    else
    {
      miv.push_back(src);
    }
  }

  // unload missing dlls
  images_t::iterator p;
  for ( p=dlls.begin(); p != dlls.end(); )
  {
    image_info_t &ii = p->second;
    const char *fname = ii.fname.c_str();
    if ( find_dll(miv, fname) == NULL )
    {
      if ( !del_pending_event(LIBRARY_LOAD, fname) )
      {
        debug_event_t ev;
        ev.eid     = LIBRARY_UNLOAD;
        ev.pid     = process_handle;
        ev.tid     = process_handle;
        ev.ea      = BADADDR;
        ev.handled = true;
        qstrncpy(ev.info, fname, sizeof(ev.info));
        enqueue_event(ev, IN_FRONT);
      }
      dlls.erase(p++);
    }
    else
    {
      ++p;
    }
  }

  // load new dlls
  int n = miv.size();
  for ( int i=0; i < n; i++ )
  {
    // ignore unnamed dlls
    if ( miv[i].name.empty() )
      continue;

    // ignore the input file
    if ( !is_dll && miv[i].name == input_file_path )
      continue;

    // ignore if dll already exists
    ea_t base = miv[i].start_ea;
    p = dlls.find(base);
    if ( p != dlls.end() )
      continue;

    // ignore memory chunks which do not correspond to an ELF header
    char magic[4];
    if ( _read_memory(-1, base, &magic, 4, false) != 4 )
      continue;

    if ( memcmp(magic, "\x7F\x45\x4C\x46", 4) != 0 )
      continue;

    qstring soname;
    const char *modname = miv[i].name.c_str();
    get_soname(modname, &soname);
    asize_t size = calc_module_size(miv, &miv[i]);
    add_dll(base, size, modname, soname.c_str());
  }
  if ( !dlls_to_import.empty() )
    tdb_new(); // initialize multi-thread support
}

//--------------------------------------------------------------------------
// this function has a side effect: it sets debapp_attrs.addrsize to 8
// if founds a 64-bit address in the mapfile
bool linux_debmod_t::read_mapping(mapfp_entry_t *me)
{
  qstring line;
  if ( qgetline(&line, mapfp) <= 0 )
    return false;

  me->ea1 = BADADDR;
  me->bitness = 0;
  int len = 0;
  int code = qsscanf(line.begin(), "%a-%a %s %a %s %" FMT_64 "x%n",
                     &me->ea1, &me->ea2, me->perm,
                     &me->offset, me->device, &me->inode, &len);
  if ( code == 6 )
  {
    me->bitness = 1;
    size_t pos = line.find('-');
    if ( pos != qstring::npos && pos > 8 )
    {
      me->bitness = 2;
      debapp_attrs.addrsize = 8;
    }
    char *ptr = line.begin() + len;
    ptr = skip_spaces(ptr);
    // remove trailing spaces and eventual (deleted) suffix
    static const char delsuff[] = " (deleted)";
    const int suflen = sizeof(delsuff) - 1;
    char *end = tail(ptr);
    while ( end > ptr && qisspace(end[-1]) )
      *--end = '\0';
    if ( end-ptr > suflen && strncmp(end-suflen, delsuff, suflen) == 0 )
      end[-suflen] = '\0';
    me->fname = ptr;
  }
  return me->ea1 != BADADDR;
}

//--------------------------------------------------------------------------
int linux_debmod_t::get_memory_info(meminfo_vec_t &miv, bool suspend)
{
  ldeb("get_memory_info(suspend=%d)\n", suspend);
  if ( exited )
    return -1;
  if ( suspend )
    suspend_all_threads();

  rewind(mapfp);
  mapfp_entry_t me;
  qstrvec_t possible_interp;
  int bitness = 1;
  while ( read_mapping(&me) )
  {
    // skip empty ranges
    if ( me.empty() )
      continue;

    if ( interp.empty() && !me.fname.empty() && !possible_interp.has(me.fname) )
    {
      //check for [.../]ld-XXX.so"
      size_t pos = me.fname.find("ld-");
      if ( pos != qstring::npos && (pos == 0 || me.fname[pos-1] == '/') )
        possible_interp.push_back(me.fname);
    }

    // for some reason linux lists some ranges twice
    // ignore them
    int i;
    for ( i=0; i < miv.size(); i++ )
      if ( miv[i].start_ea == me.ea1 )
        break;
    if ( i != miv.size() )
      continue;

    memory_info_t &mi = miv.push_back();
    mi.start_ea = me.ea1;
    mi.end_ea   = me.ea2;
    mi.name.swap(me.fname);
#ifdef __ANDROID__
    // android reports simple library names without path. try to find it.
    make_android_abspath(&mi.name);
#endif
    mi.bitness = me.bitness;
    //msg("%s: %a..%a. Bitness: %d\n", mi.name.c_str(), mi.start_ea, mi.end_ea, mi.bitness);

    if ( bitness < mi.bitness )
      bitness = mi.bitness;

    if ( strchr(me.perm, 'r') != NULL )
      mi.perm |= SEGPERM_READ;
    if ( strchr(me.perm, 'w') != NULL )
      mi.perm |= SEGPERM_WRITE;
    if ( strchr(me.perm, 'x') != NULL )
      mi.perm |= SEGPERM_EXEC;
  }

  if ( !possible_interp.empty() )
  {
    bool ok = false;

    for ( size_t i = 0; i < possible_interp.size(); ++i )
    {
      interp = possible_interp[i];
      debdeb("trying potential interpreter %s\n", interp.c_str());
      if ( add_shlib_bpt(miv, true) )
      {
        ok = true;
        dmsg("Found a valid interpeter in %s, will report shared library events!\n", interp.c_str());
        handle_dll_movements(miv);
      }
    }

    if ( !ok )
      interp.qclear();
  }

  // During the parsing of each memory segment we had just guessed the bitness.
  // So fix now bitness of all memory segments
  for ( int i = 0; i < miv.size(); i++ )
    miv[i].bitness = bitness;

  if ( suspend )
    resume_all_threads();
  return 1;
}

//--------------------------------------------------------------------------
int idaapi linux_debmod_t::dbg_get_memory_info(meminfo_vec_t &ranges)
{
  int code = get_memory_info(ranges, false);
  if ( code == 1 )
  {
    if ( same_as_oldmemcfg(ranges) )
      code = -2;
    else
      save_oldmemcfg(ranges);
  }
  return code;
}

linux_debmod_t::~linux_debmod_t()
{
}

//--------------------------------------------------------------------------
void idaapi linux_debmod_t::dbg_set_debugging(bool _debug_debugger)
{
  debug_debugger = _debug_debugger;
}

//--------------------------------------------------------------------------
int idaapi linux_debmod_t::dbg_init(void)
{
  dbg_term(); // initialize various variables
  qgetenv("DEBUG_FILE_DIRECTORY", &debug_file_directory);
  debdeb("DEBUG_FILE_DIRECTORY=%s\n", debug_file_directory.c_str());
  return DBG_HAS_PROCGETINFO | DBG_HAS_DETACHPROC;
}

//--------------------------------------------------------------------------
void idaapi linux_debmod_t::dbg_term(void)
{
  cleanup();
  cleanup_hwbpts();
}

//--------------------------------------------------------------------------
bool idaapi linux_debmod_t::thread_get_fs_base(thid_t tid, int reg_idx, ea_t *pea)
{
#if !defined(__ARM__) && defined(__X64__)

  /* The following definitions come from prctl.h, but may be absent
     for certain configurations.  */
  #ifndef ARCH_GET_FS
  #define ARCH_SET_GS 0x1001
  #define ARCH_SET_FS 0x1002
  #define ARCH_GET_FS 0x1003
  #define ARCH_GET_GS 0x1004
  #endif

  switch ( reg_idx )
  {
    case R_FS:
      if ( ptrace (PTRACE_ARCH_PRCTL, tid, pea, ARCH_GET_FS) == 0 )
        return true;
      break;
    case R_GS:
      if ( ptrace (PTRACE_ARCH_PRCTL, tid, pea, ARCH_GET_GS) == 0 )
        return true;
      break;
    case R_CS:
    case R_DS:
    case R_ES:
    case R_SS:
      *pea = 0;
      return true;
  }
  return false;
#else
  qnotused(tid);
  qnotused(reg_idx);
  qnotused(pea);
  return false;
#endif
}

//--------------------------------------------------------------------------
int idaapi linux_debmod_t::handle_ioctl(int fn, const void *in, size_t, void **, ssize_t *)
{
  if ( fn == 0 )  // chmod +x
  {
    // this call is not used anymore
    char *fname = (char *)in;
    qstatbuf st;
    qstat(fname, &st);
    int mode = st.qst_mode | S_IXUSR|S_IXGRP|S_IXOTH;
    chmod(fname, mode);
  }
  return 0;
}

//--------------------------------------------------------------------------
// recovering from a broken session consists in the following steps:
//
//  1 - Cleanup dlls previously recorded.
//  2 - Do like if we were attaching (calling handle_process_start(attaching=>AMT_ATTACH_BROKEN))
//  3 - Generate library events.
//  4 - Restore RIP/EIP if we stopped in a breakpoint.
//
bool idaapi linux_debmod_t::dbg_continue_broken_connection(pid_t _pid)
{
  debmod_t::dbg_continue_broken_connection(_pid);
  bool ret = in_event = false;

  // cleanup previously recorded information
  dlls.clear();

  // restore broken breakpoints and continue like a normal attach
  if ( restore_broken_breakpoints() && handle_process_start(_pid, AMT_ATTACH_BROKEN) )
  {
    // generate all library events
    gen_library_events(_pid);

    // fix instruction pointer in case we're at a breakpoint
    if ( !fix_instruction_pointer() )
      dmsg("Debugger failed to correctly restore the instruction pointer after recovering from a broken connection.\n");

    // and finally pause the process
    broken_connection = false;
    ret = true;
  }
  return ret;
}

//--------------------------------------------------------------------------
// if the process was stopped at a breakpoint and then the connections goes
// down, when re-attaching the process we may be at EIP+1 (Intel procs) so
// we need to change EIP to EIP-1
bool linux_debmod_t::fix_instruction_pointer(void)
{
  bool ret = true;
#if !defined(__ARM__)
  if ( last_event.eid == BREAKPOINT )
  {
    ret = false;
    struct user_regs_struct regs;
    if ( qptrace(PTRACE_GETREGS, last_event.tid, 0, &regs) == 0 )
    {
      if ( last_event.ea == regs.PCREG-1 )
        regs.PCREG--;

      ret = qptrace(PTRACE_SETREGS, last_event.tid, 0, &regs) == 0;
    }
  }
#endif
  return ret;
}

//--------------------------------------------------------------------------
bool init_subsystem()
{
  tdb_init();
  qatexit(kill_all_processes);
  linux_debmod_t::reuse_broken_connections = true;
  return true;
}

//--------------------------------------------------------------------------
bool term_subsystem()
{
  del_qatexit(kill_all_processes);
  tdb_term();
  return true;
}

//--------------------------------------------------------------------------
debmod_t *create_debug_session()
{
  return new linux_debmod_t();
}
