#ifndef __DEBUGGER_MODULE__
#define __DEBUGGER_MODULE__

//
//
//      This is the base debmod_t class definition
//      From this class all debugger code must inherite and specialize
//
//      Some OS specific functions must be implemented:
//        bool init_subsystem();
//        bool term_subsystem();
//        debmod_t *create_debug_session();
//        int create_thread(thread_cb_t thread_cb, void *context);
//

#include <map>
#include <deque>
#include <set>
#include <algorithm>
#include <pro.h>
#include <idd.hpp>
#include "consts.h"

extern debugger_t debugger;

//--------------------------------------------------------------------------
struct name_info_t
{
  eavec_t addrs;
  qvector<char *> names;
  void clear(void)
  {
    addrs.clear();
    names.clear();
  }
};

//--------------------------------------------------------------------------
// Extended process info
struct ext_process_info_t : public process_info_t
{
  int addrsize;     // process bitness 32bit - 4, 64bit - 8, 0 - unknown
  qstring ext_name; // human-readable name (e.g. with command line agrs)
  void copy_to(process_info_t *dst)
  {
    dst->pid = pid;
    const char *src_name = ext_name.empty() ? name : ext_name.c_str();
    qstrncpy(dst->name, src_name, sizeof(dst->name));
  }
};
typedef qvector<ext_process_info_t> procvec_t;

//--------------------------------------------------------------------------
// Very simple class to store pending events
enum queue_pos_t
{
  IN_FRONT,
  IN_BACK
};

//--------------------------------------------------------------------------
struct pagebpt_data_t
{
  ea_t ea;              // address of the bpt as specified by the user
  ea_t page_ea;         // real address of the bpt as written to the process
  int user_len;         // breakpoint length as specified by the user
  int real_len;         // real length of the breakpoint as written to the process
  uint32 old_prot;      // old page protections (before writing the bpt to the process)
                        // if 0, the bpt has not been written to the process yet.
  uint32 new_prot;      // new page protections (when the bpt is active)
  bpttype_t type;       // breakpoint type
};

// Information about page breakpoints is stored in this data structure.
// The map is indexed by the page start address (not the address specified
// by the user!)
typedef std::map<ea_t, pagebpt_data_t> page_bpts_t; // page_ea -> bpt info
typedef qvector<page_bpts_t::iterator> pbpt_iterators_t; // list of iterators into page_bpts_t

//--------------------------------------------------------------------------
// set of addresses
typedef std::set<ea_t> easet_t;

//--------------------------------------------------------------------------
struct debmod_bpt_t
{
  ea_t ea;
  uchar saved[8]; // size of the biggest supported bpt size (PPC64)
  uchar nsaved;
  int bid;        // (epoc) breakpoint id (from TRK)
  debmod_bpt_t() : ea(BADADDR),bid(0) {}
  debmod_bpt_t(ea_t _ea, uchar _nsaved) : ea(_ea), nsaved(_nsaved), bid(0) {}
};
typedef std::map<ea_t, debmod_bpt_t> debmodbpt_map_t;

struct eventlist_t : public std::deque<debug_event_t>
{
private:
  bool synced;
public:
  // save a pending event
  void enqueue(const debug_event_t &ev, queue_pos_t pos)
  {
    if ( pos != IN_BACK )
      push_front(ev);
    else
      push_back(ev);
  }

  // retrieve a pending event
  bool retrieve(debug_event_t *event)
  {
    if ( empty() )
      return false;
    // get the first event and return it
    *event = front();
    pop_front();
    return true;
  }
};

typedef int ioctl_handler_t(
  class rpc_engine_t *rpc,
  int fn,
  const void *buf,
  size_t size,
  void **poutbuf,
  ssize_t *poutsize);

int send_ioctl(rpc_engine_t *rpc, int fn, const void *buf, size_t size, void **poutbuf, ssize_t *poutsize);
int send_debug_names_to_ida(ea_t *addrs, const char *const *names, int qty);
int send_debug_event_to_ida(const debug_event_t *ev, int rqflags);
void set_arm_thumb_modes(ea_t *addrs, int qty);
char *debug_event_str(const debug_event_t *ev, char *buf, size_t bufsize);
char *debug_event_str(const debug_event_t *ev); // returns static buf

// Main class to represent a debugger module
class debmod_t
{

protected:
  typedef std::map<int, regval_t> regval_map_t;
  qvector<exception_info_t> exceptions;
  name_info_t dn_names;
  // Pending events. currently used only to store
  // exceptions that happen while attaching
  eventlist_t events;
  // The last event received via a successful get_debug_event()
  debug_event_t last_event;

  // debugged process attributes (may be changed after process start/attach)
  debapp_attrs_t debapp_attrs;

  procvec_t proclist;

  // appcall contexts
  struct call_context_t
  {
    regvals_t saved_regs;
    ea_t sp;
    ea_t ctrl_ea;
    bool regs_spoiled;
    call_context_t() : sp(BADADDR), ctrl_ea(BADADDR), regs_spoiled(false) {}
  };
  typedef qstack<call_context_t> call_contexts_t;
  typedef std::map<thid_t, call_contexts_t> appcalls_t;
  appcalls_t appcalls;

  int send_ioctl(int fn, const void *buf, size_t size, void **poutbuf, ssize_t *poutsize)
  {
    return ::send_ioctl(rpc, fn, buf, size, poutbuf, poutsize);
  }
  // If an IDC error occurs: we can not prepare an error message on the server
  // side because we do not have access to error strings (they are in ida.hlp).
  // We pass the error code to IDA (with eventual arguments) so it can prepare
  // a nice error message for the user
  void report_idc_error(ea_t ea, error_t code, ssize_t errval, const char *errprm)
  {
    return ::report_idc_error(rpc, ea, code, errval, errprm);
  }

  typedef std::map<ea_t, lowcnd_t> lowcnds_t;
  lowcnds_t cndmap;
  eavec_t handling_lowcnds;
  bool evaluate_and_handle_lowcnd(debug_event_t *event, int elc_flags=0);
  bool handle_lowcnd(lowcnd_t *lc, debug_event_t *event, int elc_flags);
#define ELC_KEEP_EIP  0x0001 // do not reset eip before stepping
#define ELC_KEEP_SUSP 0x0002 // keep suspended state, do not resume after stepping

  // helper functions for programmatical single stepping
  virtual int dbg_perform_single_step(debug_event_t *event, const insn_t &cmd);
  virtual int dbg_freeze_threads_except(thid_t) { return 0; }
  virtual int dbg_thaw_threads_except(thid_t) { return 0; }
  int resume_app_and_get_event(debug_event_t *dev);
  void set_platform(const char *platform_name);

  // return number of processes, -1 - not implemented
  virtual int idaapi get_process_list(procvec_t *proclist);

public:
  // initialized by dbg_init()
  int debugger_flags;
  meminfo_vec_t old_areas;
  rpc_engine_t *rpc;
  bool debug_debugger;
  // Is dynamic library?
  bool is_dll;

  // indexes of sp and program counter registers.
  // Must be initialized by derived classes.
  int sp_idx, pc_idx;

  // Total number of registers.
  // Must be initialized by derived classes.
  int nregs;

  // Breakpoint code.
  // Must be initialized by derived classes.
  bytevec_t bpt_code;

  qstring input_file_path;

  page_bpts_t page_bpts;

  DECLARE_UD_REPORTING(msg, rpc);
  DECLARE_UD_REPORTING(warning, rpc);
  DECLARE_UD_REPORTING(error, rpc);

  bool broken_connection;
  pid_t pid;

  debmodbpt_map_t bpts;

  static bool reuse_broken_connections;
  //------------------------------------
  // Constructors and destructors
  //------------------------------------
  debmod_t();
  virtual ~debmod_t() { cleanup(); }

  //------------------------------------
  // Debug names methods
  //------------------------------------
  void clear_debug_names();
  name_info_t *get_debug_names();
  void save_debug_name(ea_t ea, const char *name);
  int set_debug_names();
  int send_debug_names_to_ida(ea_t *addrs, const char *const *names, int qty);
  int send_debug_event_to_ida(const debug_event_t *ev, int rqflags);
  //------------------------------------
  // Utility methods
  //------------------------------------
  void cleanup(void);
  AS_PRINTF(2, 3) void debdeb(const char *format, ...);
  AS_PRINTF(2, 3) bool deberr(const char *format, ...);
  bool same_as_oldmemcfg(const meminfo_vec_t &areas) const;
  void save_oldmemcfg(const meminfo_vec_t &areas);
  bool continue_after_last_event(bool handled = true);
  lowcnd_t *get_failed_lowcnd(thid_t tid, ea_t ea);
  page_bpts_t::iterator find_page_bpt(ea_t ea, int size=1);
  bool del_page_bpt(ea_t ea, bpttype_t type);
  void enable_page_bpts(bool enable);
  ea_t calc_page_base(ea_t ea) { return align_down(ea, dbg_memory_page_size()); }
  void log_exception(const debug_event_t *ev, const exception_info_t *ei);

  //------------------------------------
  // Shared methods
  //------------------------------------
  virtual bool check_input_file_crc32(uint32 orig_crc);
  virtual const exception_info_t *find_exception(int code);
  virtual bool get_exception_name(int code, char *buf, size_t bufsize);
  virtual int  idaapi dbg_process_get_info(int n,
    const char *input,
    process_info_t *info);

  //------------------------------------
  // Methods to be implemented
  //------------------------------------
  virtual int idaapi dbg_init(bool _debug_debugger) = 0;
  virtual void idaapi dbg_term(void) = 0;
  virtual int  idaapi dbg_detach_process(void) = 0;
  virtual int  idaapi dbg_start_process(const char *path,
    const char *args,
    const char *startdir,
    int flags,
    const char *input_path,
    uint32 input_file_crc32) = 0;
  virtual gdecode_t idaapi dbg_get_debug_event(debug_event_t *event, int timeout_msecs) = 0;
  virtual int  idaapi dbg_attach_process(pid_t process_id, int event_id) = 0;
  virtual int  idaapi dbg_prepare_to_pause_process(void) = 0;
  virtual int  idaapi dbg_exit_process(void) = 0;
  virtual int  idaapi dbg_continue_after_event(const debug_event_t *event) = 0;
  virtual void idaapi dbg_set_exception_info(const exception_info_t *info, int qty);
  virtual void idaapi dbg_stopped_at_debug_event(void) = 0;
  virtual int  idaapi dbg_thread_suspend(thid_t thread_id) = 0;
  virtual int  idaapi dbg_thread_continue(thid_t thread_id) = 0;
  virtual int  idaapi dbg_set_resume_mode(thid_t thread_id, resume_mode_t resmod) = 0;
  virtual int  idaapi dbg_read_registers(thid_t thread_id,
    int clsmask,
    regval_t *values) = 0;
  virtual int  idaapi dbg_write_register(thid_t thread_id,
    int reg_idx,
    const regval_t *value) = 0;
  virtual int  idaapi dbg_thread_get_sreg_base(thid_t thread_id,
    int sreg_value,
    ea_t *ea) = 0;
  virtual ea_t idaapi map_address(ea_t ea, const regval_t *, int /* regnum */) { return ea; }
  virtual int  idaapi dbg_get_memory_info(meminfo_vec_t &areas) = 0;
  virtual ssize_t idaapi dbg_read_memory(ea_t ea, void *buffer, size_t size) = 0;
  virtual ssize_t idaapi dbg_write_memory(ea_t ea, const void *buffer, size_t size) = 0;
  virtual int  idaapi dbg_is_ok_bpt(bpttype_t type, ea_t ea, int len) = 0;
  // for swbpts, len may be -1 (unknown size, for example arm/thumb mode) or bpt opcode length
  // dbg_add_bpt returns 2 if it adds a page bpt
  virtual int  idaapi dbg_add_bpt(bpttype_t type, ea_t ea, int len) = 0;
  virtual int  idaapi dbg_del_bpt(bpttype_t type, ea_t ea, const uchar *orig_bytes, int len) = 0;
  virtual int  idaapi dbg_update_bpts(update_bpt_info_t *bpts, int nadd, int ndel);
  virtual int  idaapi dbg_add_page_bpt(bpttype_t /*type*/, ea_t /*ea*/, int /*size*/) { return 0; }
  virtual bool idaapi dbg_enable_page_bpt(page_bpts_t::iterator /*p*/, bool /*enable*/) { return false; }
  virtual int  idaapi dbg_update_lowcnds(const lowcnd_t *lowcnds, int nlowcnds);
  virtual int  idaapi dbg_eval_lowcnd(thid_t tid, ea_t ea);
  virtual int  idaapi dbg_open_file(const char * /*file*/, uint32 * /*fsize*/, bool /*readonly*/) { return -1; }
  virtual void idaapi dbg_close_file(int /*fn*/) {}
  virtual ssize_t idaapi dbg_read_file(int /*fn*/, uint32 /*off*/, void * /*buf*/, size_t /*size*/) { return 0; }
  virtual ssize_t idaapi dbg_write_file(int /*fn*/, uint32 /*off*/, const void * /*buf*/, size_t /*size*/) { return 0; }
  virtual int  idaapi handle_ioctl(int /*fn*/, const void* /*buf*/, size_t /*size*/,
                                   void** /*outbuf*/, ssize_t* /*outsize*/) { return 0; }
  virtual int  idaapi get_system_specific_errno(void) const; // this code must be acceptable by winerr()
  virtual bool idaapi dbg_update_call_stack(thid_t, call_stack_t *) { return false; }
  virtual ea_t idaapi dbg_appcall(
    ea_t /*func_ea*/,
    thid_t /*tid*/,
    int /*stkarg_nbytes*/,
    const struct regobjs_t * /*regargs*/,
    struct relobj_t * /*stkargs*/,
    struct regobjs_t * /*retregs*/,
    qstring *errbuf,
    debug_event_t * /*event*/,
    int /*flags*/);
  virtual int idaapi dbg_cleanup_appcall(thid_t /*tid*/);
  virtual bool idaapi write_registers(
    thid_t /*tid*/,
    int /*start*/,
    int /*count*/,
    const regval_t * /*values*/,
    const int * /*indices*/ = NULL) { return false; }
  // finalize appcall stack image
  // input: stack image contains the return address at the beginning
  virtual int finalize_appcall_stack(call_context_t &, regval_map_t &, bytevec_t &) { return 0; }
  virtual ea_t calc_appcall_stack(const regvals_t &regvals);
  virtual bool should_stop_appcall(thid_t tid, const debug_event_t *event, ea_t ea);
  virtual bool preprocess_appcall_cleanup(thid_t, call_context_t &) { return true; }
  virtual int get_regidx(const char *regname, int *clsmask) = 0;
  virtual uint32 dbg_memory_page_size(void) { return 0x1000; }
  virtual bool idaapi dbg_prepare_broken_connection(void) { return false; }
  virtual bool idaapi dbg_continue_broken_connection(pid_t) { old_areas.clear(); return true; }
  virtual bool idaapi dbg_enable_trace(thid_t, bool, int) { return false; }
  virtual bool idaapi dbg_is_tracing_enabled(thid_t, int) { return false; }
  virtual int idaapi dbg_rexec(const char *cmdline);
  virtual int read_bpt_orgbytes(ea_t *p_ea, int *p_len, uchar *buf, int bufsize);
  virtual void dbg_get_debapp_attrs(debapp_attrs_t *out_pattrs) const;

  bool restore_broken_breakpoints(void);
};

//---------------------------------------------------------------------------

// Possible values returned by debmod_t.dbg_init()
#define DBG_HAS_PROCGETINFO 1
#define DBG_HAS_DETACHPROC  2

//
// Some functions, per OS implemented
//
bool init_subsystem();
bool term_subsystem();
debmod_t *create_debug_session();

//
// Processor specific init/term
//
void processor_specific_init(void);
void processor_specific_term(void);

// forward declaration, needed for GDB
int idaapi s_set_resume_mode(thid_t thread_id, resume_mode_t resmod);

// Perform an action on all existing debugger modules
struct debmod_visitor_t
{
  virtual int visit(debmod_t *debmod) = 0;
};
int for_all_debuggers(debmod_visitor_t &v);


//
// Utility functions
//

// Common method between MacOS and Linux to launch a process
int idaapi maclnx_launch_process(
  debmod_t *debmod,
  const char *path,
  const char *args,
  const char *startdir,
  int flags,
  const char *input_path,
  uint32 input_file_crc32,
  void **child_pid);

//
// Externs
//
extern debmod_t *idc_debmod;
extern thid_t idc_thread;
extern bool ignore_sigint;

//---------------------------------------------------------------------------
// util.cpp
void lprintf(const char *format,...);

//---------------------------------------------------------------------------
// server.cpp
bool lock_begin();
bool lock_end();

bool srv_lock_begin(void);
bool srv_lock_end(void);

#endif
