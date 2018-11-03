#ifndef __WIN32_DEBUGGER_MODULE__
#define __WIN32_DEBUGGER_MODULE__

#include <windows.h>
#include <Tlhelp32.h>
#include "../../ldr/pe/pe.h"
#include "winbase_debmod.h"

//-V::720 It is advised to utilize the 'SuspendThread' function only when developing a debugger

// Type definitions

class win32_debmod_t;

//--------------------------------------------------------------------------
// image information
struct image_info_t
{
  image_info_t() { memset(this, 0, sizeof(*this)); }
  image_info_t(win32_debmod_t *);
  image_info_t(win32_debmod_t *, ea_t _base, uint32 _imagesize, const qstring &_name);
  image_info_t(win32_debmod_t *, const LOAD_DLL_DEBUG_INFO &i, uint32 _imagesize, const char *_name);
  image_info_t(win32_debmod_t *, const module_info_t &m);

  win32_debmod_t *sess;
  ea_t base;
  uval_t imagesize;
  qstring name;
  LOAD_DLL_DEBUG_INFO dll_info;
};

// key: image base address
typedef std::map<ea_t, image_info_t> images_t;

//--------------------------------------------------------------------------
#ifdef __ARM__
  #define RC_GENERAL ARM_RC_GENERAL
  #define RC_ALL     ARM_RC_ALL
#else
  #define RC_GENERAL X86_RC_GENERAL
  #define RC_ALL     X86_RC_ALL
#endif

// thread information
struct thread_info_t : public CREATE_THREAD_DEBUG_INFO
{
  thread_info_t(const CREATE_THREAD_DEBUG_INFO &i, thid_t t, wow64_state_t wow64_state);
  thid_t tid;                   // thread id
  int suspend_count;
  ea_t bpt_ea;
  int flags;
#define THR_CLSMASK 0x0007      // valid register classes in CONTEXT structure
                                // we use X86_RC.. constants here
#define THR_TRACING 0x0100      // expecting a STEP event
#define THR_FSSAVED 0x0200      // remembered FS value
#define THR_WOW64   0x0400      // is wow64 process?
  CONTEXT ctx;
  ea_t callgate_ea;

  void invalidate_context(void) { flags &= ~THR_CLSMASK; ctx.ContextFlags = 0; }
  bool read_context(int clsmask);
  bool write_context(int clsmask);
#ifndef __ARM__
  void cvt_from_wow64(const WOW64_CONTEXT &wow64ctx, int clsmask);
  void cvt_to_wow64(WOW64_CONTEXT *wow64ctx, int clsmask) const;
  bool toggle_tbit(bool set_tbit, class win32_debmod_t *debmod);
#endif
  bool is_tracing(void) const { return (flags & THR_TRACING) != 0; }
  void set_tracing(void) { flags |= THR_TRACING; }
  void clr_tracing(void) { flags &= ~THR_TRACING; }
  ea_t get_ip(void) { return read_context(RC_GENERAL) ? ctx.Eip : BADADDR; }
};

//--------------------------------------------------------------------------
inline thread_info_t::thread_info_t(
        const CREATE_THREAD_DEBUG_INFO &i,
        thid_t t,
        wow64_state_t wow64_state)
    : CREATE_THREAD_DEBUG_INFO(i), tid(t), suspend_count(0), bpt_ea(BADADDR),
      flags(wow64_state > 0 ? THR_WOW64 : 0),
      callgate_ea(0)
{
  ctx.ContextFlags = 0;
}

//--------------------------------------------------------------------------
// Check if the context structure has valid values at the specified portion
// portion is a conbination of CONTEXT_... bitmasks
inline bool has_portion(const CONTEXT &ctx, int portion)
{
  return (ctx.ContextFlags & portion & 0xFFFF) != 0;
}

//--------------------------------------------------------------------------
// (tid -> info)
struct threads_t: public std::map<DWORD, thread_info_t>
{
  thread_info_t *get(DWORD tid)
  {
    const iterator it = find(tid);
    if ( it == end() )
      return NULL;
    return &it->second;
  }
};

//--------------------------------------------------------------------------
typedef qvector<thread_info_t> threadvec_t;

//--------------------------------------------------------------------------
// structure for the internal breakpoint information for threads
struct internal_bpt_info_t
{
  int count;            // number of times this breakpoint is 'set'
  uchar orig_bytes[BPT_CODE_SIZE]; // original byte values
};
typedef std::map<ea_t, internal_bpt_info_t> bpt_info_t;

//--------------------------------------------------------------------------
typedef int (*process_cb_t)(debmod_t *, PROCESSENTRY32 *pe32, void *ud);
typedef int (*module_cb_t)(debmod_t *, MODULEENTRY32 *me32, void *ud);

//----------------------------------------------------------------------------
// A live PDB session, that will be used remotely (typically by non-windows machines).
struct pdb_remote_session_t;
void close_pdb_remote_session(pdb_remote_session_t *);

//Wow64-specific events
#ifndef STATUS_WX86_BREAKPOINT
#  define STATUS_WX86_BREAKPOINT 0x4000001f
#endif
#ifndef STATUS_WX86_SINGLE_STEP
#  define STATUS_WX86_SINGLE_STEP 0x4000001e
#endif
//--------------------------------------------------------------------------
class win32_debmod_t : public winbase_debmod_t
{
  typedef winbase_debmod_t inherited;
private:
  gdecode_t get_debug_event(debug_event_t *event, int timeout_ms);
  void check_thread(bool must_be_main_thread) const;
  void add_thread(const CREATE_THREAD_DEBUG_INFO &thr_info, thid_t tid);
  void install_callgate_workaround(thread_info_t *ti, const debug_event_t *event);
public:
  // debugged process information
  qstring process_path;
  HANDLE thread_handle;
  HANDLE redirin_handle, redirout_handle;
  attach_status_t attach_status;
  HANDLE attach_evid;
  int8 expecting_debug_break;
  bool stop_at_ntdll_bpts;

  images_t curproc; // image of the running process
  images_t dlls; // list of loaded DLLs
  images_t images; // list of detected PE images
  images_t thread_ranges; // list of ranges related to threads
  images_t class_ranges;  // list of ranges related to class names

  easet_t dlls_to_import;          // list of dlls to import information from

  bpt_info_t thread_bpts;

  threads_t threads;

  // ID of a thread for which we must emulate a STEP event on XP (using a breakpoint)
  thid_t winxp_step_thread;

  CREATE_PROCESS_DEBUG_INFO cpdi;

  debug_event_t *in_event; // current debug event
  bool fake_suspend_event;
  bool exiting;
  bool DebugBreakProcess_requested;
  procinfo_vec_t processes;

  // threads suspended by the fiber created for restoring broken connections
  threadvec_t _suspended_threads;
  // event to wait until the broken connection is completely restored
  HANDLE broken_event_handle;

  // Module specific methods, to be implemented
  virtual void idaapi dbg_set_debugging(bool _debug_debugger);
  virtual int  idaapi dbg_init(void);
  virtual void idaapi dbg_term(void);
  virtual int  idaapi dbg_detach_process(void);
  virtual int  idaapi dbg_start_process(const char *path,
    const char *args,
    const char *startdir,
    int flags,
    const char *input_path,
    uint32 input_file_crc32);
  virtual gdecode_t idaapi dbg_get_debug_event(debug_event_t *event, int timeout_ms);
  virtual int  idaapi dbg_attach_process(pid_t process_id, int event_id, int flags);
  virtual int  idaapi dbg_prepare_to_pause_process(void);
  virtual int  idaapi dbg_exit_process(void);
  virtual int  idaapi dbg_continue_after_event(const debug_event_t *event);
  virtual void idaapi dbg_stopped_at_debug_event(void);
  virtual int  idaapi dbg_thread_suspend(thid_t thread_id);
  virtual int  idaapi dbg_thread_continue(thid_t thread_id);
  virtual int  idaapi dbg_set_resume_mode(thid_t thread_id, resume_mode_t resmod);
  virtual int  idaapi dbg_read_registers(thid_t thread_id,
    int clsmask,
    regval_t *values);
  virtual int idaapi dbg_write_register(thid_t thread_id,
    int reg_idx,
    const regval_t *value);

  void patch_context_struct(CONTEXT &ctx, int reg_idx, const regval_t *value) const;
  virtual int idaapi dbg_thread_get_sreg_base(ea_t *ea, thid_t thread_id, int sreg_value);
  virtual int idaapi dbg_get_memory_info(meminfo_vec_t &ranges);
  virtual ssize_t idaapi dbg_read_memory(ea_t ea, void *buffer, size_t size);
  virtual ssize_t idaapi dbg_write_memory(ea_t ea, const void *buffer, size_t size);
  virtual int idaapi dbg_add_bpt(bpttype_t type, ea_t ea, int len);
  virtual int idaapi dbg_del_bpt(bpttype_t type, ea_t ea, const uchar *orig_bytes, int len);
  virtual int idaapi handle_ioctl(int fn, const void *buf, size_t size, void **outbuf, ssize_t *outsize);
  //
  win32_debmod_t();
  ~win32_debmod_t() { cleanup(); }

  void handle_pdb_thread_request(void *data);
  uint32 calc_imagesize(eanat_t base);
  void get_filename_for(
    eanat_t image_name_ea,
    bool is_unicode,
    eanat_t image_base,
    char *buf,
    size_t bufsize,
    HANDLE process_handle,
    const char *process_path);
  ea_t get_dll_export(
    const images_t &dlls,
    ea_t imagebase,
    const char *exported_name);

  bool create_process(
    const char *path,
    const char *args,
    const char *startdir,
    bool is_gui,
    bool hide_window,
    PROCESS_INFORMATION *ProcessInformation);

  void show_debug_event(
    const DEBUG_EVENT &ev,
    HANDLE process_handle,
    const char *process_path);

  ssize_t _read_memory(eanat_t ea, void *buffer, size_t size, bool suspend = false);
  ssize_t _write_memory(eanat_t ea, const void *buffer, size_t size, bool suspend = false);

  int rdmsr(int reg, uint64 *value);
  int wrmsr(int reg, uint64 value);
  int kldbgdrv_access_msr(struct SYSDBG_MSR *msr, bool write);

  // !! OVERWRITTEN METHODS !!
  bool refresh_hwbpts();

  // Utility methods
  gdecode_t handle_exception(debug_event_t *event,
    const EXCEPTION_RECORD &er,
    bool was_thread_bpt,
    bool firsttime);
  ssize_t access_memory(eanat_t ea, void *buffer, ssize_t size, bool write, bool suspend);
  inline void resume_all_threads(bool raw = false);
  inline void suspend_all_threads(bool raw = false);
  size_t add_dll(image_info_t &ii);
  HANDLE get_thread_handle(thid_t tid);
  static int get_dmi_cb(debmod_t *sess, MODULEENTRY32 *me32, void *ud);
  void get_debugged_module_info(module_info_t *dmi);
  int for_each_module(DWORD pid, module_cb_t module_cb, void *ud);
  bool myCloseHandle(HANDLE &h);
  void cleanup(void);
  void restore_original_bytes(ea_t ea, bool really_restore = true);
  int save_original_bytes(ea_t ea);
  bool set_thread_bpt(thread_info_t &ti, ea_t ea);
  bool del_thread_bpt(thread_info_t &ti, ea_t ea);
  bool del_thread_bpts(ea_t ea);
  bool has_bpt_at(ea_t ea);
  bool can_access(ea_t addr);
  ea_t get_kernel_bpt_ea(ea_t ea, thid_t tid);
  void create_attach_event(debug_event_t *event, bool attached);
  void create_start_event(debug_event_t *event);
  bool check_for_hwbpt(debug_event_t *event, bool is_stepping=false);
  ea_t get_region_info(ea_t ea, memory_info_t *info);
  bool get_dll_exports(
    const images_t &dlls,
    ea_t imagebase,
    name_info_t &ni,
    const char *exported_name = NULL);
  bool get_filename_from_process(eanat_t name_ea,
    bool is_unicode,
    char *buf,
    size_t bufsize);
  bool get_debug_string(const DEBUG_EVENT &ev, char *buf, size_t bufsize);
  bool add_thread_ranges(
      HANDLE process_handle,
      thid_t tid,
      images_t &thread_ranges,
      images_t &class_ranges);
  ea_t get_pe_header(eanat_t imagebase, peheader_t *nh);
  bool set_debug_hook(ea_t base);
  bool get_pe_export_name_from_process(
        eanat_t imagebase,
        char *name,
        size_t namesize);

  void show_exception_record(const EXCEPTION_RECORD &er, int level=0);

  eanat_t pstos0(eanat_t ea);
  eanat_t s0tops(eanat_t ea);

  bool prepare_to_stop_process(debug_event_t *, const threads_t &);
  bool disable_hwbpts();
  bool enable_hwbpts();
  bool may_write(ea_t ea);
  LPVOID correct_exe_image_base(LPVOID base);
#ifdef UNDER_CE
  ea_t get_process_base(size_t size);
#endif
  bool clear_tbit(thread_info_t &th);
  void invalidate_all_contexts(void);
  void enqueue_event(const debug_event_t &ev, queue_pos_t pos);

  void suspend_running_threads(threadvec_t &suspended);
  void resume_suspended_threads(threadvec_t suspended) const;
  bool reopen_threads(void);

  virtual bool idaapi write_registers(
    thid_t thread_id,
    int start,
    int count,
    const regval_t *values,
    const int *indices = NULL);

  virtual int dbg_freeze_threads_except(thid_t tid);
  virtual int dbg_thaw_threads_except(thid_t tid);
  virtual bool idaapi dbg_prepare_broken_connection(void);
  virtual bool idaapi dbg_continue_broken_connection(pid_t pid);

  qvector<pdb_remote_session_t*> pdb_remote_sessions;
  pdb_remote_session_t *get_pdb_session(int id);
  void delete_pdb_session(int id);
};

ea_t s0tops(ea_t ea);

#endif

