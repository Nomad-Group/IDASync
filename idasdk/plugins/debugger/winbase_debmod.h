#ifndef __WINBASE_HPP__
#define __WINBASE_HPP__

// Base class for win32, wince, windbg modules

#include <algorithm>
#include <map>

using std::for_each;
#ifdef _MSC_VER // borland chokes on this
using std::pair;
using std::make_pair;
#endif

//--------------------------------------------------------------------------
#ifdef __ARM__
#  define BASE_DEBUGGER_MODULE wince_debmod_t
#  include "wince_debmod.h"
#  define BPT_CODE_SIZE ARM_BPT_SIZE
#else
#  define BASE_DEBUGGER_MODULE pc_debmod_t
#  include "deb_pc.hpp"
#  include "pc_debmod.h"
#  define BPT_CODE_SIZE X86_BPT_SIZE
#endif
#include "win32_util.hpp"

//--------------------------------------------------------------------------
// DEP policies
enum dep_policy_t
{
  dp_always_off,
  dp_always_on,
  dp_opt_in,
  dp_opt_out
};

//--------------------------------------------------------------------------
enum attach_status_t
{
  as_none,       // no attach to process requested
  as_attaching,  // waiting for CREATE_PROCESS_DEBUG_EVENT, indicating the process is attached
  as_breakpoint, // waiting for first breakpoint, indicating the process was properly initialized and suspended
  as_attached,   // process was successfully attached
  as_detaching,  // waiting for next get_debug_event() request, to return the process as detached
  as_attach_kernel, // attaching to kernel
};

// vector of win32 page protections
// we need this type because meminfo_t does not contain the original win32 protections
// but we need them to verify page bpts
typedef qvector<uint32> win32_prots_t;

//--------------------------------------------------------------------------
// When debugging WOW64 processes with ida32 we have to take into account
// ntdll.dll, which is a 64-bit file and gets loaded into high addresses.
// Since ea_t can not represent such addresses, we use our own type to
// remember the DLL boundaries

typedef size_t eanat_t;

struct ntdll_range_t
{
  eanat_t start;
  eanat_t end;
  HANDLE handle;
  ntdll_range_t() : start(0), end(0), handle(INVALID_HANDLE_VALUE) {}
  bool has(eanat_t addr) const { return addr >= start && addr < end; }
};
DECLARE_TYPE_AS_MOVABLE(ntdll_range_t);

struct ntdll_vec_t : protected qvector<ntdll_range_t>
{
  typedef qvector<ntdll_range_t> inherited;
  void clear() { inherited::clear(); }
  size_t size() const { return inherited::size(); }
  bool empty() const { return inherited::empty(); }
  // it returns false if there is a dll with such an address
  bool add(eanat_t addr, size_t size, HANDLE h = INVALID_HANDLE_VALUE);
  // it returns true if the dll address doesn't fit to `ea_t`
  bool check_high_address_and_add(
          eanat_t addr,
          size_t size,
          HANDLE h = INVALID_HANDLE_VALUE);
  // it returns true if the dll address doesn't fit to `ea_t`
  bool del_and_check_high_address(HANDLE *h, eanat_t addr);
  bool has(eanat_t addr) const;
};

//--------------------------------------------------------------------------
class winbase_debmod_t: public BASE_DEBUGGER_MODULE
{
  typedef BASE_DEBUGGER_MODULE inherited;
  wow64_state_t is_wow64;         // use check_wow64_process()

protected:
  HANDLE process_handle;
  dep_policy_t dep_policy;
  ntdll_vec_t ntdlls;
  // local functions
  bool mask_page_bpts(ea_t startea, ea_t endea, uint32 *protect);
  void verify_page_protections(meminfo_vec_t *areas, const win32_prots_t &prots);

  winbase_debmod_t(void);

  // overridden virtual functions
  bool idaapi dbg_enable_page_bpt(page_bpts_t::iterator p, bool enable);
  int idaapi dbg_add_page_bpt(bpttype_t type, ea_t ea, int size);
  bool check_for_call_large(const debug_event_t *event, HANDLE process_handle);
#ifdef __X64__
  wow64_state_t check_wow64_process();
#else
  wow64_state_t check_wow64_process() { return WOW64_NO; }
#endif

  int get_process_addrsize(pid_t pid);

  bool is_ntdll_name(const char *path);

  // return number of processes, -1 - not implemented
  virtual int idaapi get_process_list(procvec_t *proclist);
  // return the file name assciated with pid
  virtual bool idaapi get_exec_fname(int pid, char *buf, size_t bufsize);
  // get process bitness: 32bit - 4, 64bit - 8, 0 - unknown
  virtual int idaapi get_process_bitness(int pid);

  virtual void idaapi dbg_term(void);

public:
  static win_tool_help_t *get_tool_help();
  static win_version_t winver;

private:
  void build_process_ext_name(ext_process_info_t *pinfo);
  static bool get_process_path(
            ext_process_info_t *pinfo,
            char *buf, size_t bufsize);
  static bool remove_page_protections(
            DWORD *p_input,
            bpttype_t bpttype,
            dep_policy_t dpolicy,
            HANDLE proc_handle);

  static win_tool_help_t *win_tool_help;
};

bool should_fire_page_bpt(page_bpts_t::iterator p, ea_t ea, DWORD failed_access_type, ea_t pc, dep_policy_t dep_policy);

#ifdef _PE_H_
bool read_pe_header(peheader_t *pe);
#endif

//-------------------------------------------------------------------------
inline void tchar_utf8(qstring *buf, TCHAR *tchar)
{
#ifdef UNICODE
  utf16_utf8(buf, tchar);
#else
  acp_utf8(buf, tchar);
#endif
}

//-------------------------------------------------------------------------
inline void tchar_utf8(char *buf, TCHAR *tchar, size_t bufsize)
{
  qstring utf8;
  tchar_utf8(&utf8, tchar);
  qstrncpy(buf, utf8.c_str(), bufsize);
}

#endif
