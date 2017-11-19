//
// Wrapper for Windows ToolHelp library: enumerate processes/modules
//
// PSAPI.DLL:                                 NT, 2K, XP/2K3
// KERNEL32.DLL (ToolHelp functions): 9X, ME,     2K, XP/2K3
//? add NT support

#ifndef __TOOLHELP_HPP__
#define __TOOLHELP_HPP__

#ifdef __NT__

#include <windows.h>
#include <Tlhelp32.h>

#ifndef UNDER_CE
#include <dbghelp.h>
#endif

#include <segment.hpp>

#ifdef UNICODE
#define LookupPrivilegeValue_Name "LookupPrivilegeValueW"
#else
#define LookupPrivilegeValue_Name "LookupPrivilegeValueA"
#endif

#ifdef UNDER_CE
#  define KERNEL_LIB_NAME   "coredll.dll"
#  define TOOLHELP_LIB_NAME "toolhelp.dll"
#  ifndef TH32CS_SNAPNOHEAPS
#    define TH32CS_SNAPNOHEAPS    0x40000000
#  endif
#  ifndef TH32CS_SNAPMODULE32
#  define TH32CS_SNAPMODULE32 TH32CS_SNAPMODULE
#  endif
#else
#  define KERNEL_LIB_NAME   "kernel32.dll"
#  define TOOLHELP_LIB_NAME "kernel32.dll"
#  ifndef TH32CS_SNAPNOHEAPS
#    define TH32CS_SNAPNOHEAPS    0x0
#  endif
#endif

//--------------------------------------------------------------------------
inline bool is_wow64_process_h(HANDLE proc_handle, bool *is_wow64);
inline bool is_wow64_process(int pid, bool *is_wow64);

inline uchar win_prot_to_ida_perm(DWORD protection);

//--------------------------------------------------------------------------
class win_version_t
{
public:
  inline win_version_t();
  inline bool ok();
  inline bool is_NT();
  inline bool is_strictly_xp();     // Is strictly XP (32bit)?
  inline bool is_DW32();
  inline bool is_2K();              // Is at least Win2K?
  inline bool is_64bitOS();
  inline const OSVERSIONINFO &get_info();

private:
  OSVERSIONINFO OSVersionInfo;
  bool ver_ok;
};

//--------------------------------------------------------------------------
class win_tool_help_t
{
public:
  inline win_tool_help_t();
  inline ~win_tool_help_t();
  inline bool ok();
  inline bool use_debug_break_process();
  inline bool debug_break_process(HANDLE process_handle);
  inline bool use_debug_detach_process();
  inline bool debug_detach_process(pid_t pid);

private:
  // function prototypes
  typedef HANDLE (WINAPI *CreateToolhelp32Snapshot_t)(DWORD dwFlags, DWORD th32ProcessID);
  typedef BOOL   (WINAPI *Process32First_t)(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
  typedef BOOL   (WINAPI *Process32Next_t)(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
  typedef BOOL   (WINAPI *Module32First_t)(HANDLE hSnapshot, LPMODULEENTRY32 lpme);
  typedef BOOL   (WINAPI *Module32Next_t)(HANDLE hSnapshot, LPMODULEENTRY32 lpme);
  typedef BOOL   (WINAPI *DebugActiveProcessStop_t)(DWORD dwProcessID);
  typedef BOOL   (WINAPI *DebugBreakProcess_t)(HANDLE Process);
  typedef BOOL   (WINAPI *CloseToolhelp32Snapshot_t)(HANDLE hSnapshot);

  // functions pointers
  CreateToolhelp32Snapshot_t _CreateToolhelp32Snapshot;
  Process32First_t           _Process32First;
  Process32Next_t            _Process32Next;
  Module32First_t            _Module32First;
  Module32Next_t             _Module32Next;
  CloseToolhelp32Snapshot_t  _CloseToolhelp32Snapshot;
  DebugActiveProcessStop_t   _DebugActiveProcessStop;
  DebugBreakProcess_t        _DebugBreakProcess;

  HMODULE th_handle;
  bool use_debug_break;

  inline void term();

  friend class toolhelp_snapshot_t;
  friend class process_snapshot_t;
  friend class module_snapshot_t;
};

//--------------------------------------------------------------------------
class toolhelp_snapshot_t
{
  public:
    inline toolhelp_snapshot_t(win_tool_help_t *tool);
    inline ~toolhelp_snapshot_t();
    inline bool ok();
    inline bool open(uint32 flags, pid_t pid);
    inline void close();
    inline uint32 last_err();
  protected:
    bool seterr();        // always returns 'false' for convenience
    win_tool_help_t *t;
    HANDLE h;
    uint32 last_error;
};

//--------------------------------------------------------------------------
class process_snapshot_t: public toolhelp_snapshot_t
{
  public:
    inline process_snapshot_t(win_tool_help_t *tool);
    inline bool first(uint32 flags, LPPROCESSENTRY32 lppe);
    inline bool next(LPPROCESSENTRY32 lppe);
};

//--------------------------------------------------------------------------
class module_snapshot_t: public toolhelp_snapshot_t
{
  public:
    inline module_snapshot_t(win_tool_help_t *tool);
    inline bool first(uint32 flags, pid_t pid, LPMODULEENTRY32 lpme);
    inline bool next(LPMODULEENTRY32 lpme);
};

//--------------------------------------------------------------------------
inline win_version_t::win_version_t()
{
  OSVersionInfo.dwOSVersionInfoSize = sizeof(OSVersionInfo);
  ver_ok = GetVersionEx(&OSVersionInfo) != 0;
}

//--------------------------------------------------------------------------
inline bool win_version_t::ok()
{
  return ver_ok;
}

//--------------------------------------------------------------------------
inline bool win_version_t::is_NT()
{
  return ok() && OSVersionInfo.dwPlatformId == VER_PLATFORM_WIN32_NT;
}

//--------------------------------------------------------------------------
// Is strictly XP?
inline bool win_version_t::is_strictly_xp()
{
  return ok() && is_NT() && OSVersionInfo.dwMajorVersion == 5 && OSVersionInfo.dwMinorVersion == 1;
}

//--------------------------------------------------------------------------
inline bool win_version_t::is_DW32()
{
  return ok() && OSVersionInfo.dwPlatformId == 3;
}

//--------------------------------------------------------------------------
// Is at least Win2K?
inline bool win_version_t::is_2K()
{
  return ok() && OSVersionInfo.dwMajorVersion >= 5;
}

//--------------------------------------------------------------------------
inline bool win_version_t::is_64bitOS()
{
#ifdef __X64__
  return true;
#else
#ifndef UNDER_CE
  static char is_64 = -1;
  if ( is_64 != -1 )
    return is_64 != 0;
  if ( OSVersionInfo.dwMajorVersion > 5
    || OSVersionInfo.dwMajorVersion == 5 && OSVersionInfo.dwMinorVersion >= 1 )
  {
    bool is_wow64 = false;
    return is_wow64_process_h(GetCurrentProcess(), &is_wow64) && is_wow64;
  }
#endif
  return false;
#endif
}

//--------------------------------------------------------------------------
inline const OSVERSIONINFO &win_version_t::get_info()
{
  return OSVersionInfo;
}

//--------------------------------------------------------------------------
inline win_tool_help_t::win_tool_help_t()
{
  use_debug_break = !qgetenv("IDA_NO_DEBUGBREAKPROCESS");
  HMODULE kern_handle = GetModuleHandle(TEXT(KERNEL_LIB_NAME));
  *(FARPROC*)&_DebugActiveProcessStop = GetProcAddress(kern_handle, TEXT("DebugActiveProcessStop"));
  *(FARPROC*)&_DebugBreakProcess      = GetProcAddress(kern_handle, TEXT("DebugBreakProcess"));

  // load the library
  th_handle = LoadLibrary(TEXT(TOOLHELP_LIB_NAME));
  if ( th_handle == NULL )
    return;

  // find the needed functions
  *(FARPROC*)&_CreateToolhelp32Snapshot = GetProcAddress(th_handle, TEXT("CreateToolhelp32Snapshot"));
  *(FARPROC*)&_Process32First           = GetProcAddress(th_handle, TEXT("Process32First"));
  *(FARPROC*)&_Process32Next            = GetProcAddress(th_handle, TEXT("Process32Next"));
  *(FARPROC*)&_Module32First            = GetProcAddress(th_handle, TEXT("Module32First"));
  *(FARPROC*)&_Module32Next             = GetProcAddress(th_handle, TEXT("Module32Next"));
#ifdef UNDER_CE
  *(FARPROC*)&_CloseToolhelp32Snapshot  = GetProcAddress(th_handle, TEXT("CloseToolhelp32Snapshot"));
#endif

  bool is_ok = _CreateToolhelp32Snapshot != NULL
    && _Process32First != NULL
    && _Process32Next != NULL
#ifdef UNDER_CE
    && _CloseToolhelp32Snapshot  != NULL
#endif
    && _Module32First != NULL
    && _Module32Next != NULL;
  if ( !is_ok )
    term();
}

//--------------------------------------------------------------------------
inline win_tool_help_t::~win_tool_help_t()
{
  term();
}

//--------------------------------------------------------------------------
inline bool win_tool_help_t::ok()
{
  return th_handle != NULL;
}

//--------------------------------------------------------------------------
inline bool win_tool_help_t::use_debug_break_process()
{
  return use_debug_break && _DebugBreakProcess != NULL;
}

//--------------------------------------------------------------------------
inline bool win_tool_help_t::debug_break_process(HANDLE process_handle)
{
  return process_handle != INVALID_HANDLE_VALUE && _DebugBreakProcess(process_handle);
}

//--------------------------------------------------------------------------
inline bool win_tool_help_t::use_debug_detach_process()
{
  return _DebugActiveProcessStop != NULL;
}

//--------------------------------------------------------------------------
inline bool win_tool_help_t::debug_detach_process(pid_t pid)
{
  return _DebugActiveProcessStop != NULL && _DebugActiveProcessStop(pid);
}

//--------------------------------------------------------------------------
inline void win_tool_help_t::term()
{
  if ( th_handle != NULL )
  {
    FreeLibrary(th_handle);
    th_handle = NULL;
  }
}

//--------------------------------------------------------------------------
inline process_snapshot_t::process_snapshot_t(win_tool_help_t *tool)
  : toolhelp_snapshot_t(tool)
{
}

//--------------------------------------------------------------------------
inline bool process_snapshot_t::first(uint32 flags, LPPROCESSENTRY32 lppe)
{
  open(TH32CS_SNAPPROCESS | flags, 0);
  lppe->dwSize = sizeof(PROCESSENTRY32);
  if ( ok() && t->_Process32First(h, lppe) )
  {
    // ignore "System Process" (ID==0)
    return lppe->th32ProcessID==0 ? next(lppe) : true;
  }
  return seterr();
}

//--------------------------------------------------------------------------
inline bool process_snapshot_t::next(LPPROCESSENTRY32 lppe)
{
  while ( ok() )
  {
    if ( !t->_Process32Next(h, lppe) )
      break;
    // ignore "System Process" (ID==0)
    if ( lppe->th32ProcessID != 0 )
      return true;
  }
  return seterr();
}

//--------------------------------------------------------------------------
inline module_snapshot_t::module_snapshot_t(win_tool_help_t *tool)
  : toolhelp_snapshot_t(tool)
{
}

//--------------------------------------------------------------------------
inline bool module_snapshot_t::first(uint32 flags, pid_t pid, LPMODULEENTRY32 lpme)
{
  if ( !open(TH32CS_SNAPMODULE | flags, pid) )
    return false;
  lpme->dwSize = sizeof(MODULEENTRY32);
  if ( t->_Module32First(h, lpme) )
    return true;
  return seterr();
}

//--------------------------------------------------------------------------
inline bool module_snapshot_t::next(LPMODULEENTRY32 lpme)
{
  if ( ok() )
    return false;
  if ( t->_Module32Next(h, lpme) )
    return true;
  seterr();
  return false;
}

//--------------------------------------------------------------------------
inline toolhelp_snapshot_t::toolhelp_snapshot_t(win_tool_help_t *tool)
  : t(tool), h(INVALID_HANDLE_VALUE), last_error(0)
{
}

//--------------------------------------------------------------------------
inline toolhelp_snapshot_t::~toolhelp_snapshot_t()
{
  close();
}

//--------------------------------------------------------------------------
inline bool toolhelp_snapshot_t::ok()
{
  return h != INVALID_HANDLE_VALUE;
}

//--------------------------------------------------------------------------
// // always returns 'false' for convenience
inline bool toolhelp_snapshot_t::seterr()
{
  last_error = GetLastError();
  return false;
}

//--------------------------------------------------------------------------
// // always returns 'false' for convenience
inline uint32 toolhelp_snapshot_t::last_err()
{
  return last_error;
}

//--------------------------------------------------------------------------
inline bool toolhelp_snapshot_t::open(uint32 flags, pid_t pid)
{
  if ( !t->ok() )
    return false;
  close();
  for ( int cnt=0; cnt < 5; cnt++ )
  {
    h = t->_CreateToolhelp32Snapshot(flags, pid);
    if ( h != INVALID_HANDLE_VALUE )
      return true;
    seterr();
    // MSDN: If the function fails with ERROR_BAD_LENGTH, retry
    //       the function until it succeeds.
    if ( last_err() != ERROR_BAD_LENGTH
      || (flags & (TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32)) == 0 )
      break;
  }
  return false;
}

//--------------------------------------------------------------------------
inline void toolhelp_snapshot_t::close()
{
  if ( t->ok() && h != INVALID_HANDLE_VALUE )
  {
#ifdef UNDER_CE
    t->_CloseToolhelp32Snapshot(h);
#else
    CloseHandle(h);
#endif
  }
}

//--------------------------------------------------------------------------
#ifndef UNDER_CE
inline bool is_wow64_process_h(HANDLE proc_handle, bool *is_wow64)
{
  typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
  static LPFN_ISWOW64PROCESS fnIsWow64Process = NULL;
  static bool is_wow_defined = false;
  if ( !is_wow_defined )
  {
    *(FARPROC*)&fnIsWow64Process = GetProcAddress(GetModuleHandle(TEXT("kernel32")),"IsWow64Process");
    is_wow_defined = true;
  }
  if ( fnIsWow64Process != NULL )
  {
    BOOL bIsWow64 = FALSE;
    if ( !fnIsWow64Process(proc_handle, &bIsWow64) )
      return false;
    *is_wow64 = bIsWow64 != 0;
    return true;
  }
  return false;
}
#else
inline bool is_wow64_process_h(HANDLE, bool *)
{
  return false;
}
#endif

//--------------------------------------------------------------------------
inline bool is_wow64_process(int pid, bool *is_wow64)
{
  HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
  if ( h == NULL )
    return false;
  return is_wow64_process_h(h, is_wow64);
}

//--------------------------------------------------------------------------
// convert Windows protection modes to IDA protection modes
inline uchar win_prot_to_ida_perm(DWORD protection)
{
  uchar perm = 0;

  if ( protection & PAGE_READONLY )          perm |= SEGPERM_READ;
  if ( protection & PAGE_READWRITE )         perm |= SEGPERM_READ | SEGPERM_WRITE;
  if ( protection & PAGE_WRITECOPY )         perm |= SEGPERM_READ | SEGPERM_WRITE;
  if ( protection & PAGE_EXECUTE )           perm |=                                SEGPERM_EXEC;
  if ( protection & PAGE_EXECUTE_READ )      perm |= SEGPERM_READ                 | SEGPERM_EXEC;
  if ( protection & PAGE_EXECUTE_READWRITE ) perm |= SEGPERM_READ | SEGPERM_WRITE | SEGPERM_EXEC;
  if ( protection & PAGE_EXECUTE_WRITECOPY ) perm |= SEGPERM_READ | SEGPERM_WRITE | SEGPERM_EXEC;

  return perm;
}

#endif // __NT__
#endif // __TOOLHELP_HPP__
