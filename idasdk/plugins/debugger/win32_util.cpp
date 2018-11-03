#include <windows.h>
#include <pro.h>
#include "winbase_debmod.h"
#include "win32_util.hpp"

#ifdef __X64__
typedef BOOL WINAPI IsWow64Process_t(HANDLE, PBOOL);
static IsWow64Process_t *_IsWow64Process = NULL;
#endif

//--------------------------------------------------------------------------
wow64_state_t check_wow64_handle(HANDLE handle)
{
#ifndef __X64__
  qnotused(handle);
#else
  if ( _IsWow64Process == NULL )
  {
    HMODULE k32 = GetModuleHandle(TEXT(KERNEL_LIB_NAME));
    *(FARPROC*)&_IsWow64Process = GetProcAddress(k32, TEXT("IsWow64Process"));
    if ( _IsWow64Process == NULL )
      return WOW64_NONE; // unknown
  }
  BOOL bIsWow64 = FALSE;
  if ( _IsWow64Process(handle, &bIsWow64) && bIsWow64 != 0 )
    return WOW64_YES;
#endif
  return WOW64_NO;
}

//--------------------------------------------------------------------------
wow64_state_t check_wow64_pid(int pid)
{
  wow64_state_t r = WOW64_BAD; // assume pid is bad
  HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
  if ( h != NULL )
  {
    r = check_wow64_handle(h);
    CloseHandle(h);
  }
  return r;
}

//--------------------------------------------------------------------------
#ifdef _MSC_VER
#  pragma warning(push)
#  pragma warning(disable: 4996) // GetVersionEx was declared deprecated
#endif
win_version_t::win_version_t()
{
  OSVersionInfo.dwOSVersionInfoSize = sizeof(OSVersionInfo);
  ver_ok = GetVersionEx(&OSVersionInfo) != 0;
#if !defined(UNDER_CE) && !defined(__X64__)
  is_64bit_os = false;
  if ( OSVersionInfo.dwMajorVersion > 5
    || OSVersionInfo.dwMajorVersion == 5 && OSVersionInfo.dwMinorVersion >= 1 )
  {
    is_64bit_os = check_wow64_handle(GetCurrentProcess()) > 0;
  }
#endif
}
#ifdef _MSC_VER
#  pragma warning(pop)
#endif

//--------------------------------------------------------------------------
win_tool_help_t::win_tool_help_t()
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
    && _CloseToolhelp32Snapshot != NULL
#endif
    && _Module32First != NULL
    && _Module32Next != NULL;
  if ( !is_ok )
    term();
}

