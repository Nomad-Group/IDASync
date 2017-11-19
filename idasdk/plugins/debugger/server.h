#ifndef SERVER_H
#define SERVER_H

#include <map>
#include <algorithm>

#include <fpro.h>
#include <expr.hpp>
#ifndef UNDER_CE
#  include <signal.h>
#endif

#ifdef __NT__
//#  ifndef SIGHUP
//#    define SIGHUP 1
//#  endif
#  if defined(__X64__)
#    define SYSTEM "Windows"
#  elif defined(UNDER_CE)
#    define SYSTEM "WindowsCE"
#  else
#    define SYSTEM "Windows"
#  endif
#  ifdef UNDER_CE
#    ifdef USE_ASYNC
#      define DEBUGGER_ID    DEBUGGER_ID_ARM_WINCE_ASYNC
#    else
#      define socklen_t int
#      define DEBUGGER_ID    DEBUGGER_ID_ARM_WINCE_TCPIP
#    endif
#  else
#    define socklen_t int
#    define DEBUGGER_ID    DEBUGGER_ID_X86_IA32_WIN32_USER
#  endif
#else   // not NT, i.e. UNIX
#  if defined(__LINUX__)
#    if defined(__ARM__)
#      if defined(__ANDROID__)
#        define SYSTEM "Android"
#      else
#        define SYSTEM "ARM Linux"
#      endif
#      define DEBUGGER_ID    DEBUGGER_ID_ARM_LINUX_USER
#    else
#      define SYSTEM "Linux"
#      define DEBUGGER_ID    DEBUGGER_ID_X86_IA32_LINUX_USER
#    endif
     // linux debugger can not be multithreaded because it uses thread_db.
     // i doubt that this library is meant to be used with multiple
     // applications simultaneously.
#    define __SINGLE_THREADED_SERVER__
#  elif defined(__MAC__)
#    if defined(__arm__)
#      define SYSTEM "iPhone"
#      define DEBUGGER_ID    DEBUGGER_ID_ARM_IPHONE_USER
#    else
#      define SYSTEM "Mac OS X"
#      define DEBUGGER_ID    DEBUGGER_ID_X86_IA32_MACOSX_USER
#    endif
#  else
#    error "Unknown platform"
#  endif
#  include <sys/socket.h>
#  include <netinet/in.h>
#  ifdef LIBWRAP
extern "C" const char *check_connection(int);
#  endif // LIBWRAP
#endif // !__NT__

#ifdef __X64__
#define SYSBITS " 64-bit"
#else
#define SYSBITS " 32-bit"
#endif

#ifdef UNDER_CE
#  ifndef __SINGLE_THREADED_SERVER__
#    define __SINGLE_THREADED_SERVER__
#  endif
#endif

#ifdef __SINGLE_THREADED_SERVER__
#  define __SERVER_TYPE__ "ST"
#else
#  define __SERVER_TYPE__ "MT"
#endif

#include "debmod.h"
#include "rpc_hlp.h"
#include "rpc_server.h"

// sizeof(ea_t)==8 and sizeof(size_t)==4 servers can not be used to debug 64-bit
// applications. but to debug 32-bit applications, simple 32-bit servers
// are enough and can work with both 32-bit and 64-bit versions of ida.
// so, there is no need to build sizeof(ea_t)==8 and sizeof(size_t)==4 servers
#if defined(__EA64__) != defined(__X64__)
#error "Mixed mode servers do not make sense, they should not be compiled"
#endif

extern rpc_server_list_t clients_list;

#endif
