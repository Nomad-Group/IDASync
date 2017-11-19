/*
        This is the iPhone user land debugger entry point file
*/
//lint -esym(750,__LITTLE_ENDIAN__,__inline__) not referenced
#undef  __LITTLE_ENDIAN__
#define __LITTLE_ENDIAN__
#define __inline__ inline
#define REMOTE_DEBUGGER
#define RPC_CLIENT

static const char wanted_name[] = "Remote iPhone v1.x debugger";
#define DEBUGGER_NAME  "iphone"
#define PROCESSOR_NAME "arm"
#define DEFAULT_PLATFORM_NAME "macosx"
#define TARGET_PROCESSOR PLFM_ARM
#define DEBUGGER_ID    DEBUGGER_ID_ARM_IPHONE_USER
#define DEBUGGER_FLAGS DBG_FLAG_REMOTE
#define S_FILETYPE     f_MACHO

#include <pro.h>
#include <idp.hpp>
#include <idd.hpp>
#include <ua.hpp>
#include <area.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include "rpc_client.h"
#include "rpc_debmod.h"
#include "tcpip.h"

rpc_debmod_t g_dbgmod(DEFAULT_PLATFORM_NAME);
#include "common_stub_impl.cpp"

#include "arm_local_impl.cpp"
#include "mac_local_impl.cpp"
#include "common_local_impl.cpp"
