#define REMOTE_DEBUGGER
#define RPC_CLIENT

static const char wanted_name[] = "Remote Windows debugger";

#define DEBUGGER_NAME  "win32"
#define PROCESSOR_NAME "metapc"
#define DEFAULT_PLATFORM_NAME "win32"
#define TARGET_PROCESSOR PLFM_386
#define DEBUGGER_ID    DEBUGGER_ID_X86_IA32_WIN32_USER
#define DEBUGGER_FLAGS (DBG_FLAG_REMOTE       \
                      | DBG_FLAG_EXITSHOTOK   \
                      | DBG_FLAG_LOWCNDS      \
                      | DBG_FLAG_DEBTHREAD    \
                      | DBG_FLAG_ANYSIZE_HWBPT)
#define DEBUGGER_RESMOD (DBG_RESMOD_STEP_INTO)
#define HAVE_APPCALL
#define S_FILETYPE     f_PE
#define win32_init_plugin       init_plugin
#define win32_term_plugin       term_plugin

#include <pro.h>
#include <idp.hpp>
#include <idd.hpp>
#include <ua.hpp>
#include <area.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include "tcpip.h"
#include "w32sehch.h" //lint -esym(766, w32sehch.h) not used
#include "rpc_client.h"
#include "rpc_debmod.h"

rpc_debmod_t g_dbgmod(DEFAULT_PLATFORM_NAME);
#include "common_stub_impl.cpp"

#include "pc_local_impl.cpp"
#include "win32_local_impl.cpp"
#include "common_local_impl.cpp"
