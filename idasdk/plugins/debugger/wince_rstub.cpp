#define REMOTE_DEBUGGER
#define RPC_CLIENT

#include <map>

#ifdef USE_ASYNC
static const char wanted_name[] = "Remote WinCE debugger (ActiveSync)";
#define DEBUGGER_NAME  "wince"
#define DEBUGGER_ID    DEBUGGER_ID_ARM_WINCE_ASYNC
#define DEBUGGER_FLAGS (DBG_FLAG_REMOTE       \
                      | DBG_FLAG_NOHOST       \
                      | DBG_FLAG_FAKE_ATTACH  \
                      | DBG_FLAG_HWDATBPT_ONE \
                      | DBG_FLAG_CLEAN_EXIT   \
                      | DBG_FLAG_NOPASSWORD   \
                      | DBG_FLAG_NOSTARTDIR   \
                      | DBG_FLAG_EXITSHOTOK   \
                      | DBG_FLAG_LOWCNDS      \
                      | DBG_FLAG_PREFER_SWBPTS)
#else
static const char wanted_name[] = "Remote WinCE debugger (TCP/IP)";
#define DEBUGGER_NAME  "wincetcp"
#define DEBUGGER_ID    DEBUGGER_ID_ARM_WINCE_TCPIP
#define DEBUGGER_FLAGS (DBG_FLAG_REMOTE       \
                      | DBG_FLAG_FAKE_ATTACH  \
                      | DBG_FLAG_HWDATBPT_ONE \
                      | DBG_FLAG_CLEAN_EXIT   \
                      | DBG_FLAG_NOPASSWORD   \
                      | DBG_FLAG_NOSTARTDIR   \
                      | DBG_FLAG_EXITSHOTOK   \
                      | DBG_FLAG_LOWCNDS      \
                      | DBG_FLAG_PREFER_SWBPTS)
#endif

#define DEFAULT_PLATFORM_NAME "win32"
#define WINCE_DEBUGGER
#define PROCESSOR_NAME "arm"
#define TARGET_PROCESSOR PLFM_ARM
#define SET_DBG_OPTIONS set_wince_options
#define S_MAP_ADDRESS   local_pstos0
#define S_FILETYPE      f_PE
#define win32_init_plugin       init_plugin
#define win32_term_plugin       term_plugin

#include <pro.h>
#include <err.h>
#include <ua.hpp>
#include <idd.hpp>
#include <loader.hpp>
#include "rpc_client.h"
#include "rpc_debmod.h"

rpc_debmod_t g_dbgmod(DEFAULT_PLATFORM_NAME);
#include "common_stub_impl.cpp"
#include "arm_local_impl.cpp"
#include "win32_local_impl.cpp"

static ea_t idaapi local_pstos0(ea_t ea, const regval_t *, int);
static bool wince_load_options(void);
static const char *idaapi set_wince_options(const char *keyword, int pri, int value_type, const void *value);

#include "wince.hpp"
#include "common_local_impl.cpp"

ea_t slot;

//----------------------------------------------------------------------
// map process slot to slot 0
static ea_t idaapi local_pstos0(ea_t ea, const regval_t *, int)
{
  if ( slot == BADADDR )
  {
    slot = s_ioctl(1, NULL, 0, NULL, NULL);        // get slot number
  }
  return pstos0(ea);
}

//----------------------------------------------------------------------
static bool enable_hwbpts(bool enable)
{
  if ( debugger_inited )
  {
    int32 x = enable;
    return s_ioctl(2, &x, sizeof(x), NULL, NULL) != 0;
  }
  return true;
}

//--------------------------------------------------------------------------
#define WINCE_NODE  "$ wince rstub"

// wince option - "enable hardware breakpoints"
static uval_t hwbpts = 0;

enum wince_opts_t
{
  OPTID_HWBPTS_ENABLED,
};

//--------------------------------------------------------------------------
static void wince_save_options(void)
{
  if ( netnode::inited() )
  {
    netnode node;
    node.create(WINCE_NODE);
    if ( node != BADNODE )
    {
      node.supset(OPTID_HWBPTS_ENABLED, &hwbpts, sizeof(hwbpts));
    }
  }
}

//--------------------------------------------------------------------------
static bool wince_load_options(void)
{
  if ( netnode::inited() )
  {
    netnode node;
    node.create(WINCE_NODE);
    if ( node != BADNODE )
    {
      node.supval(OPTID_HWBPTS_ENABLED, &hwbpts, sizeof(hwbpts));
      enable_hwbpts(hwbpts != 0);
    }
    return true;
  }
  return false;
}

//----------------------------------------------------------------------
static const char *idaapi set_wince_options(
        const char *keyword,
        int pri,
        int value_type,
        const void *value)
{
  if ( keyword == NULL ) // interactive call
  {
    static const char form[] =
      "Windows CE debugger specific options\n"
      "\n"
      "  <Enable hardware breakpoints:C>>\n"
      "\n";

    if ( !AskUsingForm_c(form, &hwbpts) )
      return IDPOPT_OK;
    wince_save_options();
  }
  else
  {
    if ( *keyword == '\0' )
    {
      // we are done with the .cfg file, time to load parameters stored in
      // the database
      wince_load_options();
      return IDPOPT_OK;
    }
    if ( strcmp(keyword, "HWBPTS_ENABLED") != 0 )
      return IDPOPT_BADKEY;
    if ( value_type != IDPOPT_BIT )
      return IDPOPT_BADTYPE;
    hwbpts = *(int*)value;
    if ( pri == IDPOPT_PRI_HIGH )
      wince_save_options();
  }
  enable_hwbpts(hwbpts != 0);
  return IDPOPT_OK;
}

//----------------------------------------------------------------------
bool myread(ea_t ea, void *buf, size_t size)
{
  if ( s_read_memory(ea, buf, size) != size )
  {
    msg("%a: rpc read memory error\n", ea);
    return false;
  }
  return true;
}
