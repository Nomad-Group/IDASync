#include <set>
#include <pro.h>
#include <name.hpp>
#include <kernwin.hpp>
#include <dbg.hpp>
#include <loader.hpp>
#include "w32sehch.h"

static int req_id = -1;

//---------------------------------------------------------------------------
struct x86seh_ctx_t
{
  qvector<uint32> handlers;
  qstring title;
  thid_t tid;

  bool get_sehlist();
  x86seh_ctx_t(thid_t _tid, const char *_title): title(_title),tid(_tid) {}
  void refresh();
};

//---------------------------------------------------------------------------
bool x86seh_ctx_t::get_sehlist()
{
  uint64 fs_sel;
  ea_t fs_base;
  uint32 excr_ea;
  handlers.clear();
  if ( !get_reg_val("fs", &fs_sel)
    || internal_get_sreg_base(tid, int(fs_sel), &fs_base) <= 0
    || read_dbg_memory(fs_base, &excr_ea, sizeof(excr_ea)) != sizeof(excr_ea) )
  {
    warning("Failed to build the SEH list for thread %08X", tid);
    return false;
  }

  struct EXC_REG_RECORD
  {
    uint32 p_prev;
    uint32 p_handler;
  };
  EXC_REG_RECORD rec;
  std::set<uint32> seen;
  while ( excr_ea != 0xffffffff )
  {
    if ( read_dbg_memory(excr_ea, &rec, sizeof(rec)) != sizeof(rec) )
      break;

    if ( !seen.insert(excr_ea).second )
    {
      msg("Circular SEH record has been detected\n");
      break;
    }

    handlers.push_back(rec.p_handler);
    excr_ea = rec.p_prev;
  }
  return true;
}

//---------------------------------------------------------------------------
void x86seh_ctx_t::refresh()
{
  get_sehlist();
  refresh_chooser(title.c_str());
}

//---------------------------------------------------------------------------
static int idaapi dbg_callback(void *obj, int code, va_list)
{
  if ( code == dbg_suspend_process )
  {
    x86seh_ctx_t *ctx = (x86seh_ctx_t *)obj;
    ctx->refresh();
  }
  return 0;
}

//---------------------------------------------------------------------------
static const char *const x86seh_chooser_cols[] =
{
  "Address",
  "Name"
};

static const int widths[] =
{
  10 | CHCOL_HEX,
  30
};
CASSERT(qnumber(widths) == qnumber(x86seh_chooser_cols));

//---------------------------------------------------------------------------
static uint32 idaapi ch_sizer(void *obj)
{
  x86seh_ctx_t *ctx = (x86seh_ctx_t *)obj;
  return ctx->handlers.size();
}

//---------------------------------------------------------------------------
static void idaapi ch_getl(void *obj, uint32 n, char *const *arrptr)
{
  x86seh_ctx_t *ctx = (x86seh_ctx_t *)obj;
  if ( n == 0 )
  {
    qstrncpy(arrptr[0], x86seh_chooser_cols[0], MAXSTR);
    qstrncpy(arrptr[1], x86seh_chooser_cols[1], MAXSTR);
    return;
  }
  uint32 addr = ctx->handlers[n-1];
  qsnprintf(arrptr[0], MAXSTR, "%08X", addr);
  get_nice_colored_name(addr, arrptr[1], MAXSTR, GNCN_NOCOLOR | GNCN_NOLABEL);
}

//---------------------------------------------------------------------------
static uint32 idaapi ch_update(void *obj, uint32 n)
{
  x86seh_ctx_t *ctx = (x86seh_ctx_t *)obj;
  ctx->get_sehlist();
  return n;
}

//---------------------------------------------------------------------------
static void idaapi ch_enter(void *obj, uint32 n)
{
  x86seh_ctx_t *ctx = (x86seh_ctx_t *)obj;
  if ( --n < ctx->handlers.size() )
  {
    ea_t ea = ctx->handlers[n];
    if ( !isCode(get_flags_novalue(ea)) )
      create_insn(ea);

    jumpto(ea);
  }
}

//---------------------------------------------------------------------------
static void idaapi ch_destroy(void *obj)
{
  x86seh_ctx_t *ctx = (x86seh_ctx_t *)obj;
  unhook_from_notification_point(HT_DBG, dbg_callback, ctx);
  delete ctx;
}

//-------------------------------------------------------------------------
struct show_window_ah_t : public action_handler_t
{
  virtual int idaapi activate(action_activation_ctx_t *)
  {
    thid_t tid = get_current_thread();

    // Find and refresh existing window
    char title[MAXSTR];
    qsnprintf(title, sizeof(title), "[%04X] - Structured exception handlers list", tid);
    TForm *form = find_tform(title); //lint !e64
    if ( form != NULL )
    {
      switchto_tform(form, true); //lint !e64
      return 1;
    }

    x86seh_ctx_t *ch = new x86seh_ctx_t(tid, title);
    if ( !ch->get_sehlist() )
    {
      delete ch;
      return 0;
    }

    int code = choose2(CH_NOBTNS,
                       -1, -1, -1, -1,
                       ch,
                       qnumber(x86seh_chooser_cols),
                       widths,
                       ch_sizer,
                       ch_getl,
                       title,
                       144, // icon
                       1,
                       NULL,
                       NULL,
                       ch_update,
                       NULL,
                       ch_enter,
                       ch_destroy,
                       NULL,
                       NULL);
    if ( code != -1 )
      hook_to_notification_point(HT_DBG, dbg_callback, ch);

    //lint -esym(429,ch) custodial pointer has not been freed or returned
    return 1;
  }

  virtual action_state_t idaapi update(action_update_ctx_t *)
  {
    return AST_ENABLE;
  }
};
static show_window_ah_t show_window_ah;


//---------------------------------------------------------------------------
void remove_x86seh_menu()
{
  if ( req_id != -1 )
  {
    cancel_exec_request(req_id);
    req_id = -1;
  }
}

//---------------------------------------------------------------------------
void install_x86seh_menu()
{
  // HACK: We queue this request because commdbg apparently enables the debug menus
  //       just after calling init_debugger().
  struct uireq_install_menu_t: public ui_request_t
  {
    virtual bool idaapi run()
    {
      if ( !inf.is_64bit() )
      {
        register_and_attach_to_menu(
                "Debugger/Debugger windows/Stack trace",
                "dbg:sehList", "SEH list", NULL, SETMENU_APP,
                &show_window_ah,
                &PLUGIN);
      }
      req_id = -1;
      return false;
    }
  };
  req_id = execute_ui_requests(new uireq_install_menu_t, NULL);
}
