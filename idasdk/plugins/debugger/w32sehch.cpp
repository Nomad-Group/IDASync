#include <set>
#include <pro.h>
#include <name.hpp>
#include <kernwin.hpp>
#include <dbg.hpp>
#include <loader.hpp>
#include "w32sehch.h"

static int req_id = -1;

//-------------------------------------------------------------------------
// non-modal exception handler chooser
struct x86seh_chooser_t : public chooser_t
{
protected:
  thid_t tid;
  qvector<uint32> list; //lint !e958 padding is required to align members
  qstring title_;

  static const int widths_[];
  static const char *const header_[];
  enum { ICON = 144 };

public:
  // this object must be allocated using `new`
  x86seh_chooser_t(thid_t tid);
  virtual ~x86seh_chooser_t()
  {
    unhook_from_notification_point(
            HT_DBG,
            dbg_handler, const_cast<char *>(title));
  }
  //lint -e{1511} member hides non-virtual member
  ssize_t choose(uint32 addr = uint32(-1))
  {
    return ::choose(this, &addr);
  }

  virtual const void *get_obj_id(size_t *len) const
  {
    *len = sizeof(tid);
    return &tid;
  }

  virtual size_t idaapi get_count() const { return list.size(); }
  virtual void idaapi get_row(
          qstrvec_t *cols,
          int *icon_,
          chooser_item_attrs_t *attrs,
          size_t n) const;
  virtual cbret_t idaapi enter(size_t n);

  // calculate the location of the item,
  // `item_data` is a pointer to a 32-bit address
  virtual ssize_t idaapi get_item_index(const void *item_data) const;
  virtual bool idaapi init();
  virtual cbret_t idaapi refresh(ssize_t n);

protected:
  static ssize_t idaapi dbg_handler(void *ud, int notif_code, va_list va);
};

//-------------------------------------------------------------------------
const int x86seh_chooser_t::widths_[] =
{
  CHCOL_HEX | 10, // Address
  30,             // Name
};
const char *const x86seh_chooser_t::header_[] =
{
  "Address",  // 0
  "Name",     // 1
};

//-------------------------------------------------------------------------
inline x86seh_chooser_t::x86seh_chooser_t(thid_t tid_)
  : chooser_t(CH_NOBTNS | CH_FORCE_DEFAULT | CH_CAN_REFRESH,
              qnumber(widths_), widths_, header_),
    tid(tid_),
    list()
{
  title_.sprnt("[%04X] - Structured exception handlers list", tid);
  title = title_.c_str();
  CASSERT(qnumber(widths_) == qnumber(header_));
  icon = ICON;

  hook_to_notification_point(
          HT_DBG,
          dbg_handler, const_cast<char *>(title));
}

//-------------------------------------------------------------------------
void idaapi x86seh_chooser_t::get_row(
        qstrvec_t *cols_,
        int *,
        chooser_item_attrs_t *,
        size_t n) const
{
  // assert: n < list.size()
  uint32 addr = list[n];

  qstrvec_t &cols = *cols_;
  cols[0].sprnt("%08X", addr);
  get_nice_colored_name(&cols[1], addr, GNCN_NOCOLOR | GNCN_NOLABEL);
  CASSERT(qnumber(header_) == 2);
}

//-------------------------------------------------------------------------
chooser_t::cbret_t idaapi x86seh_chooser_t::enter(size_t n)
{
  // assert: n < list.size()
  ea_t ea = ea_t(list[n]);
  if ( !is_code(get_flags(ea)) )
    create_insn(ea);
  jumpto(ea);
  return cbret_t(); // nothing changed
}

//------------------------------------------------------------------------
ssize_t idaapi x86seh_chooser_t::get_item_index(const void *item_data) const
{
  if ( list.empty() )
    return NO_SELECTION;

  // `item_data` is a pointer to a 32-bit address
  uint32 item_addr = *(const uint32 *)item_data;
  if ( item_addr == uint32(-1) )
    return 0; // first item by default

  // find `item_script` in the list
  const uint32 *p = list.find(item_addr);
  if ( p != list.end() )
    return p - list.begin();
  return 0; // first item by default
}

//--------------------------------------------------------------------------
bool idaapi x86seh_chooser_t::init()
{
  // rebuild the handlers list
  uint64 fs_sel;
  ea_t fs_base;
  uint32 excr_ea;
  list.clear();
  if ( !get_reg_val("fs", &fs_sel)
    || internal_get_sreg_base(&fs_base, tid, int(fs_sel)) <= 0
    || read_dbg_memory(fs_base, &excr_ea, sizeof(excr_ea)) != sizeof(excr_ea) )
  {
    warning("Failed to build the SEH list for thread %08X", tid);
    return false; // do not show the empty chooser
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

    list.push_back(rec.p_handler);
    excr_ea = rec.p_prev;
  }
  return true;
}

//------------------------------------------------------------------------
chooser_t::cbret_t idaapi x86seh_chooser_t::refresh(ssize_t n)
{
  uint32 item_addr = uint32(-1);
  if ( n >= 0 && n < list.size() )
    item_addr = list[n];  // remember the currently selected handler

  init();

  if ( n < 0 )
    return NO_SELECTION;
  ssize_t idx = get_item_index(&item_addr);
  // no need to adjust `idx` as get_item_index() returns first item by
  // default
  return idx;
}

//-------------------------------------------------------------------------
ssize_t idaapi x86seh_chooser_t::dbg_handler(void *ud, int code, va_list)
{
  if ( code == dbg_suspend_process )
  {
    const char *ttl = static_cast<const char *>(ud);
    refresh_chooser(ttl);
  }
  return 0;
}


//-------------------------------------------------------------------------
struct show_window_ah_t : public action_handler_t
{
  virtual int idaapi activate(action_activation_ctx_t *)
  {
    thid_t tid = get_current_thread();
    x86seh_chooser_t *ch = new x86seh_chooser_t(tid);
    //lint -e{429} Custodial pointer 'ch' has not been freed or returned
    return ch->choose() == 0;
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
