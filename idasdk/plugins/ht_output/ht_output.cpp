/*
 *  This is a sample plugin demonstrating receiving output window notification callbacks
 *  and using of new output window functions: get_output_curline, get_output_cursor,
 *  get_output_selected_text, add_output_popup
 *
 */

#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

static form_actions_t *fa;
static qstring selected_data;

#define ACTION_NAME "ht_output:PrintSelection"

AS_PRINTF(1, 2) static void form_msg(const char *format, ...)
{
  textctrl_info_t ti;
  fa->get_text_value(1, &ti);
  va_list va;
  va_start(va, format);
  ti.text.cat_vsprnt(format, va);
  va_end(va);
  fa->set_text_value(1, &ti);
}

//---------------------------------------------------------------------------
void desc_notification(const char *notification_name)
{
  form_msg("Received notification from output window: \"%s\"\n", notification_name);
}

//---------------------------------------------------------------------------
// Callback for ui notifications
static ssize_t idaapi ui_callback(void * /*ud*/, int notification_code, va_list va)
{
  switch ( notification_code )
  {
    // called when IDA is preparing a context menu for a view
    // Here dynamic context-depending user menu items can be added.
    case ui_populating_widget_popup:
      {
        TWidget *f = va_arg(va, TWidget *);
        if ( get_widget_type(f) == BWN_OUTPUT )
        {
          TPopupMenu *p = va_arg(va, TPopupMenu *);
          selected_data.qclear();
          if ( get_output_selected_text(&selected_data) )
            attach_action_to_popup(f, p, ACTION_NAME);
          desc_notification("msg_popup");
        }
      }
      break;
  }
  return 0;
}

//---------------------------------------------------------------------------
// Callback for view notifications
static ssize_t idaapi output_callback(void * /*ud*/, int notification_code, va_list va)
{
  switch ( notification_code )
  {
    case msg_activated:
      desc_notification("msg_activated");
      break;
    case msg_deactivated:
      desc_notification("msg_deactivated");
      break;
    case msg_keydown:
      {
        desc_notification("msg_keydown");
        int key = va_arg(va, int);
        int state = va_arg(va, int);
        form_msg("Parameters: Key:%d(\'%c\') State:%d\n", key, key, state);
      }
      break;
    case msg_click:
    case msg_dblclick:
      {
        desc_notification(notification_code == msg_click ? "msg_click" : "msg_dblclick");
        int px = va_arg(va, int);
        int py = va_arg(va, int);
        int state = va_arg(va, int);
        qstring buf;
        if ( get_output_curline(&buf, false) )
          form_msg("Clicked string: %s\n", buf.c_str());
        int cx,cy;
        get_output_cursor(&cx, &cy);
        msg("Parameters: x:%d, y:%d, state:%d\n", px, py, state);
        msg("Cursor position:(%d, %d)\n", cx, cy);
      }
      break;
    case msg_closed:
      desc_notification("msg_closed");
  }
  return 0;
}

//-------------------------------------------------------------------------
struct printsel_t : public action_handler_t
{
  virtual int idaapi activate(action_activation_ctx_t *)
  {
    form_msg("User menu item is called for selection: \"%s\"\n", selected_data.c_str());
    return 1;
  }

  virtual action_state_t idaapi update(action_update_ctx_t *)
  {
    return AST_ENABLE_ALWAYS;
  }
};
static printsel_t printsel_ah;
static const action_desc_t print_selection_action = ACTION_DESC_LITERAL(
        ACTION_NAME,
        "Print selection",
        &printsel_ah,
        NULL,
        NULL,
        -1);

//--------------------------------------------------------------------------
int idaapi init(void)
{
  return PLUGIN_KEEP;
}

//--------------------------------------------------------------------------
// this callback is called when something happens in our editor form
static int idaapi editor_modcb(int fid, form_actions_t &f_actions)
{
  if ( fid == CB_INIT ) // Initialization
  {
    /* set callback for output window notifications */
    hook_to_notification_point(HT_UI, ui_callback);
    hook_to_notification_point(HT_OUTPUT, output_callback);
    fa = &f_actions;
  }
  else if ( fid == CB_CLOSE )
  {
    unhook_from_notification_point(HT_OUTPUT, output_callback);
    unhook_from_notification_point(HT_UI, ui_callback);
  }
  return 1;
}

//--------------------------------------------------------------------------
bool idaapi run(size_t)
{
  static const char formdef[] =
    "BUTTON NO NONE\n"        // we do not want the standard buttons on the form
    "BUTTON YES NONE\n"
    "BUTTON CANCEL NONE\n"
    "Editor form\n"           // the form title. it is also used to refer to the form later
    "\n"
    "%/"                      // placeholder for the 'editor_modcb' callback
    "<Text:t1:30:40:::>\n"    // text edit control
    "\n";

  // structure for text edit control
  textctrl_info_t ti;
  ti.cb = sizeof(textctrl_info_t);
  ti.text = "";

  open_form(formdef, 0, editor_modcb, &ti);
  register_action(print_selection_action);
  return true;
}

static const char wanted_name[] = "HT_OUTPUT notifications handling example";
static const char wanted_hotkey[] = "Ctrl-Alt-F11";
//--------------------------------------------------------------------------
static const char comment[] = "HT_OUTPUT notifications handling";
static const char help[] =
        "This pluging demonstrates handling of output window\n"
        "notifications: Activation/Desactivation, adding\n"
        "popup menus, keyboard and mouse events, changing of current\n"
        "cursor position and closing of view\n";

//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  0,                    // plugin flags
  init,                 // initialize

  NULL,                 // terminate. this pointer may be NULL.

  run,                  // invoke plugin

  comment,              // long comment about the plugin
                        // it could appear in the status line
                        // or as a hint

  help,                 // multiline help about the plugin

  wanted_name,          // the preferred short name of the plugin
  wanted_hotkey         // the preferred hotkey to run the plugin
};
