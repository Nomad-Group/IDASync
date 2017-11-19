/*
 *  This plugin demonstrates how to use non modal forms.
 *  It creates 2 windows on the screen:
 *      - a window with 4 buttons: dock, undock, show, hide      (CONTROL FORM)
 *      - a window with a text edit control and a list control   (EDITOR FORM)
 *  The buttons of the first window can be used to manage the second window.
 *  We will call the first window 'CONTROL FORM' and the second window 'EDITOR
 *  FORM', just to be able to reference them easily.
 */

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

// the editor form
static TForm *editor_tform;

// chooser (list view) items
static const char *const names[] =
{
  "Item one",
  "Item two",
  "Item three"
};

// contents of the text field for each item
static qstring txts[] =
{
  "Text one:\n This is text for item one",
  "Text two:\n And this is text for item two",
  "Text three:\n And finally text for the last item"
};

// Current index for chooser list view
static int curidx = 0;
// Form actions for control dialog
static form_actions_t *control_fa;
// Defines where to place new/existing editor window
static bool dock = false;

// Form actions for editor window
enum editor_form_actions
{
  TEXT_CHANGED  = 1,
  ITEM_SELECTED = 2,
};

// Form actions for control window
enum control_form_actions
{
  BTN_DOCK   = 10,
  BTN_UNDOCK = 11,
  BTN_OPEN   = 12,
  BTN_CLOSE  = 13,
};

//--------------------------------------------------------------------------
inline void enable_button(form_actions_t &fa, int fid, bool enabled)
{
  fa.enable_field(fid, enabled);
}

//--------------------------------------------------------------------------
// Update control window buttons state
static void update_buttons(form_actions_t &fa)
{
  bool visible = editor_tform != NULL;
  enable_button(fa, 10, !dock && visible);
  enable_button(fa, 11, dock && visible);
  enable_button(fa, 12, !visible);
  enable_button(fa, 13, visible);
}

//--------------------------------------------------------------------------
// this callback is called when the user clicks on a button
static int idaapi btn_cb(TView *[], int)
{
  msg("button has been pressed -> ");
  return 0;
}

//--------------------------------------------------------------------------
// this callback is called when something happens in our non-modal editor form
static int idaapi editor_modcb(int fid, form_actions_t &fa)
{
  switch ( fid )
  {
    case CB_INIT:     // Initialization
      msg("init editor form\n");
      break;
    case CB_CLOSE:    // Closing the form
      msg("closing editor form\n");
      // mark the form as closed
      editor_tform = NULL;
      // If control form exists then update buttons
      if ( control_fa != NULL )
        update_buttons(*control_fa);
      break;
    case TEXT_CHANGED:     // Text changed
      {
        textctrl_info_t ti;
        fa.get_text_value(1, &ti);
        txts[curidx] = ti.text;
      }
      msg("text has been changed\n");
      break;
    case ITEM_SELECTED:    // list item selected
      {
        intvec_t sel;
        if ( fa.get_chooser_value(2, &sel) )
        {
          curidx = sel[0] - 1;
          textctrl_info_t ti;
          ti.cb = sizeof(textctrl_info_t);
          ti.text = txts[curidx];
          fa.set_text_value(1, &ti);
        }
      }
      msg("selection has been changed\n");
      break;
    default:
      msg("unknown id %d\n", fid);
      break;
  }
  return 1;
}
//---------------------------------------------------------------------------
// chooser: return the text to display at line 'n' (0 returns the column header)
static void idaapi getl(void *, uint32 n, char * const *arrptr)
{
  qstrncpy(arrptr[0], n == 0 ? "Name" : names[n-1], MAXSTR);
}

//---------------------------------------------------------------------------
// chooser: return the number of lines in the list
static uint32 idaapi sizer(void *)
{
  return qnumber(names);
}

//---------------------------------------------------------------------------
// create and open the editor form
static void open_editor_form(int options = 0)
{
  static const char formdef[] =
    "BUTTON NO NONE\n"        // we do not want the standard buttons on the form
    "BUTTON YES NONE\n"
    "BUTTON CANCEL NONE\n"
    "Editor form\n"           // the form title. it is also used to refer to the form later
    "\n"
    "%/"                      // placeholder for the 'editor_modcb' callback
    "\n"
    "<List:E2:30:30:1::><|><Text:t1:30:40:::>\n" // text edit control and chooser control separated by splitter
    "\n";
  // structure for text edit control
  textctrl_info_t ti;
  ti.cb = sizeof(textctrl_info_t);
  ti.text = txts[0];
  // structure for chooser list view
  chooser_info_t chi = { 0 };
  chi.cb = sizeof(chooser_info_t);
  chi.columns = 1;
  chi.getl   = getl;
  chi.sizer  = sizer;
  static const int widths[] = { 12 };
  chi.widths = widths;
  // selection for chooser list view
  intvec_t selected;
  editor_tform = OpenForm_c(formdef,
                            FORM_QWIDGET | options,
                            editor_modcb,
                            &chi,
                            &selected,
                            &ti);
}


//---------------------------------------------------------------------------
static void close_editor_form()
{
  msg("closing editor form\n");
  close_tform(editor_tform, FORM_CLOSE_LATER);
  editor_tform = NULL;
}
//--------------------------------------------------------------------------
inline void dock_form(bool _dock)
{
  set_dock_pos("Editor form",
               NULL,
               _dock ? DP_INSIDE : DP_FLOATING);
}

//--------------------------------------------------------------------------
// this callback is called when something happens in our non-modal control form
static int idaapi control_modcb(int fid, form_actions_t &fa)
{
  switch ( fid )
  {
    case CB_INIT:   // Initialization
      msg("init control form\n");
      dock = false;
      control_fa = &fa;   // remember the 'fa' for the future
      update_buttons(fa);
      break;
    case CB_CLOSE:  // Closing
      msg("closing control form\n");
      control_fa = NULL;
      return 1;
    case BTN_DOCK:
      msg("dock editor form\n");
      dock = true;
      dock_form(dock);
      break;
    case BTN_UNDOCK:
      msg("undock editor form\n");
      dock = false;
      dock_form(dock);
      break;
    case BTN_OPEN:
      msg("open editor form\n");
      open_editor_form(FORM_TAB|FORM_RESTORE);
      dock_form(dock);
      break;
    case BTN_CLOSE:
      close_editor_form();
      break;
    default:
      break;
  }
  update_buttons(fa);
  return 1;
}

//--------------------------------------------------------------------------
// the main function of the plugin
static void idaapi run(int)
{
  // first open the editor form
  open_editor_form(FORM_RESTORE);

  static const char control_form[] =
    "BUTTON NO NONE\n"          // do not display standard buttons at the bottom
    "BUTTON YES NONE\n"
    "BUTTON CANCEL NONE\n"
    "Control form\n"            // the title. it is used to refer to the form later
    "%/"                        // placeholder for control_modcb
    "<Dock:B10:30:::><Undock:B11:30:::><Show:B12:30:::><Hide:B13:30:::>\n"; // Create control buttons

  OpenForm_c(control_form,
                             FORM_QWIDGET | FORM_RESTORE | FORM_MENU,
                             control_modcb,
                             btn_cb, btn_cb, btn_cb, btn_cb);
  set_dock_pos("Control form", NULL, DP_FLOATING, 0, 0, 300, 100);
}

//--------------------------------------------------------------------------
// initialize the plugin
static int idaapi init(void)
{
  // we always agree to work.
  // we must return PLUGIN_KEEP because we will install callbacks.
  // if we return PLUGIN_OK, the kernel may unload us at any time and this will
  // lead to crashes.
  return PLUGIN_KEEP;
}

//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  0,
  init,                 // initialize
  NULL,                 // terminate. this pointer may be NULL.
  run,                  // invoke plugin
  NULL,                 // long comment about the plugin
  NULL,                 // multiline help about the plugin
  "Open non-modal form sample",// the preferred short name of the plugin
  NULL                  // the preferred hotkey to run the plugin
};
