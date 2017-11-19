/* Custom viewer sample plugin.
 * Copyright (c) 2007 by Ilfak Guilfanov, ig@hexblog.com
 * Feel free to do whatever you want with this code.
 *
 * This sample plugin demonstates how to create and manipulate a simple
 * custom viewer in IDA v5.1
 *
 * Custom viewers allow you to create a view which displays colored lines.
 * These colored lines are dynamically created by callback functions.
 *
 * Custom viewers are used in IDA itself to display
 * the disassembly listng, structure, and enumeration windows.
 *
 * This sample plugin just displays several sample lines on the screen.
 * It displays a hint with the current line number.
 * The right-click menu contains one sample command.
 * It reacts to one hotkey.
 *
 * This plugin uses the simpleline_place_t class for the locations.
 * Custom viewers can use any decendant of the place_t class.
 * The place_t is responsible for supplying data to the viewer.
 */

//---------------------------------------------------------------------------
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

#define ACTION_NAME "custview:SampleMenuItem"

static struct
{
  const char *text;
  bgcolor_t color;
} const sample_text[] =
{
  { "This is a sample text",                                         0xFFFFFF },
  { "It will be displayed in the custom view",                       0xFFC0C0 },
  { COLSTR("This line will be colored as erroneous", SCOLOR_ERROR),  0xC0FFC0 },
  { COLSTR("Every", SCOLOR_AUTOCMT) " "
    COLSTR("word", SCOLOR_DNAME) " "
    COLSTR("can", SCOLOR_IMPNAME) " "
    COLSTR("be", SCOLOR_NUMBER) " "
    COLSTR("colored!", SCOLOR_EXTRA),                                0xC0C0FF },
  { "  No limit on the number of lines.",                            0xC0FFFF },
};

// Structure to keep all information about the our sample view
struct sample_info_t
{
  TForm *form;
  TCustomControl *cv;
  strvec_t sv;
  sample_info_t(TForm *f) : form(f), cv(NULL) {}
};

static const sample_info_t *last_si = NULL;

//---------------------------------------------------------------------------
// get the word under the (keyboard or mouse) cursor
static bool get_current_word(TCustomControl *v, bool mouse, qstring &word)
{
  // query the cursor position
  int x, y;
  if ( get_custom_viewer_place(v, mouse, &x, &y) == NULL )
    return false;

  // query the line at the cursor
  char buf[MAXSTR];
  const char *line = get_custom_viewer_curline(v, mouse);
  tag_remove(line, buf, sizeof(buf));
  if ( x >= (int)strlen(buf) )
    return false;

  // find the beginning of the word
  char *ptr = buf + x;
  while ( ptr > buf && !qisspace(ptr[-1]) )
    ptr--;

  // find the end of the word
  char *begin = ptr;
  ptr = buf + x;
  while ( !qisspace(*ptr) && *ptr != '\0' )
    ptr++;

  word = qstring(begin, ptr-begin);
  return true;
}

//---------------------------------------------------------------------------
// Keyboard callback
static bool idaapi ct_keyboard(TCustomControl * /*v*/, int key, int shift, void *ud)
{
  if ( shift == 0 )
  {
    sample_info_t *si = (sample_info_t *)ud;
    switch ( key )
    {
      case 'N':
        warning("The hotkey 'N' has been pressed");
        return true;
      case IK_ESCAPE:
        close_tform(si->form, FORM_SAVE | FORM_CLOSE_LATER);
        return true;
    }
  }
  return false;
}

//---------------------------------------------------------------------------
// This callback will be called each time the keyboard cursor position
// is changed
static void idaapi ct_curpos(TCustomControl *v, void *)
{
  qstring word;
  if ( get_current_word(v, false, word) )
    msg("Current word is: %s\n", word.c_str());
}

//--------------------------------------------------------------------------
int idaapi ui_callback(void *ud, int code, va_list va)
{
  sample_info_t *si = (sample_info_t *)ud;
  switch ( code )
  {
    // how to implement a simple hint callback
    case ui_get_custom_viewer_hint:
      {
        TCustomControl *viewer = va_arg(va, TCustomControl *);
        place_t *place         = va_arg(va, place_t *);
        int *important_lines   = va_arg(va, int *);
        qstring &hint          = *va_arg(va, qstring *);
        if ( si->cv == viewer ) // our viewer
        {
          if ( place == NULL )
            return 0;
          simpleline_place_t *spl = (simpleline_place_t *)place;
          hint.sprnt("Hint for line %ld", spl->n);
          *important_lines = 1;
          return 1;
        }
        break;
      }
    case ui_tform_invisible:
      {
        TForm *f = va_arg(va, TForm *);
        if ( f == si->form )
        {
          delete si;
          unhook_from_notification_point(HT_UI, ui_callback, NULL);
        }
      }
      break;
    case ui_populating_tform_popup:
      {
        TForm *f = va_arg(va, TForm *);
        if ( f == (Forms::TForm*) si->cv )
        {
          TPopupMenu *p = va_arg(va, TPopupMenu *);
          // Create right-click menu on the fly
          attach_action_to_popup(f, p, ACTION_NAME);
        }
      }
      break;
  }
  return 0;
}

//-------------------------------------------------------------------------
struct sample_action_t : public action_handler_t
{
  virtual int idaapi activate(action_activation_ctx_t *)
  {
    qstring word;
    if ( !get_current_word(last_si->cv, false, word) )
      return 0;

    info("The current word is: %s", word.c_str());
    return 1;
  }

  virtual action_state_t idaapi update(action_update_ctx_t *)
  {
    return AST_ENABLE_ALWAYS;
  }
};
static sample_action_t sample_ah;
static const action_desc_t sample_action = ACTION_DESC_LITERAL(
        ACTION_NAME,
        "Sample menu item",
        &sample_ah,
        "N",
        NULL,
        -1);

//---------------------------------------------------------------------------
// Create a custom view window
void idaapi run(int)
{
  HWND hwnd = NULL;
  TForm *form = create_tform("Sample custom view", &hwnd);
  if ( hwnd == NULL )
  {
    warning("Could not create custom view window\n"
            "perhaps it is open?\n"
            "Switching to it.");
    form = find_tform("Sample custom view");
    if ( form != NULL )
      switchto_tform(form, true);
    return;
  }
  // allocate block to hold info about our sample view
  sample_info_t *si = new sample_info_t(form);
  last_si = si;
  // prepare the data to display. we could prepare it on the fly too.
  // but for that we have to use our own custom place_t class decendant.
  for ( int i=0; i < qnumber(sample_text); i++ )
  {
    si->sv.push_back(simpleline_t("")); // add empty line
    si->sv.push_back(simpleline_t(sample_text[i].text));
    si->sv.back().bgcolor = sample_text[i].color;
  }
  // create two place_t objects: for the minimal and maximal locations
  simpleline_place_t s1;
  simpleline_place_t s2(si->sv.size()-1);
  // create a custom viewer
  si->cv = create_custom_viewer("", (TWinControl *)form, &s1, &s2, &s1, 0, &si->sv);
  // set the handlers so we can communicate with it
  set_custom_viewer_handlers(si->cv, ct_keyboard, NULL, NULL, NULL, ct_curpos, NULL, si);
  // also set the ui event callback
  hook_to_notification_point(HT_UI, ui_callback, si);
  // finally display the form on the screen
  open_tform(form, FORM_TAB|FORM_MENU|FORM_RESTORE|FORM_QWIDGET);
  //lint -esym(429,si) not freed. will be freed upon window destruction

  // Register the action. This one will be attached
  // live, to the popup menu.
  register_action(sample_action);
}

//--------------------------------------------------------------------------
int idaapi init(void)
{
  return PLUGIN_KEEP;
}

//--------------------------------------------------------------------------
void idaapi term(void)
{
}

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

  term,                 // terminate. this pointer may be NULL.

  run,                  // invoke plugin

  "",                   // long comment about the plugin
                        // it could appear in the status line
                        // or as a hint

  "",                    // multiline help about the plugin

  "Sample custview",    // the preferred short name of the plugin
  ""                    // the preferred hotkey to run the plugin
};
