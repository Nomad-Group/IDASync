//---------------------------------------------------------------------------
// Hex view sample plugin

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

//---------------------------------------------------------------------------
// hex data
class hex_data_t
{
  friend class hex_place_t;

  FILE *f;
  uint64 sz;
  uint align;

public:

  hex_data_t() : f(NULL), sz(10000), align(16) {}
  ~hex_data_t() { close(); }

  bool open(const char *fname)
  {
    close();
    f = qfopen(fname, "rb");
    if ( f == NULL )
      return false;
    // 64 bit functions could be used instead
    qfseek(f, 0, SEEK_END);
    sz = qftell(f);
    return true;
  }

  //lint -sem(hex_data_t::close,cleanup)
  void close()
  {
    if ( f != NULL )
    {
      qfclose(f);
      f = NULL;
      sz = 0;
    }
  }

  void detach()
  {
    f = NULL;
    sz = 0;
  }

  bool read(uint64 pos, void *buf, size_t bufsize)
  {
    // 64 bit functions could be used instead
    if ( qfseek(f, pos, SEEK_SET) != 0 )
      return false;
    return qfread(f, buf, bufsize) == bufsize;
  }

  uint64 size() const
  {
    return sz;
  }

  int alignment() const
  {
    return align;
  }

  uval_t pos_to_line(uint64 pos) const
  {
    return pos / align;
  }

  uval_t maxline() const
  {
    return pos_to_line(sz - 1);
  }
};

//---------------------------------------------------------------------------
// hex place
define_place_exported_functions(hex_place_t)
class hex_place_t : public place_t
{
public:
  hex_data_t *d;
  uval_t n;
  hex_place_t() : d(NULL), n(0) { lnnum = 0; }
  hex_place_t(hex_data_t *_d, uint64 pos = 0) : d(_d)
  { n = d->pos_to_line(pos); lnnum = 0; }
  define_place_virtual_functions(hex_place_t)
};
#include "hexplace.cpp"

//---------------------------------------------------------------------------
// Structure to keep all information about the our hex view
struct hex_info_t
{
  TForm *form;
  TCustomControl *cv;
  TCustomControl *hexview;
  hex_data_t data;
  hex_info_t(TForm *f, const hex_data_t & hd)
    : form(f), cv(NULL), hexview(NULL), data(hd) {}
};


//--------------------------------------------------------------------------
int idaapi ui_callback(void *ud, int code, va_list va)
{
  hex_info_t *si = (hex_info_t *)ud;
  switch ( code )
  {
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
  }
  return 0;
}

//---------------------------------------------------------------------------
// Create a custom view window
void idaapi run(int)
{
  static const char formtitle[] = "Sample hexview";
  TForm *form = find_tform(formtitle);
  if ( form != NULL )
  {
    warning("Hexview already open. Switching to it.");
    switchto_tform(form, true);
    return;
  }

  // ask the user to select a file
  char *filename = askfile_c(0, NULL, "Select a file to display...");
  if ( filename == NULL || filename[0] == 0 )
    return;
  // open the file
  hex_data_t hdata;
  if ( !hdata.open(filename) )
    return;

  // create the new file
  form = create_tform(formtitle, NULL);

  // allocate block to hold info about our view
  hex_info_t *si = new hex_info_t(form, hdata);
  hdata.detach();

  // create two place_t objects: for the minimal and maximal locations
  hex_place_t s1(&si->data);
  hex_place_t s2(&si->data, si->data.size() - 1);
  // create a custom viewer
  si->cv = create_custom_viewer("", NULL, &s1, &s2, &s1, 0, &si->data);
  // create a code viewer container for the custom view
  si->hexview = create_code_viewer(form, si->cv);
  // set the radix and alignment for the offsets
  set_code_viewer_lines_radix(si->hexview, 16);
  set_code_viewer_lines_alignment(si->hexview, si->data.size() > 0xFFFFFFFF ? 16 : 8);
  // also set the ui event callback
  hook_to_notification_point(HT_UI, ui_callback, si);
  // finally display the form on the screen
  open_tform(form, FORM_TAB|FORM_MENU|FORM_RESTORE|FORM_QWIDGET);
  //lint -esym(429,si) not freed. will be freed upon window destruction
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

  "Sample hexview",     // the preferred short name of the plugin
  ""                    // the preferred hotkey to run the plugin
};
