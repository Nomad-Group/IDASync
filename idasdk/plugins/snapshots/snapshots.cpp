/*
* This is a sample plugin to demonstrate the snapshot management API
*/

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <algorithm>

//--------------------------------------------------------------------------
#define DECLARE_THIS snapman_t *_this = (snapman_t *)obj //lint -e773
class snapman_t
{
  struct snapdesc_t
  {
    snapshot_t *ss;
    qstring title;
    qstring date;
  };
  typedef qvector<snapdesc_t *> sdlist_t;
  snapshot_t root;
  sdlist_t sdlist;
  int source_snapidx;

  static const int widths[2];
  static const char *const header[2];

  void sdlist_clear()
  {
    for (sdlist_t::iterator p=sdlist.begin();p!=sdlist.end();++p)
      delete *p;
    sdlist.clear();
    source_snapidx = 0;
  }

  static uint32 idaapi sizer(void *obj)
  {
    DECLARE_THIS;
    return _this->sdlist.size();
  }

  static void idaapi edit(void *obj, uint32 n)
  {
    DECLARE_THIS;
    snapdesc_t *sd = _this->get_item(n);
    if ( sd == NULL )
      return;

    const char *answer = askstr(0, sd->ss->desc, "Enter new snapshot description");
    if ( answer == NULL )
      return;

    // Update the description
    qstrncpy(sd->ss->desc, answer, sizeof(sd->ss->desc));
    update_snapshot_attributes(sd->ss->filename, &_this->root, sd->ss, SSUF_DESC);
  }

  static void idaapi ins(void *obj)
  {
    const char *answer = askstr(0, "snapshot description", "Enter snapshot description");
    if ( answer == NULL )
      return;

    qstring err_msg;
    snapshot_t new_attr;
    qstrncpy(new_attr.desc, answer, sizeof(new_attr.desc));
    if ( take_database_snapshot(&new_attr, &err_msg) )
    {
      msg("Created new snapshot: %s\n", new_attr.filename);
      DECLARE_THIS;
      _this->init();
    }
    else
    {
      warning("Failed to create a snapshot, error: %s\n", err_msg.c_str());
    }
  }

  static uint32 idaapi del(void *obj, uint32 n)
  {
    DECLARE_THIS;
    snapdesc_t *sd = _this->get_item(n);
    if ( sd == NULL )
      return n;

    // Simply delete the file
    qunlink(sd->ss->filename);

    // Rebuild the list
    _this->init();

    return 1;
  }

  static void idaapi desc(void *obj, uint32 n, char *const *arrptr)
  {
    // generate the column headers
    if ( n == 0 )
    {
      qstrncpy(arrptr[0], header[0], MAXSTR);
      qstrncpy(arrptr[1], header[1], MAXSTR);
      return;
    }

    DECLARE_THIS;
    snapdesc_t *sd = _this->get_item(n);
    QASSERT(561, sd != NULL);

    qstrncpy(arrptr[0], sd->date.c_str(), MAXSTR);
    qstrncpy(arrptr[1], sd->title.c_str(), MAXSTR);
  }

  static void idaapi done_restore(const char *err_msg, void *)
  {
    if ( err_msg != NULL )
      warning("ICON ERROR\nError restoring: %s", err_msg);
    else
      warning("Restored successfully!");
  }

  void build_tree_list(snapshot_t *n, int level = 0)
  {
    if ( n != &root )
    {
      // Insert new description record
      snapdesc_t *sd = new snapdesc_t();
      sdlist.push_back(sd);

      // Compute title
      for (int i=0;i<level*3;i++)
        sd->title += "  ";

      // Remember selected node
      if ( n->id == root.id )
      {
        source_snapidx = sdlist.size();
        sd->title += "->";
      }

      sd->title += n->desc;

      // Compute date
      char ss_date[MAXSTR];
      qstrftime64(ss_date, sizeof(ss_date), "%Y-%m-%d %H:%M:%S", n->id);
      sd->date = ss_date;
      // Store ss
      sd->ss = n;
    }
    for ( snapshots_t::iterator it=n->children.begin(); it != n->children.end(); ++it )
      build_tree_list(*it, level+1);
  }

  snapdesc_t *get_item(uint32 n)
  {
    return n > sdlist.size() ? NULL : sdlist[n-1];
  }

public:
  bool init()
  {
    sdlist_clear();
    root.clear();
    if ( !build_snapshot_tree(&root) )
    {
      warning("Snapshot tree cannot be built.\nNo snapshots exist?");
      return false;
    }

    // Convert the tree to a list
    build_tree_list(&root);
    if ( sdlist.empty() )
    {
      warning("Snapshot tree empty!");
      return false;
    }
    return true;
  }

  ~snapman_t()
  {
    sdlist_clear();
  }

  void show()
  {
    // now open the window
    int r = choose2(CH_MODAL,// modal window
      -1, -1, -1, -1,       // position is determined by the OS
      this,                 // pass the snapman to the chooser
      qnumber(header),      // number of columns
      widths,               // widths of columns
      sizer,                // function that returns number of lines
      desc,                 // function that generates a line
      "Simple snapshot manager", // window title
      -1,                   // use the default icon for the window
      source_snapidx,       // position the cursor on the source snapshot
      del,                  // "kill" callback
      ins,                  // "new" callback
      NULL,                 // "update" callback
      edit,                 // "edit" callback
      NULL,                 // function to call when the user pressed Enter
      NULL,                 // function to call when the window is closed
      NULL,                 // use default popup menu items
      NULL);                // use the same icon for all lines
    if ( r > 0 )
    {
      snapdesc_t *sd = get_item(r);
      if ( sd != NULL && sd->ss != NULL )
        restore_database_snapshot(sd->ss, done_restore, NULL);
    }
  }
};
#undef DECLARE_THIS

// column widths
const int snapman_t::widths[2] = { 12, 70 };

const char *const snapman_t::header[2] =
{
  "Date",
  "Description",
};


//--------------------------------------------------------------------------
//
//      Initialize.
//
int idaapi init(void)
{
  // Display help
  msg(
    "Simple snapshot manager loaded!\n"
    "Press Shift+F8 to toggle the plugin\n"
    "Inside the snapshots window, press:\n"
    " - Insert: to take a snapshot\n"
    " - Delete: to delete\n"
    " - Edit: to edit the snapshot description\n"
    "\n"
    "Click on:\n"
    " - Ok: to restore the selected snapshot\n"
    " - Cancel: close without doing anything\n");

  // Plugin must remain loaded if it plans to restore a database
  // The plugin flags must include PLUGIN_FIX as well
  return PLUGIN_KEEP;
}

//--------------------------------------------------------------------------
//      Terminate.
//      Usually this callback is empty.
void idaapi term(void)
{
//  warning("term choose2");
}

//--------------------------------------------------------------------------
//
//      The plugin method
//
//      This is the main function of plugin.
//
void idaapi run(int /*arg*/)
{
  snapman_t sm;
  if ( !sm.init() )
    return;

  sm.show();
}

//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  // plugin flags
  PLUGIN_FIX,
  // initialize
  init,
  // terminate. this pointer may be NULL.
  term,
  // invoke plugin
  run,
  // long comment about the plugin
  // it could appear in the status line
  // or as a hint
  "This is a sample plugin. It displays the list of snapshots",
  // multiline help about the plugin
  "A snapshot manager sample plugin\n"
  "\n"
  "This plugin allows you to list and restore snapshots.\n",
  // the preferred short name of the plugin
  "Simple snapshot manager",
  // the preferred hotkey to run the plugin
  "Shift-F8"
};
