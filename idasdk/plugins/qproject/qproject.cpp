/*
 *  This is a sample plugin module. It demonstrates how to fully use
 *  the Qt environment in IDA.
 *
 */

#include <QtGui>
#include <QtWidgets>

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

// include your own widget here
#include "graphwidget.h"

//--------------------------------------------------------------------------
static ssize_t idaapi ui_callback(void *user_data, int notification_code, va_list va)
{
  if ( notification_code == ui_widget_visible )
  {
    TWidget *widget = va_arg(va, TWidget *);
    if ( widget == user_data )
    {
      // widget is created, create controls

      QWidget *w = (QWidget *) widget;

      QHBoxLayout *mainLayout = new QHBoxLayout();
      mainLayout->setMargin(0);

      GraphWidget *userWidget = new GraphWidget();

      mainLayout->addWidget(userWidget);

      w->setLayout(mainLayout);
    }
  }
  if ( notification_code == ui_widget_invisible )
  {
    TWidget *widget = va_arg(va, TWidget *);
    if ( widget == user_data )
    {
      // widget is closed, destroy objects (if required)
    }
  }
  return 0;
}

//--------------------------------------------------------------------------
int idaapi init(void)
{
  // the plugin works only with idaq
  return is_idaq() ? PLUGIN_OK : PLUGIN_SKIP;
}

//--------------------------------------------------------------------------
void idaapi term(void)
{
  unhook_from_notification_point(HT_UI, ui_callback);
}

//--------------------------------------------------------------------------
bool idaapi run(size_t)
{
  TWidget *widget = find_widget("Sample Qt Project");
  if ( widget == NULL )
  {
    widget = create_empty_widget("Sample Qt Project");
    hook_to_notification_point(HT_UI, ui_callback, widget);
    display_widget(widget, WOPN_TAB|WOPN_MENU|WOPN_RESTORE);
  }
  else
  {
    close_widget(widget, WCLS_SAVE);
  }
  return true;
}

//--------------------------------------------------------------------------
char comment[] = "This is a sample Qt Project plugin.";

char help[] =
    "A sample plugin module\n"
    "\n"
    "This module shows you how to use fully the Qt environment in IDA.";


//--------------------------------------------------------------------------
// This is the preferred name of the plugin module in the menu system
// The preferred name may be overriden in plugins.cfg file

char wanted_name[] = "Qt Project Sample";


// This is the preferred hotkey for the plugin module
// The preferred hotkey may be overriden in plugins.cfg file
// Note: IDA won't tell you if the hotkey is not correct
//       It will just disable the hotkey.

char wanted_hotkey[] = "";


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

  comment,              // long comment about the plugin
  // it could appear in the status line
  // or as a hint

  help,                 // multiline help about the plugin

  wanted_name,          // the preferred short name of the plugin
  wanted_hotkey         // the preferred hotkey to run the plugin
};
