/*
* This is a sample plugin to demonstrate the UI requests and the process_ui_action()
* One process_ui_action() can be processed during an UI request.
* The UI request is a nice example to show how to schedule UI actions for sequential execution
*/

#include <ida.hpp>
#include <idp.hpp>
#include <graph.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

static int req_id = 0;

//--------------------------------------------------------------------------
int idaapi init(void)
{
  return PLUGIN_KEEP;
}

//--------------------------------------------------------------------------
void idaapi term(void)
{
  if ( req_id != 0 && cancel_exec_request(req_id) )
    msg("Cancelled unexecuted ui_request\n");
}

//--------------------------------------------------------------------------
void idaapi run(int /*arg*/)
{
  class msg_req_t: public ui_request_t
  {
    const char *_msg;
  public:
    msg_req_t(const char *mesg): _msg(qstrdup(mesg))
    {
    }
    ~msg_req_t()
    {
      qfree((void *)_msg);
    }
    virtual bool idaapi run()
    {
      msg("%s", _msg);
      return false;
    }
  };

  class stepover_req_t: public ui_request_t
  {
    int count;
  public:
    stepover_req_t(int cnt): count(cnt)
    {
    }
    virtual bool idaapi run()
    {
      process_ui_action("ThreadStepOver");
      return --count != 0;
    }
  };

  req_id = execute_ui_requests(
    new msg_req_t("will "),
    new msg_req_t("step "),
    new msg_req_t("over 5 times\n"),
    new stepover_req_t(5),
    NULL);
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

  // long comment about the plugin
  // it could appear in the status line
  // or as a hint
  "This is a sample ui_requests plugin.",

  // multiline help about the plugin
  "A sample ui_requests and process_ui_commands plugin",

  // the preferred short name of the plugin
  "UI requests demo",
  "Shift-F8"                   // the preferred hotkey to run the plugin
};
