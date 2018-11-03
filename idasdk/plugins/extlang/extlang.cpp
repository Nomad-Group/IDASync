/*
        This is a sample plugin. It illustrates

          how to register a thid party language interpreter

*/

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <expr.hpp>
#include <kernwin.hpp>

//--------------------------------------------------------------------------
static bool idaapi compile_expr(// Compile an expression
        const char *name,       // in: name of the function which will
                                //     hold the compiled expression
        ea_t current_ea,        // in: current address. if unknown then BADADDR
        const char *expr,       // in: expression to compile
        qstring *errbuf)        // out: error message if compilation fails
{                               // Returns: success
  qnotused(name);
  qnotused(current_ea);
  qnotused(expr);
  // our toy interpreter doesn't support separate compilation/evaluation
  // some entry fields in ida won't be useable (bpt conditions, for example)
  if ( errbuf != NULL )
    *errbuf = "compilation error";
  return false;
}

//--------------------------------------------------------------------------
static bool idaapi call_func(   // Evaluate a previously compiled expression
        idc_value_t *result,    // out: function result
        const char *name,       // in: function to call
        const idc_value_t args[], // in: input arguments
        size_t nargs,           // in: number of input arguments
        qstring *errbuf)        // out: error message if compilation fails
{                               // Returns: success
  qnotused(name);
  qnotused(nargs);
  qnotused(args);
  qnotused(result);
  if ( errbuf != NULL )
    *errbuf = "evaluation error";
  return false;
}

//--------------------------------------------------------------------------
bool idaapi eval_expr(           // Compile and evaluate expression
        idc_value_t *rv,        // out: expression value
        ea_t current_ea,        // in: current address. if unknown then BADADDR
        const char *expr,       // in: expression to evaluation
        qstring *errbuf)        // out: error message if compilation fails
{                               // Returns: success
  qnotused(current_ea);
  // we know to parse and decimal and hexadecimal numbers
  int radix = 10;
  const char *ptr = skip_spaces(expr);
  bool neg = false;
  if ( *ptr == '-' )
  {
    neg = true;
    ptr = skip_spaces(ptr+1);
  }
  if ( *ptr == '0' && *(ptr+1) == 'x' )
  {
    radix = 16;
    ptr += 2;
  }
  sval_t value = 0;
  while ( radix == 10 ? qisdigit(*ptr) : qisxdigit(*ptr) )
  {
    int d = *ptr <= '9' ? *ptr-'0' : qtolower(*ptr)-'a'+10;
    value *= radix;
    value += d;
    ptr++;
  }
  if ( neg )
    value = -value;
  ptr = skip_spaces(ptr);
  if ( *ptr != '\0' )
  {
    msg("EVAL FAILED: %s\n", expr);
    if ( errbuf != NULL )
      *errbuf = "syntax error";
    return false;
  }

  // we have the result, store it in the return value
  rv->clear();
  rv->num = value;
  msg("EVAL %" FMT_EA "d: %s\n", value, expr);
  return true;
}

//--------------------------------------------------------------------------
static extlang_t el =
{
  sizeof(extlang_t),            // Size of this structure
  0,                            // Language features, currently 0
  0,                            // refcnt
  "extlang sample",             // Language name
  NULL,                         // fileext
  NULL,                         // syntax highlighter
  compile_expr,
  NULL,                         // compile_file
  call_func,
  eval_expr,
  NULL,                         // create_object
  NULL,                         // get_attr
  NULL,                         // set_attr
  NULL,                         // call_method
  NULL,                         // eval_snippet
  NULL,                         // load_procmod
  NULL,                         // unload_procmod
};

//--------------------------------------------------------------------------
int idaapi init(void)
{
  if ( install_extlang(&el) )
  {
    return PLUGIN_KEEP;
  }
  else
  {
    msg("extlang: install_extlang() failed\n");
    return PLUGIN_SKIP;
  }
}

//--------------------------------------------------------------------------
void idaapi term(void)
{
  remove_extlang(&el);
}

//--------------------------------------------------------------------------
bool idaapi run(size_t) // won't be called
{
  return false;
}

//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_FIX|PLUGIN_HIDE,// plugin flags:
                        //   - we want to be in the memory from the start
                        //   - plugin is hidden
  init,                 // initialize
  term,                 // terminate. this pointer may be NULL.
  run,                  // invoke plugin
  NULL,                 // long comment about the plugin
  NULL,                 // multiline help about the plugin
  "Sample third party language", // the preferred short name of the plugin
  NULL                  // the preferred hotkey to run the plugin
};
