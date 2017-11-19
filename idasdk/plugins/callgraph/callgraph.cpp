#include "callgraph.h"

//lint -e64 type mismatch
//--------------------------------------------------------------------------
static funcs_walk_options_t fg_opts =
{
  FWO_VERSION,                 // version
  FWO_CALLEE_RECURSE_UNLIM,    // flags
  2,                           // max callees recursion
  1,                           // max callers recursion
  255                          // max nodes per level
};

//--------------------------------------------------------------------------
// Checks if a function is visited already
// If it is visited then true is returned and nid contains the node ID
bool callgraph_t::visited(ea_t func_ea, int *nid)
{
  ea_int_map_t::const_iterator it = ea2node.find(func_ea);
  if ( it != ea2node.end() )
  {
    if ( nid != NULL )
      *nid = it->second;
    return true;
  }
  return false;
}

//--------------------------------------------------------------------------
void callgraph_t::add_fathers(
    func_t *func,
    ea_t func_start,
    int id,
    funcs_walk_options_t *opt,
    int level)
{
  qnotused(func);
  if ( level >= (opt->callers_recurse_limit+2) )
  {
    return;
  }

  //msg("Level %d, node 0x%08x\n", level, func_start);
  xrefblk_t xb_to;

  for ( bool xb_to_ok = xb_to.first_to(func_start, XREF_FAR);
    xb_to_ok && xb_to.iscode;
    xb_to_ok = xb_to.next_to() )
  {
    func_t *f_from = get_func(xb_to.from);
    if ( f_from == NULL )
      continue;

    int idto = add(f_from->startEA);
    //msg("Adding XREF to 1st node %d\n", idto);
    create_edge(idto, id);

    add_fathers(f_from, f_from->startEA, idto, opt, level+1);
  }
}

//--------------------------------------------------------------------------
int callgraph_t::walk_func(
    eavec_t *hide_nodes,
    func_t *func,
    funcs_walk_options_t *opt,
    int level)
{
  // add a node for this function
  ea_t func_start = func->startEA;

  int id = add(func_start);

  // Add the callers of the 1st function
  if ( level == 2 )
  {
    add_fathers(func, func_start, id, opt, 2);
  }

  int total = 0;
  func_item_iterator_t fii;

  for ( bool fi_ok=fii.set(func); fi_ok; fi_ok=fii.next_code() )
  {
    xrefblk_t xb;
    for ( bool xb_ok = xb.first_from(fii.current(), XREF_FAR);
      xb_ok && xb.iscode;
      xb_ok = xb.next_from() )
    {
      bool is_func_lib;
      ea_t ea;

      func_t *f = get_func(xb.to);
      if ( f == NULL )
      {
        ea = xb.to;
        is_func_lib = true;

        if ((opt->flags & FWO_SKIPLIB) != 0)
          continue;
      }
      else
      {
        ea = f->startEA;
        is_func_lib = false;
      }

      eavec_t::iterator hide_nodes_it;

      // Any node to hide?
      if ( !hide_nodes->empty() )
      {
        hide_nodes_it = std::find(hide_nodes->begin(), hide_nodes->end(), ea);
        if ( *hide_nodes_it == ea )
        {
          //msg("Hiding node 0x%08x\n", *hide_nodes_it);
          continue;
        }
      }

      int id2 = -1;
      if ( !visited(ea, &id2) )
      {
        if ( func_contains(func, xb.to) )
          continue;

        bool skip = false;

        if ( opt != NULL )
        {
          skip =
            // skip lib funcs?
            (((is_func_lib) && ((opt->flags & FWO_SKIPLIB) != 0))
            // max recursion is off, and limit is reached?
            || (  ((opt->flags & FWO_CALLEE_RECURSE_UNLIM) == 0)
            && (level > opt->callees_recurse_limit) ));
        }

        // More nodes in this level than the maximum specified?
        if ( total++ >= fg_opts.max_nodes )
        {
          id2 = add((ea_t)VERTEX_HIDDEN_NODES);
          create_edge(id, id2);
          break;
        }

        if ( skip )
          id2 = add(ea);
        else if ( !is_func_lib )
          id2 = walk_func(hide_nodes, f, opt, level+1);
        else if ( (is_func_lib && opt->flags & FWO_SKIPLIB) == 0 )
          id2 = add(ea);

        if ( id2 != -1 )
          create_edge(id, id2);
      }
      //msg("Adding edge between %d and %d\n", id, id2);
    }
  }
  return id;
}

//--------------------------------------------------------------------------
int callgraph_t::find_first(const char *text)
{
  if ( text == NULL || text[0] == '\0' )
    return -1;

  qstrncpy(cur_text, text, sizeof(cur_text));
  cur_node = 0;
  return find_next();
}

//--------------------------------------------------------------------------
int callgraph_t::find_next()
{
  for ( int i = cur_node; i < node_count; i++ )
  {
    const char *s = get_name(i);
    if ( stristr(s, cur_text) != NULL )
    {
      cur_node = i + 1;
      return i;
    }
  }
  // reset search
  cur_node = 0;
  // nothing is found
  return -1;
}

//--------------------------------------------------------------------------
void callgraph_t::create_edge(int id1, int id2)
{
  edges.push_back(edge_t(id1, id2));
}

//--------------------------------------------------------------------------
void callgraph_t::reset()
{
  node_count = 0;
  cur_node = 0;
  cur_text[0] = '\0';
  ea2node.clear();
  node2ea.clear();
  cached_funcs.clear();
  edges.clear();
}

//--------------------------------------------------------------------------
ea_t callgraph_t::get_addr(int nid)
{
  int_ea_map_t::const_iterator it = node2ea.find(nid);
  return it == node2ea.end() ? BADADDR : it->second;
}

//--------------------------------------------------------------------------
// Given an address, this function first returns ASCII string if found
// otherwise it returns a UNICODE string
// FIXME: not comprehensive, better follow the settings in strings options
size_t get_string(ea_t ea, qstring *out)
{
  char buf[MAXSTR];

  out->qclear();
  size_t len = get_max_ascii_length(ea, ASCSTR_C);
  if ( len > 4 )
  {
    if( get_ascii_contents2(ea, len, ASCSTR_C, buf, sizeof(buf)) )
    {
      *out = buf;
      return true;
    }
  }
  else
  {
    len = get_max_ascii_length(ea, ASCSTR_UNICODE);
    if ( len > 4 )
    {
      if( get_ascii_contents2(ea, len, ASCSTR_UNICODE, buf, sizeof(buf)) )
      {
        *out = buf;
        return true;
      }
    }
  }
  return out->size();
}

//--------------------------------------------------------------------------
bool get_strings(ea_t ea, qstring *out)
{
  qstring tmp;

  func_t *func = get_func(ea);
  func_item_iterator_t fii;
  for ( bool fi_ok=fii.set(func); fi_ok; fi_ok=fii.next_code() )
  {
    xrefblk_t xb;
    for ( bool xb_ok = xb.first_from(fii.current(), XREF_DATA);
      xb_ok;
      xb_ok = xb.next_from() )
      {
        if ( get_string(xb.to, &tmp) > 0 )
          *out += tmp + "\n";
      }
  }

  if ( out->size() > 1 )
    out->insert("\n\nStrings:\n");

  return !out->empty();
}

//--------------------------------------------------------------------------
callgraph_t::funcinfo_t *callgraph_t::get_info(int nid)
{
  funcinfo_t *ret = NULL;

  do
  {
    // returned cached name
    int_funcinfo_map_t::iterator it = cached_funcs.find(nid);

    if ( it != cached_funcs.end() )
    {
      ret = &it->second;
      break;
    }

    // node does not exist?
    int_ea_map_t::const_iterator it_ea = node2ea.find(nid);
    if ( it_ea == node2ea.end() )
      break;

    funcinfo_t fi;

    qstring buf;
    if ( get_true_name(&buf, it_ea->second) <= 0 )
    {
      /*
      ** NOTE: With patched databases it may fail for a reason unknown (ATM).
      ** To test it, open an Objective-C app and patch it with the following
      ** script: https://github.com/zynamics/objc-helper-plugin-ida
      */
      if ( (int32)it_ea->second == VERTEX_HIDDEN_NODES )
      {
        fi.name = "More nodes hidden...";
      }
      else
      {
        msg("%a: Invalid address\n", it_ea->second);
        fi.name = "?";
      }
    }
    else
    {
      qstring outbuf = buf;
      qstring demangled;
      if ( demangle_name2(&demangled, buf.begin(), MNG_SHORT_FORM) > 0 )
      {
        outbuf.append("\n");
        outbuf.append(demangled);
      }

      // Assign the name
      fi.name = outbuf;

      // Add the strings reference if set
      qstring strings;
      if ( (fg_opts.flags & FWO_SHOWSTRING) != 0 && get_strings(it_ea->second, &strings) )
        fi.strings = strings;
    }

    // XXX: FIXME: UGLY HACK
    // Use a special color for the selected node
    if ( nid == 0 )
    {
      fi.color = 0x44FF55;
    }
    else
    {
      // Is it an imported function?
      segment_t *seg = getseg(it_ea->second);
      if ( seg != NULL && seg->type == SEG_XTRN )
      {
          fi.color = 0xf000f0;
      }
      else
      {
          // XXX: FIXME Horrible...
          func_t *f = get_func(it_ea->second);
          if ( f != NULL
            && ((f->flags & FUNC_LIB) != 0 || buf[0] == '.') )
          {
            fi.color = 0xfff000;
          }
          else
          {
            fi.color = calc_bg_color(it_ea->second);
          }
      }
    }

    fi.ea = it_ea->second;

    it = cached_funcs.insert(cached_funcs.end(), std::make_pair(nid, fi));
    ret = &it->second;
  } while ( false );

  return ret;
}

//--------------------------------------------------------------------------
const char *callgraph_t::get_name(int nid)
{
  funcinfo_t *fi = get_info(nid);
  if ( fi == NULL )
    return "?";
  else
    return fi->name.c_str();
}

//--------------------------------------------------------------------------
int callgraph_t::add(ea_t func_ea)
{
  ea_int_map_t::const_iterator it = ea2node.find(func_ea);
  if ( it != ea2node.end() )
    return it->second;

  ea2node[func_ea]    = node_count;
  node2ea[node_count] = func_ea;
  return node_count++;
}

//--------------------------------------------------------------------------
callgraph_t::callgraph_t() : node_count(0), cur_node(0)
{
  cur_text[0] = '\0';
}

//--------------------------------------------------------------------------
void callgraph_t::clear_edges()
{
  edges.clear();
}

//--------------------------------------------------------------------------
//--------------------------------------------------------------------------
//--------------------------------------------------------------------------
graph_info_t::graphinfo_list_t graph_info_t::instances;

//--------------------------------------------------------------------------
graph_info_t::graph_info_t()
  : gv(NULL), form (NULL), func_ea(BADADDR), refresh_needed(true)
{
}

//--------------------------------------------------------------------------
bool graph_info_t::find(const ea_t ea, iterator *out)
{
  iterator end = instances.end();
  for ( iterator it = instances.begin(); it != end; ++it )
  {
    if ( (*it)->func_ea == ea )
    {
      if ( out != NULL )
        *out = it;
      return true;
    }
  }
  return false;
}

//--------------------------------------------------------------------------
graph_info_t *graph_info_t::find(const ea_t ea)
{
  iterator it;
  return find(ea, &it) ? *it : NULL;
}

//--------------------------------------------------------------------------
graph_info_t *graph_info_t::find(const char *_title)
{
  iterator it, end = instances.end();
  for ( it = instances.begin(); it != end; ++it )
  {
    graph_info_t *gi = *it;
    if ( strcmp(gi->title.c_str(), _title) == 0 )
      return gi;
  }
  return NULL;
}

//--------------------------------------------------------------------------
graph_info_t *graph_info_t::create(ea_t ea)
{
  graph_info_t *r = find(ea);

  // not there? create it
  if ( r == NULL )
  {
    // we need a function!
    func_t *pfn = get_func(ea);
    if ( pfn == NULL )
      return NULL;

    r = new graph_info_t();
    get_title(ea, &r->title);
    r->func_ea = pfn->startEA;
    instances.push_back(r);

    setup_hooks(r);
  }
  return r;
}

//--------------------------------------------------------------------------
// We hook to IDP event to receive processor module notifications
static int idaapi idp_callback(void *user_data, int notification_code, va_list va)
{
  switch (notification_code)
  {
    case processor_t::add_func:
    case processor_t::del_func:
    case processor_t::set_func_start:
    case processor_t::set_func_end:
    case processor_t::create_switch_xrefs:
    case processor_t::add_cref:
    case processor_t::del_cref:
    {
      // Check if the user changed any of the functions in the current graph
      graph_info_t *gi = (graph_info_t*)user_data;
      ea_t ea = va_arg(va, ea_t);
      ea_int_map_t::const_iterator it = gi->fg.ea2node.find(ea);

      if ( it != gi->fg.ea2node.end() )
      {
        // The center node has been changed, destroy the current callgraph
        if ( it->second == 0 )
          close_tform(gi->form, FORM_SAVE);
        else
          // A function shown in the callgraph has been changed, refresh
          // the callgraph
          gi->refresh();
      }

      break;
    }
  }

  return 0;
}

//--------------------------------------------------------------------------
void graph_info_t::setup_hooks(graph_info_t *r)
{
  // hook to processor module events
  hook_to_notification_point(HT_IDP, idp_callback, r);

  /*
  // hook events about user interface modifications
  hook_to_notification_point(HT_UI, ui_callback, r);
   * */
}

//--------------------------------------------------------------------------
void graph_info_t::remove_hooks(graph_info_t *gi)
{
  unhook_from_notification_point(HT_IDP, idp_callback, gi);
  /*
  unhook_from_notification_point(HT_UI, ui_callback, gi);
   * */
}

//--------------------------------------------------------------------------
void graph_info_t::destroy(graph_info_t *gi)
{
  iterator it;
  if ( !find(gi->func_ea, &it) )
    return;

  remove_hooks(gi);

  /** Temporary fix until the root of the bug is clear */
  //delete gi;
  instances.erase(it);
}

//--------------------------------------------------------------------------
// Get a new title for the form to be opened
bool graph_info_t::get_new_title(ea_t ea, qstring *out)
{
  int i;
  qstring tmp;

  // We should succeed in getting the name
  qstring func_name;
  if ( get_func_name2(&func_name, ea) <= 0 )
    return false;

  for ( i=1; i < 255; i++)
  {
    tmp.sprnt("Call graph of: %s (%d)", func_name.begin(), i);

    if ( find_tform(tmp.c_str()) == NULL)
    {
      *out = tmp; //->sprnt("Call graph %d of: %s", callgraph_num, func_name.begin());
      break;
    }
  }

  return true;
}

//--------------------------------------------------------------------------
bool graph_info_t::get_title(ea_t ea, qstring *out)
{
  // we should succeed in getting the name
  qstring func_name;
  if ( get_func_name2(&func_name, ea) <= 0 )
    return false;

  out->sprnt("Call graph of: %s", func_name.begin());
  return true;
}

//--------------------------------------------------------------------------
void graph_info_t::mark_for_refresh()
{
  refresh_needed = true;
}

//--------------------------------------------------------------------------
void graph_info_t::mark_as_refreshed()
{
  refresh_needed = false;
}

//--------------------------------------------------------------------------
void graph_info_t::refresh()
{
  mark_for_refresh();
  refresh_viewer(gv);
}

//--------------------------------------------------------------------------
//--------------------------------------------------------------------------
//--------------------------------------------------------------------------
//lint -esym(773,DECLARE_GI_VAR) not parenthesized
#define DECLARE_GI_VAR \
  graph_info_t *gi = (graph_info_t *) ud

#define DECLARE_GI_VARS \
  DECLARE_GI_VAR;       \
  callgraph_t *fg = &gi->fg

//--------------------------------------------------------------------------
void idaapi callgraph_t::jump_disasm(void *ud, int code, va_list va) const
{
  DECLARE_GI_VARS;
  qnotused(code);
  va_arg(va, graph_viewer_t *);
  selection_item_t *s = va_arg(va, selection_item_t *);
  if ( s != NULL && s->is_node )
    jumpto(fg->get_addr(s->node));
}

//--------------------------------------------------------------------------
void idaapi callgraph_t::user_refresh(
    void *ud,
    int code,
    va_list va,
    int current_node)
{
  DECLARE_GI_VARS;
  qnotused(code);
  qnotused(current_node);
  if ( !gi->is_refresh_needed() )
    return;

  gi->mark_as_refreshed();
  fg->reset();

  func_t *f = get_func(gi->func_ea);
  if ( f == NULL )
  {
    msg("%a: Invalid function\n", gi->func_ea);
    return;
  }

  fg->walk_func(&gi->hide_nodes, f, &fg_opts, 2);

  mutable_graph_t *mg = va_arg(va, mutable_graph_t *);

  // we have to resize
  mg->reset();
  mg->resize(fg->count());

  callgraph_t::edge_iterator it;
  callgraph_t::edge_iterator end = fg->end_edges();

  for ( it=fg->begin_edges(); it != end; ++it )
  {
    mg->add_edge(it->id1, it->id2, NULL);
  }

  fg->clear_edges();
}

//--------------------------------------------------------------------------
int idaapi callgraph_t::gr_callback(void *ud, int code, va_list va)
{
  bool result = false;

  switch ( code )
  {
    // a graph node has been double clicked
    // in:  graph_viewer_t *gv
    //      selection_item_t *current_item
    // out: 0-ok, 1-ignore click
    case grcode_dblclicked:
    {
      result = menu_center_cb(ud);
      break;
    }
    // refresh user-defined graph nodes and edges
    // in:  mutable_graph_t *g
    // out: success
    case grcode_user_refresh:
    {
      user_refresh(ud, code, va, -1);
      result = true;
      break;
    }

    // retrieve text for user-defined graph node
    // in:  mutable_graph_t *g
    //      int node
    //      const char **result
    //      bgcolor_t *bg_color (maybe NULL)
    // out: must return 0, result must be filled
    case grcode_user_text:
    {
      DECLARE_GI_VARS;

      va_arg(va, mutable_graph_t *);
      int node           = va_arg(va, int);
      const char **text  = va_arg(va, const char **);
      bgcolor_t *bgcolor = va_arg(va, bgcolor_t *);

      callgraph_t::funcinfo_t *fi = fg->get_info(node);
      result = fi != NULL;
      if ( result )
      {
        qstring hint;

        hint = fi->name + fi->strings;
        *text = hint.extract();
        //*text = fi->name.c_str();
        if ( bgcolor != NULL )
          *bgcolor = fi->color;
      }
      break;
    }

    // retrieve hint for the user-defined graph
    // in:  mutable_graph_t *g
    //      int mousenode
    //      int mouseedge_src
    //      int mouseedge_dst
    //      char **hint
    // 'hint' must be allocated by qalloc() or qstrdup()
    // out: 0-use default hint, 1-use proposed hint
    case grcode_user_hint:
    {
      DECLARE_GI_VARS;
      va_arg(va, mutable_graph_t *);

      int mousenode = va_argi(va, int);
      int to = va_argi(va, int);
      int from = va_argi(va, int);
      char **hint = va_arg(va, char **);

      result = true;

      ea_t addr;
      if ( mousenode != -1 && (addr = fg->get_addr(mousenode)) != BADADDR )
      {
        char *lines[1024];
        qstring all_lines;

        for ( int j=0; j < 16; j++ )
        {
          int nl = generate_disassembly(addr, lines, qnumber(lines), NULL, false);

          for ( int i = 0; i < nl; i++)
          {
            all_lines += lines[i],
              all_lines += "\n";
            qfree(lines[i]);
          }
          addr = get_item_end(addr);
        }

        *hint = all_lines.extract();
      }
      else if ( mousenode == -1 )
      {
        qstring line;

        if ( from != -1 && to != -1 )
        {
          funcinfo_t *fifrom = fg->get_info(from);
          funcinfo_t *fito = fg->get_info(to);

          // XXX: FIXME: Hack. It should be fixed hooking to del_func, etc...
          if ( fifrom == NULL || fito == NULL )
          {
            msg("Invalid function\n");
            result = false;
          }
          else
          {
            line.insert(fifrom->name.c_str());
            line.insert(" -> ");
            line.insert(fito->name.c_str());

            *hint = line.extract();
          }
        }
      }
      break;
    }
    // graph is being destroyed
    case grcode_destroyed:
    {
      DECLARE_GI_VAR;

      graph_info_t::destroy(gi);
      break;
    }
  }
  return (int)result;
}

//--------------------------------------------------------------------------
static const char *const NODE_NAME = "$ proximity browser";

static bool load_options()
{
  funcs_walk_options_t opt;
  netnode n(NODE_NAME);
  if ( !exist(n) )
    return false;

  n.supval(1, &opt, sizeof(opt));

  if ( opt.version != FWO_VERSION )
    return false;

  fg_opts = opt;
  return true;
}

//--------------------------------------------------------------------------
static int idaapi options_cb(int fid, form_actions_t &fa)
{
  ushort opt = 0;

  if ( fid == FIELD_ID_CHILDS || fid == -1 )
  {
    if ( !fa.get_checkbox_value(FIELD_ID_CHILDS, &opt) )
      INTERR(562);

    // Disable recursion level textbox
    fa.enable_field(FIELD_ID_CHILDS_LEVEL, !opt);//(opt & FWO_CALLEE_RECURSE_UNLIM) == 0);
  }

  if ( fid == FIELD_ID_FATHERS )
  {
    if ( !fa.get_checkbox_value(FIELD_ID_FATHERS, &opt) )
      INTERR(563);

    if ( opt > MAX_CALLERS_LEVEL )
    {
      info("Sorry, value is too big: %d", opt);
      opt = MAX_CALLERS_LEVEL;
      fa.set_checkbox_value(FIELD_ID_FATHERS, &opt);
    }
  }

  return 1;
}

//--------------------------------------------------------------------------
static bool show_options()
{
  static const char opt_form[] =
    "Call graph configuration\n"
    "%/"
    "<##Show ~s~tring references:C1>\n"
    "<##Options##Hide ~l~ibrary functions:C2>\n"
    "<##Max ~p~arents recursion level:D3:5:5::>\n"
    "<##Unlimited children recursion:C4>5>\n"
    "<##Max ~c~hildren recursion level:D6:5:5::>\n"
    "<##~L~imit of nodes per level:D7:5:5::>\n"
    ;

  ushort opt = fg_opts.flags;

  // When analyzing big functions, fg_opts.recurse_limit is too big
  sval_t callers_limit = fg_opts.callers_recurse_limit;
  sval_t callees_limit = fg_opts.callees_recurse_limit;
  sval_t max_nodes = fg_opts.max_nodes;

  if ( !AskUsingForm_c(
          opt_form,
          options_cb,
          &callers_limit,
          &opt,
          &callees_limit,
          &max_nodes) )
  {
    return false;
  }

  if ( callees_limit <= 0 )
  {
    callers_limit = 0;
    opt |= FWO_CALLEE_RECURSE_UNLIM;
  }

  fg_opts.flags  = opt;
  fg_opts.callees_recurse_limit = callees_limit;
  fg_opts.callers_recurse_limit = callers_limit;
  fg_opts.max_nodes = max_nodes;

  // save options
  netnode n;
  n.create(NODE_NAME);
  n.supset(1, &fg_opts, sizeof(fg_opts));
  return true;
}

//--------------------------------------------------------------------------
static void jump_to_node(const graph_info_t *gi, const int nid)
{
  viewer_center_on(gi->gv, nid);
  int x, y;

  // will return a place only when a node was previously selected
  place_t *old_pl = get_custom_viewer_place(gi->gv, false, &x, &y);
  if ( old_pl != NULL )
  {
    user_graph_place_t *new_pl = (user_graph_place_t *) old_pl->clone();
    new_pl->node = nid;
    jumpto(gi->gv, new_pl, x, y);
    ::qfree(new_pl);
  }
}

//--------------------------------------------------------------------------
static int findfirst_node(callgraph_t *fg)
{
  static const char form[] =
    "Enter search substring\n"
    "\n"
    " <#Search is not case sensitive#Function name:A:1000:50::>\n\n";

  static char last_text[MAXSTR] = "";
  if ( !AskUsingForm_c(form, last_text) )
    return -2;

  return fg->find_first(last_text);
}

//--------------------------------------------------------------------------
static void display_node_search_result(graph_info_t *gi, int nid)
{
  // search was cancelled
  if ( nid == -2 )
    return;

  const char *txt = gi->fg.get_findtext();
  if ( nid == -1 )
  {
    msg("No match for '%s'\n", txt);
  }
  else
  {
    msg("%a: matched '%s'\n", gi->fg.get_addr(nid), txt);
    jump_to_node(gi, nid);
  }
}

//--------------------------------------------------------------------------
bool idaapi callgraph_t::menu_refresh_cb(void *ud)
{
  DECLARE_GI_VAR;
  gi->refresh();
  return true;
}

//--------------------------------------------------------------------------
bool idaapi callgraph_t::menu_home_cb(void *ud)
{
  DECLARE_GI_VARS;
  if ( fg->count() > 1 )
    jump_to_node(gi, 0);
  return true;
}

//--------------------------------------------------------------------------
bool idaapi callgraph_t::menu_searchfirst_cb(void *ud)
{
  DECLARE_GI_VARS;
  display_node_search_result(gi, findfirst_node(fg));
  return true;
}

//--------------------------------------------------------------------------
bool idaapi callgraph_t::menu_searchnext_cb(void *ud)
{
  DECLARE_GI_VARS;
  display_node_search_result(gi, fg->find_next());
  return true;
}

//--------------------------------------------------------------------------
bool idaapi callgraph_t::menu_options_cb(void *ud)
{
  DECLARE_GI_VAR;
  if ( show_options() )
    gi->refresh();

  return true;
}

//--------------------------------------------------------------------------
bool idaapi callgraph_t::navigate(void *ud, ea_t addr)
{
  DECLARE_GI_VAR;
  ea_t func_ea;

  func_ea = gi->fg.get_addr(0);

  // Is it a function?
  func_t *pfn = get_func(addr);
  if ( pfn != NULL )
  {
    // Is it the same function?
    if (gi->func_ea != addr)
    {
      // Clear the forward queue
      gi->forward_queue.clear();

      // Enqueue the current center node
      gi->queue.push_front(func_ea);

      gi->func_ea = addr;
      gi->refresh();

      jump_to_node(gi, 0);
      return true;
    }
  }
  else
  {
    return true;
  }

  return false;
}

//--------------------------------------------------------------------------
void idaapi callgraph_t::go_back(void *ud)
{
  DECLARE_GI_VAR;

  gi->forward_queue.push_front(gi->func_ea);
  gi->func_ea = gi->queue.front();
  gi->queue.pop_front();
  gi->refresh();

  jump_to_node(gi, 0);
}

//--------------------------------------------------------------------------
void idaapi callgraph_t::go_forward(void *ud)
{
  DECLARE_GI_VAR;
  ea_t ea;

  ea = gi->forward_queue.front();
  gi->forward_queue.pop_front();
  gi->queue.push_front(gi->func_ea);
  gi->func_ea = ea;
  gi->refresh();

  jump_to_node(gi, 0);
}

//--------------------------------------------------------------------------
bool idaapi callgraph_t::menu_center_cb(void *ud)
{
  DECLARE_GI_VAR;

  int node;
  ea_t addr;

  node = viewer_get_curnode(gi->gv);
  if ( node != -1 )
  {
    addr = gi->fg.get_addr(node);
    return navigate(ud, addr);
  }
  else
    return false;

}

//--------------------------------------------------------------------------
bool idaapi callgraph_t::menu_jump_cb(void *ud)
{
  DECLARE_GI_VAR;

  int node;
  ea_t addr;

  node = viewer_get_curnode(gi->gv);
  if (node != -1)
  {
    addr = gi->fg.get_addr(node);
    jumpto(addr);
  }
  return true;
}

//--------------------------------------------------------------------------
bool idaapi callgraph_t::menu_jumpxref_cb(void *ud)
{
  DECLARE_GI_VAR;

  int node;
  ea_t addr;

  node = viewer_get_curnode(gi->gv);
  if ( node != -1 )
  {
    addr = gi->fg.get_addr(node);
    ea_t xref = choose_xref(addr);

    if ( xref != 0 && xref != BADADDR )
      navigate(ud, xref);

  }
  return true;
}

//--------------------------------------------------------------------------
bool idaapi callgraph_t::menu_jumpaddr_cb(void *ud)
{
  ea_t addr;

  if ( askaddr(&addr, "Jump address") )
  {
    func_t *pfn = get_func(addr);
    if ( pfn == NULL )
    {
      warning("You have entered an invalid address");
      return false;
    }
    navigate(ud, addr);
  }

  return true;
}

//--------------------------------------------------------------------------
bool idaapi callgraph_t::menu_back_cb(void *ud)
{
  DECLARE_GI_VAR;

  if (gi->queue.empty())
  {
    //msg("Queue is empty\n");
    close_tform(gi->form, FORM_SAVE);
    return true;
  }
  else
  {
    go_back(ud);
  }

  return true;
}

//--------------------------------------------------------------------------
bool idaapi callgraph_t::menu_forward_cb(void *ud)
{
  DECLARE_GI_VAR;

  if ( !gi->forward_queue.empty() )
  {
    go_forward(ud);
  }

  return true;
}

//--------------------------------------------------------------------------
bool idaapi callgraph_t::menu_hidenode_cb(void *ud)
{
  DECLARE_GI_VAR;

  int node;
  ea_t addr;

  node = viewer_get_curnode(gi->gv);
  if (node != -1)
  {
    addr = gi->fg.get_addr(node);
    //msg("Should hide 0x%08x\n", addr);
    gi->hide_nodes.push_back(addr);
    gi->refresh();
  }

  return true;
}

//--------------------------------------------------------------------------
// column headers
static const char *const show_header[] =
{
  "Function",
  "Address",
};
static const int show_widths[] = { CHCOL_HEX|32, 10 };

CASSERT(qnumber(show_widths) == qnumber(show_header));

//-------------------------------------------------------------------------
// function that returns number of lines in the list
static uint32 idaapi show_hidden_sizer(void *obj)
{
  graph_info_t *gi = (graph_info_t *)obj;
  return gi->hide_nodes.size();
}

//--------------------------------------------------------------------------
static void idaapi show_hidden_desc(void *obj,uint32 n,char * const *arrptr)
{
  if ( n == 0 ) // generate the column headers
  {
    for ( size_t i=0;i < qnumber(show_header); i++ )
      qstrncpy(arrptr[i], show_header[i], MAXSTR);
    return;
  }

  graph_info_t *gi = (graph_info_t *)obj;
  ea_t ea = gi->hide_nodes.at(n-1);

  qstring func_name;
  if ( get_true_name(&func_name, ea) > 0 )
  {
    qstrncpy(arrptr[0], func_name.begin(), MAXSTR);
    qsnprintf(arrptr[1], MAXSTR, "%a", ea);
  }
}

//--------------------------------------------------------------------------
bool idaapi callgraph_t::menu_showhidden_cb(void *ud)
{
  DECLARE_GI_VAR;
  size_t ret;

  if (gi->hide_nodes.empty())
  {
    info("No functions hidden\n");
    return true;
  }

  // now open the window
  ret = choose2(CH_MODAL,               // modal window
          -1, -1, -1, -1,               // position is determined by Windows
          gi,                           // pass the callgraph_t object
          qnumber(show_header),         // number of columns
          show_widths,                  // widths of columns
          show_hidden_sizer,            // function that returns number of lines
          show_hidden_desc,             // function that generates a line
          "Show function",              // window title
          -1,                           // use the default icon for the window
          0,                            // position the cursor on the first line
          NULL,                         // "kill" callback
          NULL,                         // "new" callback
          NULL,                         // "update" callback
          NULL,                         // "edit" callback
          NULL,                         // function to call when the user pressed Enter
          NULL,                         // function to call when the window is closed
          NULL,                         // use default popup menu items
          NULL);                        // use the same icon for all lines

  if ( ret > 0 )
  {
    eavec_t::iterator it;

    it = gi->hide_nodes.begin();
    gi->hide_nodes.erase(it+ret-1, it+ret);
    gi->refresh();
  }

  return true;
}

//--------------------------------------------------------------------------
bool idaapi callgraph_t::menu_showall_cb(void *ud)
{
  DECLARE_GI_VAR;

  gi->hide_nodes.clear();
  gi->refresh();

  return true;
}

//-------------------------------------------------------------------------
// function that returns number of lines in the list
static uint32 idaapi show_select_sizer(void *obj)
{
  graph_info_t *gi = (graph_info_t *)obj;
  return gi->fg.count();
}

//--------------------------------------------------------------------------
static void idaapi show_select_desc(void *obj,uint32 n,char * const *arrptr)
{
  if ( n == 0 ) // generate the column headers
  {
    for (size_t i=0;i<qnumber(show_header);i++)
      qstrncpy(arrptr[i], show_header[i], MAXSTR);
    return;
  }

  graph_info_t *gi = (graph_info_t *)obj;
  ea_t ea = gi->fg.get_addr(n-1);

  qstring func_name;
  if ( get_true_name(&func_name, ea) > 0 )
  {
    qstrncpy(arrptr[0], func_name.begin(), MAXSTR);
    qsnprintf(arrptr[1], MAXSTR, "%a", ea);
  }
}

//--------------------------------------------------------------------------
bool idaapi callgraph_t::menu_select_cb(void *ud)
{
  DECLARE_GI_VAR;
  int ret;

  // now open the window
  ret = choose2(CH_MODAL,               // modal window
          -1, -1, -1, -1,               // position is determined by Windows
          gi,                           // pass the callgraph_t object
          qnumber(show_header),         // number of columns
          show_widths,                  // widths of columns
          show_select_sizer,            // function that returns number of lines
          show_select_desc,             // function that generates a line
          "Select function",            // window title
          -1,                           // use the default icon for the window
          0,                            // position the cursor on the first line
          NULL,                         // "kill" callback
          NULL,                         // "new" callback
          NULL,                         // "update" callback
          NULL,                         // "edit" callback
          NULL,                         // function to call when the user pressed Enter
          NULL,                         // function to call when the window is closed
          NULL,                         // use default popup menu items
          NULL);                        // use the same icon for all lines

  if ( ret > 0 )
  {
    jump_to_node(gi, ret-1);
  }

  return true;
}

//--------------------------------------------------------------------------
bool idaapi donothing(void *)
{
  return true;
}

//--------------------------------------------------------------------------
void idaapi run(int arg)
{
  if ( arg == -1 )
  {
    load_options();
    show_options();
    return;
  }

  func_t *pfn = get_func(get_screen_ea());
  if ( pfn == NULL )
  {
    warning("Please position the cursor in a function first!");
    return;
  }

  load_options();
  qstring title;

  graph_info_t::get_new_title(pfn->startEA, &title);

  HWND hwnd = NULL;
  TForm *form = create_tform(title.c_str(), &hwnd);
  if ( hwnd != NULL )
  {
    // Window is new, but instance is in the list?
    graph_info_t *gi = graph_info_t::find(title.c_str());
    if ( gi != NULL )
    {
      // In that case let us "recycle" the instance
      gi->func_ea = pfn->startEA;
    }
    else
    {
      // we create a new instance
      gi = graph_info_t::create(pfn->startEA);
    }

    if ( gi != NULL )
    {
      // get a unique graph id
      netnode id;
      id.create("$ callgraph sample");

      gi->hide_nodes.begin();

      gi->mark_for_refresh();
      gi->form = form;
      gi->gv = create_graph_viewer(form, id, callgraph_t::gr_callback, gi, 0);

      open_tform(form, FORM_TAB|FORM_MENU|FORM_QWIDGET);

      if ( gi->gv != NULL )
      {
        viewer_fit_window(gi->gv);
#define ADD_POPUP(name, func, hotkey) \
        viewer_add_menu_item(gi->gv, name, callgraph_t::func, gi, hotkey, 0);
#define ADD_SEPARATOR() \
        viewer_add_menu_item(gi->gv, "-", donothing, gi, NULL, 0);
        ADD_POPUP("Options", menu_options_cb, "O");
        ADD_POPUP("Refresh", menu_refresh_cb, "R");
        ADD_SEPARATOR()
        ADD_POPUP("Jump to xref", menu_jumpxref_cb, "X");
        ADD_POPUP("Jump to address", menu_jumpaddr_cb, "G");
        ADD_POPUP("Jump to function", menu_jump_cb, "SPACE");
        ADD_POPUP("Jump to previous node", menu_back_cb, "ESC");
        ADD_POPUP("Jump to next node", menu_forward_cb, "Ctrl+Enter");
        ADD_SEPARATOR()
        ADD_POPUP("Center node", menu_center_cb, "Enter");
        ADD_POPUP("Select node", menu_select_cb, "Ctrl+L");
        ADD_POPUP("Goto to first node", menu_home_cb, "H");
        ADD_POPUP("Search first", menu_searchfirst_cb, "S");
        ADD_POPUP("Search next", menu_searchnext_cb, "N");
        ADD_POPUP("Hide selected node", menu_hidenode_cb, NULL);
        ADD_POPUP("Show hidden node", menu_showhidden_cb, NULL);
        ADD_POPUP("Show all nodes", menu_showall_cb, NULL);
#undef ADD_SEPARATOR
#undef ADD_POPUP
      }
      else
      {
        graph_info_t::destroy(gi);
        gi = NULL;
      }
    }

    // Failed to create a graph view?
    if ( gi == NULL )
    {
      warning("Failed to create call graph window!\n");
      return;
    }
  }
  else
  {
    graph_info_t *gi = graph_info_t::find(title.c_str());
    if ( gi != NULL )
    {
      gi->refresh();
      open_tform(gi->form, FORM_TAB|FORM_MENU|FORM_QWIDGET);
    }
  }
}

//-------------------------------------------------------------------------
struct show_callgraph_ah_t : public action_handler_t
{
  virtual int idaapi activate(action_activation_ctx_t *)
  {
    run(0);
    return 0;
  }

  virtual action_state_t idaapi update(action_update_ctx_t *)
  {
    return AST_ENABLE_ALWAYS;
  }
};
static show_callgraph_ah_t show_callgraph_ah;

#define ACTION_NAME "callgraph:ShowCallgraph"
#define ACTION_LABEL "Function call graph"

//--------------------------------------------------------------------------
int idaapi init(void)
{
  // GUI version?
  if ( callui(ui_get_hwnd).vptr == NULL && !is_idaq() )
    return PLUGIN_SKIP;

  static const action_desc_t desc = ACTION_DESC_LITERAL(
          ACTION_NAME,
          ACTION_LABEL,
          &show_callgraph_ah,
          "Ctrl+Shift+B",
          NULL, -1);
  if ( !register_action(desc)
    || !attach_action_to_menu("View/Open subviews/Function calls", ACTION_NAME, SETMENU_APP) )
  {
    msg("Failed to register menu item for <" ACTION_LABEL "> plugin! Please access it from the plugins submenu");
    return PLUGIN_SKIP;
  }

  return PLUGIN_KEEP;
}

//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_HIDE,          // plugin flags
  init,                 // initialize

  NULL,                 // terminate. this pointer may be NULL.

  run,                  // invoke plugin

  // long comment about the plugin
  "Proximity browser plugin.",
  // it could appear in the status line
  // or as a hint

  // multiline help about the plugin
  "Proximity browser using the graph SDK\n"
  "\n"
  "Position the cursor in a function and run the plugin.",

  ACTION_LABEL,     // the preferred short name of the plugin
  ""                // the preferred hotkey to run the plugin
};
