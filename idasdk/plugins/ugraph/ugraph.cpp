/*
 *  This is a sample plugin module.
 *  It demonstrates how to create a graph viewer with an aribtrary graph.
 *
 *  It can be compiled by the following compilers:
 *
 *      - Borland C++, CBuilder, free C++
 *
 */

#include <ida.hpp>
#include <idp.hpp>
#include <graph.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

//--------------------------------------------------------------------------
static qstrvec_t graph_text;
static graph_viewer_t *gv = NULL;

//--------------------------------------------------------------------------
static const char *get_node_name(int n)
{
  switch ( n )
  {
    case 0: return COLSTR("This", SCOLOR_MACRO);
    case 1: return COLSTR("is", SCOLOR_CNAME);
    case 2: return "a";
    case 3: return COLSTR("sample", SCOLOR_DNAME);
    case 4: return COLSTR("graph", SCOLOR_IMPNAME);
    case 5: return COLSTR("viewer", SCOLOR_ERROR);
    case 6: return COLSTR("window!", SCOLOR_DNUM) "\n(with colorful names)";
  }
  return "?";
}

//--------------------------------------------------------------------------
static ssize_t idaapi callback(void *, int code, va_list va)
{
  ssize_t result = 0;
  switch ( code )
  {
    case grcode_calculating_layout:
                              // calculating user-defined graph layout
                              // in: mutable_graph_t *g
                              // out: 0-not implemented
                              //      1-graph layout calculated by the plugin
      msg("calculating graph layout...\n");
      break;

    case grcode_changed_current:
                              // a new graph node became the current node
                              // in:  graph_viewer_t *gv
                              //      int curnode
                              // out: 0-ok, 1-forbid to change the current node
     {
       graph_viewer_t *v = va_arg(va, graph_viewer_t *);
       int curnode       = va_argi(va, int);
       msg("%p: current node becomes %d\n", v, curnode);
     }
     break;

    case grcode_clicked:      // a graph has been clicked
                              // in:  graph_viewer_t *gv
                              //      selection_item_t *current_item
                              // out: 0-ok, 1-ignore click
     {
       graph_viewer_t *v = va_arg(va, graph_viewer_t *); qnotused(v);
       selection_item_t *it = va_arg(va, selection_item_t *); qnotused(it);
       graph_item_t *m = va_arg(va, graph_item_t *);
       msg("clicked on ");
       switch ( m->type )
       {
         case git_none:
           msg("background\n");
           break;
         case git_edge:
           msg("edge (%d, %d)\n", m->e.src, m->e.dst);
           break;
         case git_node:
           msg("node %d\n", m->n);
           break;
         case git_tool:
           msg("toolbutton %d\n", m->b);
           break;
         case git_text:
           msg("text (x,y)=(%d,%d)\n", m->p.x, m->p.y);
           break;
         case git_elp:
           msg("edge layout point (%d, %d) #%d\n", m->elp.e.src, m->elp.e.dst, m->elp.pidx);
           break;
       }
     }
     break;

    case grcode_dblclicked:   // a graph node has been double clicked
                              // in:  graph_viewer_t *gv
                              //      selection_item_t *current_item
                              // out: 0-ok, 1-ignore click
     {
       graph_viewer_t *v   = va_arg(va, graph_viewer_t *);
       selection_item_t *s = va_arg(va, selection_item_t *);
       msg("%p: %sclicked on ", v, code == grcode_clicked ? "" : "dbl");
       if ( s == NULL )
         msg("background\n");
       else if ( s->is_node )
         msg("node %d\n", s->node);
       else
         msg("edge (%d, %d) layout point #%d\n", s->elp.e.src, s->elp.e.dst, s->elp.pidx);
     }
     break;

    case grcode_creating_group:
                              // a group is being created
                              // in:  mutable_graph_t *g
                              //      intvec_t *nodes
                              // out: 0-ok, 1-forbid group creation
     {
       mutable_graph_t *g = va_arg(va, mutable_graph_t *);
       intvec_t &nodes    = *va_arg(va, intvec_t *);
       msg("%p: creating group", g);
       for ( intvec_t::iterator p=nodes.begin(); p != nodes.end(); ++p )
         msg(" %d", *p);
       msg("...\n");
     }
     break;

    case grcode_deleting_group:
                              // a group is being deleted
                              // in:  mutable_graph_t *g
                              //      int old_group
                              // out: 0-ok, 1-forbid group deletion
     {
       mutable_graph_t *g = va_arg(va, mutable_graph_t *);
       int group          = va_argi(va, int);
       msg("%p: deleting group %d\n", g, group);
     }
     break;

    case grcode_group_visibility:
                              // a group is being collapsed/uncollapsed
                              // in:  mutable_graph_t *g
                              //      int group
                              //      bool expand
                              // out: 0-ok, 1-forbid group modification
     {
       mutable_graph_t *g = va_arg(va, mutable_graph_t *);
       int group          = va_argi(va, int);
       bool expand        = va_argi(va, bool);
       msg("%p: %scollapsing group %d\n", g, expand ? "un" : "", group);
     }
     break;

    case grcode_gotfocus:     // a graph viewer got focus
                              // in:  graph_viewer_t *gv
                              // out: must return 0
     {
       graph_viewer_t *g = va_arg(va, graph_viewer_t *);
       msg("%p: got focus\n", g);
     }
     break;

    case grcode_lostfocus:    // a graph viewer lost focus
                              // in:  graph_viewer_t *gv
                              // out: must return 0
     {
       graph_viewer_t *g = va_arg(va, graph_viewer_t *);
       msg("%p: lost focus\n", g);
     }
     break;

    case grcode_user_refresh: // refresh user-defined graph nodes and edges
                              // in:  mutable_graph_t *g
                              // out: success
     {
       mutable_graph_t *g = va_arg(va, mutable_graph_t *);
       msg("%p: refresh\n", g);
       // our graph is like this:
       //  0 -> 1 -> 2
       //       \-> 3 -> 4 -> 5 -> 6
       //           ^        /
       //           \-------/
       if ( g->empty() )
         g->resize(7);
       g->add_edge(0, 1, NULL);
       g->add_edge(1, 2, NULL);
       g->add_edge(1, 3, NULL);
       g->add_edge(3, 4, NULL);
       g->add_edge(4, 5, NULL);
       g->add_edge(5, 3, NULL);
       g->add_edge(5, 6, NULL);
       result = true;
     }
     break;

    case grcode_user_gentext: // generate text for user-defined graph nodes
                              // in:  mutable_graph_t *g
                              // out: must return 0
     {
       mutable_graph_t *g = va_arg(va, mutable_graph_t *);
       msg("%p: generate text for graph nodes\n", g);
       graph_text.resize(g->size());
       for ( node_iterator p=g->begin(); p != g->end(); ++p )
       {
         int n = *p;
         graph_text[n] = get_node_name(n);
       }
       result = true;
     }
     break;

    case grcode_user_text:    // retrieve text for user-defined graph node
                              // in:  mutable_graph_t *g
                              //      int node
                              //      const char **result
                              //      bgcolor_t *bg_color (maybe NULL)
                              // out: must return 0, result must be filled
                              // NB: do not use anything calling GDI!
     {
       mutable_graph_t *g = va_arg(va, mutable_graph_t *);
       int node           = va_arg(va, int);
       const char **text  = va_arg(va, const char **);
       bgcolor_t *bgcolor = va_arg(va, bgcolor_t *);
       *text = graph_text[node].c_str();
       if ( bgcolor != NULL )
         *bgcolor = DEFCOLOR;
       result = true;
       qnotused(g);
     }
     break;


    case grcode_user_size:    // calculate node size for user-defined graph
                              // in:  mutable_graph_t *g
                              //      int node
                              //      int *cx
                              //      int *cy
                              // out: 0-did not calculate, ida will use node text size
                              //      1-calculated. ida will add node title to the size
     msg("calc node size - not implemented\n");
     // ida will calculate the node size based on the node text
     break;

    case grcode_user_title:   // render node title of a user-defined graph
                              // in:  mutable_graph_t *g
                              //      int node
                              //      rect_t *title_rect
                              //      int title_bg_color
                              //      HDC dc
                              // out: 0-did not render, ida will fill it with title_bg_color
                              //      1-rendered node title
     // ida will draw the node title itself
     break;

    case grcode_user_draw:    // render node of a user-defined graph
                              // in:  mutable_graph_t *g
                              //      int node
                              //      rect_t *node_rect
                              //      HDC dc
                              // out: 0-not rendered, 1-rendered
                              // NB: draw only on the specified DC and nowhere else!
     // ida will draw the node text itself
     break;

    case grcode_user_hint:    // retrieve hint for the user-defined graph
                              // in:  mutable_graph_t *g
                              //      int mousenode
                              //      int mouseedge_src
                              //      int mouseedge_dst
                              //      char **hint
                              // 'hint' must be allocated by qalloc() or qstrdup()
                              // out: 0-use default hint, 1-use proposed hint
     {
       mutable_graph_t *g = va_arg(va, mutable_graph_t *);
       int mousenode      = va_argi(va, int);
       int mouseedge_src  = va_argi(va, int);
       int mouseedge_dst  = va_argi(va, int);
       char **hint        = va_arg(va, char **);
       char buf[MAXSTR];
       buf[0] = '\0';
       if ( mousenode != -1 )
         qsnprintf(buf, sizeof(buf), "My fancy hint for node %d", mousenode);
       else if ( mouseedge_src != -1 )
         qsnprintf(buf, sizeof(buf), "Hovering on (%d,%d)", mouseedge_src, mouseedge_dst);
       if ( buf[0] != '\0' )
         *hint = qstrdup(buf);
       result = true; // use our hint
       qnotused(g);
     }
     break;
  }
  return result;
}

//-------------------------------------------------------------------------
static const char wanted_title[] = "Sample graph";

//-------------------------------------------------------------------------
struct change_layout_ah_t : public action_handler_t
{
  virtual int idaapi activate(action_activation_ctx_t *ctx)
  {
    gv = (graph_viewer_t *) ctx->widget;
    mutable_graph_t *g = get_viewer_graph(gv);
    int code = ask_buttons("Circle", "Tree", "Digraph", 1, "Please select layout type");
    node_info_t ni;
    ni.bg_color = 0x44FF55;
    ni.text = "Hello from plugin!";
    set_node_info(g->gid, 7, ni, NIF_BG_COLOR | NIF_TEXT);
    g->current_layout = code + 2;
    g->circle_center = point_t(200, 200);
    g->circle_radius = 200;
    g->redo_layout();
    refresh_viewer(gv);
    return 1;
  }

  virtual action_state_t idaapi update(action_update_ctx_t *ctx)
  {
    if ( ctx->widget == (TWidget *) gv )
      return AST_ENABLE_FOR_WIDGET;
    else
      return AST_DISABLE_FOR_WIDGET;
  }
};
static change_layout_ah_t change_layout_ah;
static const action_desc_t change_layout_desc = ACTION_DESC_LITERAL(
        "ugraph:ChangeLayout",
        "User function",
        &change_layout_ah,
        NULL,
        NULL,
        -1);


//-------------------------------------------------------------------------
static ssize_t idaapi ui_hook(void *, int notification_code, va_list va)
{
  if ( notification_code == view_close )
  {
    TWidget *view = va_arg(va, TWidget *);
    if ( view == (TWidget *) gv )
      gv = NULL;
  }
  return 0;
}

//--------------------------------------------------------------------------
int idaapi init(void)
{
  hook_to_notification_point(HT_VIEW, ui_hook);
  return is_idaq() ? PLUGIN_OK : PLUGIN_SKIP;
}

//--------------------------------------------------------------------------
void idaapi term(void)
{
  unhook_from_notification_point(HT_VIEW, ui_hook);
}

//--------------------------------------------------------------------------
bool idaapi run(size_t)
{
  TWidget *widget = find_widget(wanted_title);
  if ( widget == NULL )
  {
    // get a unique graph id
    netnode id;
    id.create("$ ugraph sample");
    gv = create_graph_viewer(wanted_title, id, callback, NULL, 0);
    if ( gv != NULL )
    {
      display_widget(gv, WOPN_TAB|WOPN_MENU);
      viewer_fit_window(gv);
      register_action(change_layout_desc);
      viewer_attach_menu_item(gv, change_layout_desc.name);
    }
  }
  else
  {
    close_widget(widget, 0);
  }

  return true;
}

//--------------------------------------------------------------------------
static const char comment[] = "This is a sample graph plugin.";

static const char help[] =
  "A sample graph plugin module\n"
  "\n"
  "This module shows you how to create a graph viewer.";

//--------------------------------------------------------------------------
// This is the preferred name of the plugin module in the menu system
// The preferred name may be overriden in plugins.cfg file

static const char wanted_name[] = "Create sample graph view";


// This is the preferred hotkey for the plugin module
// The preferred hotkey may be overriden in plugins.cfg file
// Note: IDA won't tell you if the hotkey is not correct
//       It will just disable the hotkey.

static const char wanted_hotkey[] = "";


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
