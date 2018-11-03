#ifndef __CALLGRAPH__06192009__
#define __CALLGRAPH__06192009__

#include <deque>
#include <algorithm>
#include <ida.hpp>
#include <idp.hpp>
#include <name.hpp>
#include <bytes.hpp>
#include <graph.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <demangle.hpp>

#define MAX_CALLERS_LEVEL 10

#define FIELD_ID_STRINGS 1
#define FIELD_ID_LIBS 2
#define FIELD_ID_FATHERS 3
#define FIELD_ID_CHILDS 4
#define FIELD_ID_CHILDS_LEVEL 6

#define VERTEX_HIDDEN_NODES -1

typedef std::deque<int> int_queue_t;
typedef std::map<ea_t, int> ea_int_map_t;

//--------------------------------------------------------------------------
struct funcs_walk_options_t
{
  int32 version;
#define FWO_VERSION 1 // current version of options block
  int32 flags;
#define FWO_SHOWSTRING                           0x0001 // show string references
#define FWO_SKIPLIB                              0x0002 // skip library functions
#define FWO_CALLEE_RECURSE_UNLIM 0x0004 // unlimited callees recursion
  int32 callees_recurse_limit; // how deep to recurse callees (0 = unlimited)
  int32 callers_recurse_limit; // how deep to recurse callers (0 = unlimited)
  int32 max_nodes;             // maximum number of nodes per level
};

class graph_info_t;

//--------------------------------------------------------------------------
// function call graph creator class
class callgraph_t
{
  int node_count;

  // node id to func addr and reverse lookup
  typedef std::map<int, ea_t> int_ea_map_t;
  int_ea_map_t node2ea;

  // current node search ptr
  int  cur_node;
  char cur_text[MAXSTR];

  bool visited(ea_t func_ea, int *nid);
  int  add(ea_t func_ea);

public:

  ea_int_map_t ea2node;
  // edge structure
  struct edge_t
  {
    int id1;
    int id2;
    edge_t(int i1, int i2): id1(i1), id2(i2) {}
    edge_t(): id1(0), id2(0) {}
  };
  typedef qlist<edge_t> edges_t;

  // edge manipulation
  typedef edges_t::iterator edge_iterator;
  void create_edge(int id1, int id2);
  edge_iterator begin_edges() { return edges.begin(); }
  edge_iterator end_edges() { return edges.end(); }
  void clear_edges();

  // find nodes by text
  int find_first(const char *text);
  int find_next();
  const char *get_findtext() { return cur_text; }
  callgraph_t();
  int count() const { return node_count; }
  void reset();

  // node / func info
  struct funcinfo_t
  {
    qstring name;
    bgcolor_t color;
    ea_t ea;
    qstring strings;
  };
  typedef std::map<int, funcinfo_t> int_funcinfo_map_t;
  int_funcinfo_map_t cached_funcs;
  funcinfo_t *get_info(int nid);

  // function name manipulation
  ea_t get_addr(int nid) const;
  const char *get_name(int nid);

  int walk_func(eavec_t *hide_nodes, func_t *func, funcs_walk_options_t *o=NULL, int level=1);
  void add_fathers(func_t *func, ea_t func_start, int id, funcs_walk_options_t *opt, int level);

  bool navigate(graph_info_t *gi, ea_t addr) const;

  void go_back(graph_info_t *gi) const;
  void go_forward(graph_info_t *gi) const;

  bool options(graph_info_t *gi) const;
  bool refresh(graph_info_t *gi) const;

  bool jumpxref(graph_info_t *gi) const;
  bool jumpaddr(graph_info_t *gi) const;
  bool jump(const graph_info_t *gi) const;
  bool back(graph_info_t *gi) const;
  bool forward(graph_info_t *gi) const;

  bool center(graph_info_t *gi) const;
  bool select(const graph_info_t *gi) const;
  bool home(const graph_info_t *gi) const;
  bool searchfirst(graph_info_t *gi);
  bool searchnext(graph_info_t *gi);
  bool hidenode(graph_info_t *gi) const;
  bool showhidden(graph_info_t *gi) const;
  bool showall(graph_info_t *gi) const;

  static ssize_t idaapi gr_callback(void *ud, int code, va_list va);
  static void idaapi user_refresh(void *ud, int code, va_list va, int current_node);
private:
  edges_t edges;
};


//--------------------------------------------------------------------------
// Per function call graph context
class graph_info_t
{
// Actual context variables
public:
  callgraph_t fg; // associated call graph maker
  graph_viewer_t *gv; // associated graph_view
  TWidget *widget; // associated widget
  ea_t func_ea; // function ea in question
  qstring title; // the title

  int_queue_t queue;
  int_queue_t forward_queue;

  eavec_t hide_nodes;

// Instance management
private:
  bool refresh_needed; // schedule a refresh
  typedef qlist<graph_info_t *> graphinfo_list_t;
  typedef graphinfo_list_t::iterator iterator;
  static graphinfo_list_t instances;

  graph_info_t();
  static bool find(const ea_t func_ea, iterator *out);
public:
  static graph_info_t *find(const ea_t func_ea);
  static graph_info_t *find(const char *title);
  static graph_info_t *find(const graph_viewer_t *v);
  static graph_info_t *create(ea_t func_ea);
  static void destroy(graph_info_t *gi);
  static bool get_title(ea_t func_ea, qstring *out);
  static bool get_new_title(ea_t ea, qstring *out);
  static void setup_hooks(graph_info_t *r);
  static void remove_hooks(graph_info_t *r);
  void mark_for_refresh(void);
  void mark_as_refreshed(void);
  void refresh(void);
  bool is_refresh_needed(void) const { return refresh_needed; }
};

#endif
