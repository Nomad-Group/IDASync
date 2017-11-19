#ifndef __PDB_COMMON_H__
#define __PDB_COMMON_H__

#include <algorithm>
#include <typeinf.hpp>
typedef bool (*input_exe_reader_t)(uint64 fileOffset, uint32 count, void *buffer, uint32 *read, void *user_data);
typedef bool (*input_mem_reader_t)(ea_t ea, uint32 count, void *buffer, uint32 *read, void *user_data);

static const char spath_prefix[] = "srv*";
static const char spath_suffix[] = "*http://msdl.microsoft.com/download/symbols";

const char *pdberr(int code);

#define PDB_NODE_NAME             "$ pdb"
#define PDB_DLLBASE_NODE_IDX       0
#define PDB_DLLNAME_NODE_IDX       0

enum pdb_callcode_t
{
  // user invoked 'load pdb' command, load pdb for the input file.
  // after invocation, result (boolean) is stored in: netnode(PDB_NODE_NAME).altval(PDB_DLLBASE_NODE_IDX)
  PDB_CC_USER = 0,
  // ida decided to call the plugin itself
  PDB_CC_IDA  = 1,
  // load pdb for an additional exe/dll, during a debugging session.
  //   load_addr: netnode(PDB_NODE_NAME).altval(PDB_DLLBASE_NODE_IDX)
  //   dll_name:  netnode(PDB_NODE_NAME).supstr(PDB_DLLNAME_NODE_IDX)
  PDB_CC_DBG_MODULE_LOAD = 2,
  // load additional pdb. This is semantically the same as
  // PDB_CC_USER (i.e., "File > Load file > PDB file..."), except
  // it won't ask the user for the data; rather it expects it in
  // netnode(PDB_NODE_NAME), just like 'PDB_CC_DBG_MODULE_LOAD' would.
  PDB_CC_USER_WITH_DATA = 3,
};


// Note: This will return the machine type, as it is known
// by the IDB, which might not be what you think. For example,
// if you need to tell x86 and x64 apart, you're out of luck.
// You may want to consider looking at pdbaccess_t's
// get_machine_type().
uint32 get_machine_from_idb();

#ifdef __NT__
#include "pdbaccess.hpp"
#include "pdblocal.hpp"

//----------------------------------------------------------------------------
struct pdb_session_t
{
  HMODULE dia_hmod;
  int refcount;
  local_pdb_access_t *pdb_access;

  pdb_session_t()
    : refcount(1),
      dia_hmod(NULL),
      pdb_access(NULL)
  {
    session_count++;
  }
  ~pdb_session_t();

  HRESULT open_session(const pdbargs_t &pdbargs);
  void close();
  const char *get_used_fname() const { return used_fname.begin(); }

private:
  DECLARE_UNCOPYABLE(pdb_session_t)
  HRESULT create_dia_source(IDiaDataSource **pSource, int *dia_version);

  // The total number of different PDB sessions; kept track of
  // in order to know when we can safely CoUninitialize().
  static int session_count;

  // Whether COM is initialized in this thread.
  static bool co_initialized;
#ifdef _DEBUG
public:
  qstring pdb_path;
#endif
  qstring used_fname;
};


//----------------------------------------------------------------------------
class pdb_session_ref_t
{
public:
  pdb_session_t *session;  // refcounted object

  pdb_session_ref_t(void) : session(NULL) {}
  pdb_session_ref_t(const pdb_session_ref_t &r);
  ~pdb_session_ref_t();

  pdb_session_ref_t &operator=(const pdb_session_ref_t &r);
  void create_session();
  void close();
  bool empty() const { return session == NULL; }
  bool opened() const { return !empty() && session->pdb_access != NULL; }
  HRESULT open_session(const pdbargs_t &args);
};

#endif

#endif
