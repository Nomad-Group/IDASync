
#ifndef PDBREMOTE_HPP
#define PDBREMOTE_HPP

#include <map>
#include "../../dbg/common/rpc_hlp.h"
#include "../../dbg/common/win32_rpc.h"
#include "pdbaccess.hpp"

// The PDB related code that works on Unix
// It connects to a Windows computer and asks to retrieve PDB info

//----------------------------------------------------------------------------
class remote_pdb_access_t : public pdb_access_t
{
public:
  remote_pdb_access_t(
        const pdbargs_t &args,
        const char *_host,
        int _port,
        const char *_pwd)
    : pdb_access_t(args),
      host(_host),
      port(_port),
      pwd(_pwd),
      connection_is_open(false)
  {
    set_base_address(args.loaded_base);
  }

  virtual ~remote_pdb_access_t();

  // Open connection, create PDB session.
  HRESULT open_connection();
  // Close PDB session, close connection.
  void close_connection();

  virtual HRESULT do_iterate_children(
        pdb_sym_t &sym,
        enum SymTagEnum type,
        children_visitor_t &visitor);
  virtual HRESULT load(pdb_sym_t &sym, DWORD id);

  // Possibly remote operation.
  // If NULL is returned, it means the symbol is not available, nor
  // could it be fetched remotely.
  ioctl_pdb_code_t get_sym_data(pdb_sym_t &sym, sym_data_t **);
  ioctl_pdb_code_t get_sym_data(DWORD sym_id, sym_data_t **);


private:
#define SAFE_GET(type)                                          \
  sym_data_t *sym_data;                                         \
  ioctl_pdb_code_t result = get_sym_data(sym, &sym_data);       \
  if ( result == pdb_ok )                                       \
    return sym_data->get_##type(token, out);                    \
  else                                                          \
    return E_FAIL

  // Build sym_data_t instance, and register it into the 'cache'.
  DWORD build_and_register_sym_data(const uchar **raw, const uchar *end);

  // Wheverer fetch_children_infos(), or get_sym_data() performs
  // a remote operation, this is used to handle the response
  // and add the fetched symbol data to the cache.
  void handle_fetch_response(
        const uchar **ptr,
        const uchar *end,
        qvector<DWORD> *ids_storage);

  // Remote operation.
  ioctl_pdb_code_t fetch_children_infos(
        pdb_sym_t &sym,
        enum SymTagEnum type,
        qvector<DWORD> *children_ids);

  sym_data_t *get_sym_data_from_cache(DWORD id);

  // Low-level interface used by open_connection(), fetch_children_infos(), and get_sym_data().
  // 'fetch_type' is one of
  //   WIN32_IOCTL_PDB_OPEN,
  //   WIN32_IOCTL_PDB_FETCH_SYMBOL,
  //   WIN32_IOCTL_PDB_FETCH_CHILDREN
  ioctl_pdb_code_t perform_op(int op_type, const bytevec_t &oper, void *data);

  ioctl_pdb_code_t send_ioctl(
        int fn,
        const void *buf,
        size_t size,
        void **poutbuf,
        ssize_t *poutsize);

  std::map<DWORD, sym_data_t*> cache;
  const char *user_spath;
  char errbuf[MAXSTR];

  // For the moment, we'll channel all IOCTL requests
  // through the debugger. Ideally, we should be able to just
  // use a RPC client.
  bool load_win32_debugger(void);

  const char *host;
  int port;
  const char *pwd;
  bool was_connected;
  bool is_dbg_module;
  bool connection_is_open;
};

#endif // PDBREMOTE_HPP
