
#include <pro.h>

#include "pdbremote.hpp"
#include "varser.hpp"

// Since we're using the win32 local stup debugger at the moment,
// this is necessary.
#include <dbg.hpp>

//----------------------------------------------------------------------------
HRESULT pdb_sym_t::get_classParent(pdb_sym_t *out)
{
  DWORD parent_id;
  HRESULT hr = data->get_dword(t_classParentId, &parent_id);
  if ( hr == S_OK )
    hr = pdb_access.load(*out, parent_id);
  return hr;
}

//----------------------------------------------------------------------------
HRESULT pdb_sym_t::get_type(pdb_sym_t *out)
{
  DWORD type_id;
  HRESULT hr = data->get_dword(t_typeId, &type_id);
  if ( hr == S_OK )
    hr = pdb_access.load(*out, type_id);
  return hr;
}

//----------------------------------------------------------------------------
const uint32 sym_data_t::sizes[] =
{
  sizeof(BOOL),
  sizeof(DWORD),
  sizeof(DWORD64),
  sizeof(char *),
  sizeof(LONG),
  sizeof(VARIANT)
};

//----------------------------------------------------------------------------
sym_data_t::sym_data_t(uint32 _tokens, const uchar *buf, size_t bufsize, packing_info_t _packing)
  : present(_tokens)
{
  memset(counters, 0, sizeof(counters));
  memset(children_infos, 0, sizeof(children_infos));

  if ( _packing == SYMDAT_PACKED )
  {
    const uchar *ptr = buf;
    const uchar *end = buf + bufsize;
    for ( int bit = t_start; bit != t_end; bit <<= 1 )
    {
      sym_token_t token = sym_token_t(bit);
      if ( !token_present(token) )
        continue;

      if ( is_sym_token_bool(token) )
      {
        counters[t_bool]++;
        uint8 tmp = unpack_db(&ptr, end);
        data.append(&tmp, sizeof(tmp));
      }
      else if ( is_sym_token_dword(token) )
      {
        counters[t_dword]++;
        uint32 tmp = unpack_dd(&ptr, end);
        data.append(&tmp, sizeof(tmp));
      }
      else if ( is_sym_token_dword64(token) )
      {
        counters[t_dword64]++;
        uint64 tmp = unpack_dq(&ptr, end);
        data.append(&tmp, sizeof(tmp));
      }
      else if ( is_sym_token_string(token) )
      {
        counters[t_string]++;
        char *tmp = qstrdup(unpack_str(&ptr, end));
        data.append(&tmp, sizeof(tmp));
      }
      else if ( is_sym_token_long(token) )
      {
        counters[t_long]++;
        LONG tmp = unpack_dd(&ptr, end);
        data.append(&tmp, sizeof(tmp));
      }
      else if ( is_sym_token_variant(token) )
      {
        counters[t_variant]++;
        VARIANT var;
        if ( varser_t::deserialize(var, &ptr, end) )
        {
          data.append(&var, sizeof(var));
        }
        else
        {
          static bool warned = false;
          if ( !warned )
          {
            warning("The PDB file contains VARIANT items that cannot be deserialized.");
            warned = true;
          }
        }
      }
      else
      {
        INTERR(30200);
      }
    }

    QASSERT(30201, data.size() == counters[t_bool]    * sizes[t_bool]
                                + counters[t_dword]   * sizes[t_dword]
                                + counters[t_dword64] * sizes[t_dword64]
                                + counters[t_string]  * sizes[t_string]
                                + counters[t_long]    * sizes[t_long]
                                + counters[t_variant] * sizes[t_variant]);
    QASSERT(30202, ptr == end);
  }
  else
  {
    data.append(buf, bufsize);
    // Not supported yet. All that's left to do
    // is count the types (counters[]), though.
    INTERR(30203);
  }
}

//----------------------------------------------------------------------------
sym_data_t::~sym_data_t()
{
  for ( int i = 0; i < SymTagMax; i++ )
  {
    children_t &children = children_infos[i];
    if ( children.ids != NULL )
    {
      qfree(children.ids);
      children.ids = NULL;
      children.cnt = 0;
    }
  }

  uint8 nstring = counters[t_string];
  if ( nstring > 0 )
  {
    char **cur_str_ptr = (char **)string_ptr(t_string_start);
    for ( uint8 i = 0; i < nstring; i++, cur_str_ptr++ )
      qfree(*cur_str_ptr);
  }

  uint8 nvariant = counters[t_variant];
  if ( nvariant > 0 )
  {
    VARIANT *cur_variant_ptr = (VARIANT *)variant_ptr(t_variant_start);
    for ( uint8 i = 0; i < nvariant; i++, cur_variant_ptr++ )
      if ( cur_variant_ptr->vt == VT_LPSTR )
        qfree(cur_variant_ptr->punkVal);
  }
}


#define READ_IF_FOUND(type, fun)                \
  const type *ptr = fun##_ptr(token);           \
  if ( ptr == NULL )                            \
  {                                             \
    return S_FALSE;                             \
  }                                             \
  else                                          \
  {                                             \
    *out = *ptr;                                \
    return S_OK;                                \
  }

//----------------------------------------------------------------------------
HRESULT sym_data_t::get_bool(sym_token_t token, BOOL *out) const
{
  READ_IF_FOUND(BOOL, bool)
}

//----------------------------------------------------------------------------
HRESULT sym_data_t::get_dword(sym_token_t token, DWORD *out) const
{
  READ_IF_FOUND(DWORD, dword)
}

//----------------------------------------------------------------------------
HRESULT sym_data_t::get_dword64(sym_token_t token, DWORD64 *out) const
{
  READ_IF_FOUND(DWORD64, dword64)
}

//----------------------------------------------------------------------------
HRESULT sym_data_t::get_string(sym_token_t token, qstring *out) const
{
  READ_IF_FOUND(char *, string)
}

//----------------------------------------------------------------------------
HRESULT sym_data_t::get_long(sym_token_t token, LONG *out) const
{
  READ_IF_FOUND(LONG, long)
}

//----------------------------------------------------------------------------
HRESULT sym_data_t::get_variant(sym_token_t token, VARIANT *out) const
{
  READ_IF_FOUND(VARIANT, variant)
}

#undef READ_IF_FOUND

//----------------------------------------------------------------------------
const void *sym_data_t::any_ptr(sym_token_t token, sym_token_t start, sym_token_t end) const
{
  if ( !token_present(token) )
    return NULL;

  static const sym_token_t ends[] =
  {
    t_bool_end,
    t_dword_end,
    t_dword64_end,
    t_string_end,
    t_long_end,
    t_variant_end,
  };
  CASSERT(qnumber(ends) == qnumber(counters));
  CASSERT(qnumber(sizes) == qnumber(counters));

  // count how many bytes we have to skip and determine the type size
  uint32 type_size = 0;
  const uchar *ptr = data.begin();
  for ( int i=0; i < qnumber(ends); i++ )
  {
    if ( token <= ends[i] )
    {
      type_size = sizes[i];
      break;
    }
    ptr += counters[i] * sizes[i];
  }
  QASSERT(30204, type_size != 0);

  // how many tokens of our type we have to skip?
  uint32 bit;
  for ( bit = start; bit <= end; bit <<= 1 )
  {
    sym_token_t t = sym_token_t(bit);
    if ( token_present(t) )
    {
      if ( t == token )
        return ptr;
      ptr += type_size;
    }
  }
  return NULL; // did not find the requested token
}

//----------------------------------------------------------------------------
remote_pdb_access_t::~remote_pdb_access_t()
{
  typedef std::map<DWORD,sym_data_t*>::iterator iter;
  for ( iter it = cache.begin(), end = cache.end(); it != end; it++ )
    delete it->second;

  close_connection();
}

//----------------------------------------------------------------------------
void remote_pdb_access_t::close_connection()
{
  if ( connection_is_open )
  {
    send_ioctl(WIN32_IOCTL_PDB_CLOSE, NULL, 0, NULL, NULL);
    connection_is_open = false;
  }

  if ( !was_connected && dbg != NULL )
    dbg->term_debugger();
}

//----------------------------------------------------------------------
// load and connect to a remote win32 debugger, if necessary
bool remote_pdb_access_t::load_win32_debugger(void)
{
  was_connected = false;
  if ( dbg != NULL && (!dbg->is_remote() || strcmp(dbg->name, "win32") != 0) )
  {
    // a debugger is loaded, but it's not a remote win32
    warning("Loading PDB symbols requires a remote win32 debugger. Please stop the current debugging session and try again.");
    return false;
  }
  if ( get_process_state() != DSTATE_NOTASK )
  {
    // the debugger is already connected
    was_connected = true;
    return true;
  }
  if ( !load_debugger("win32", true) || dbg == NULL )
  {
    warning("Could not load remote Win32 debugger.");
    return false;
  }

  char server[MAXSTR];
  qstrncpy(server, host[0] != '\0' ? host : "localhost", sizeof(server));

  char pass[MAXSTR];
  if ( pwd != NULL )
    qstrncpy(pass, pwd, sizeof(pass));
  else
    pass[0] = '\0';

  while ( !dbg->init_debugger(server, port, pass) )
  {
    if ( batch ) // avoid endless (and useless) loop in batch mode
      return false;
    // hrw
    static const char formstr[] =
      "Remote PDB server\n"
      "In order to load PDB information, IDA requires a running win32_remote.exe debugger server\n"
      "running on a Windows host, but it could not connect to the win32_remote.exe debugger\n"
      "at the current specified address.\n"
      "Please make sure that win32_remote.exe is running there.\n\n"
      "<#Name of the remote host#~H~ostname :A:1023:30::> <#Remote port number#Po~r~t:D:256:8::>\n"
      "<#Password for the remote host#Pass~w~ord :A:1023:30::>\n"
      "Hint: to change this permanently, edit pdb.cfg.\n\n";
    uval_t sport = port;
    int r = AskUsingForm_c(formstr, server, &sport, pass);
    if ( r != 1 )
      return false;
    port = sport;
  }
  msg("PDB: successfully connected to %s\n", server);
  return true;
}


//----------------------------------------------------------------------------
HRESULT remote_pdb_access_t::open_connection()
{
  // Load win32 debugger (FIXME: Should just use an RPC client, not a full debugger!)
  if ( !load_win32_debugger() )
    return S_FALSE;

  // Init remote.
  bytevec_t oper;
  append_memory(oper, &inf.cc, sizeof(inf.cc));
  append_str(oper, pdbargs.pdb_path);
  append_str(oper, pdbargs.input_path);
  append_memory(oper, &pdbargs.pdb_sign, sizeof(pdbargs.pdb_sign));
  append_str(oper, pdbargs.spath);
  append_ea64(oper, get_base_address());
  append_dd(oper, pdbargs.flags);
  ioctl_pdb_code_t code = perform_op(WIN32_IOCTL_PDB_OPEN, oper, NULL);
  if ( code != pdb_ok )
    return E_FAIL;

  connection_is_open = true;
  return S_OK;
}


//----------------------------------------------------------------------------
ioctl_pdb_code_t remote_pdb_access_t::send_ioctl(
        int fn,
        const void *buf,
        size_t size,
        void **outbuf,
        ssize_t *outsz)
{
  if ( dbg == NULL )
    return pdb_error;

  return ioctl_pdb_code_t(dbg->send_ioctl(fn, buf, size, outbuf, outsz));
}


//----------------------------------------------------------------------------
HRESULT remote_pdb_access_t::do_iterate_children(
        pdb_sym_t &sym,
        enum SymTagEnum type,
        children_visitor_t &visitor)
{
  sym_data_t *symbol;
  ioctl_pdb_code_t code = get_sym_data(sym, &symbol);
  QASSERT(30205, code == pdb_ok);
  QASSERT(30206, type < SymTagMax);
  sym_data_t::children_t &children = symbol->children_infos[type];
  if ( children.ids == NULL )
  {
    qvector<DWORD> children_ids;
    code = fetch_children_infos(sym, type, &children_ids);
    if ( code == pdb_ok )
    {
      children.cnt = children_ids.size();
      children.ids = children_ids.extract();
    }
  }

  HRESULT hr = E_FAIL;
  if ( code == pdb_ok )
  {
    hr = S_OK;
    const DWORD *ptr = children.ids;
    for ( uint32 i = 0, n = children.cnt; i < n; ++i, ++ptr )
    {
      DWORD tag;
      pdb_sym_t cur(*this, *ptr);
      if ( type == SymTagNull
        || cur.get_symTag(&tag) == S_OK && tag == type )
      {
        hr = visitor.visit_child(cur);
        if ( FAILED(hr) )
          break;
      }
    }
  }
  return hr;
}

//----------------------------------------------------------------------------
HRESULT remote_pdb_access_t::load(pdb_sym_t &sym, DWORD id)
{
  sym_data_t *sd;
  if ( get_sym_data(id, &sd) != pdb_ok )
    return E_FAIL;
  sym.set_symbol_data(sd);
  return S_OK;
}

//----------------------------------------------------------------------------
DWORD remote_pdb_access_t::build_and_register_sym_data(
        const uchar **raw,
        const uchar *end)
{
  DWORD     child_sym = unpack_dd(raw, end);
  token_mask_t tokens = unpack_dd(raw, end);
  uint32       datasz = unpack_dd(raw, end);
  const uchar *data = (const uchar *)unpack_obj_inplace(raw, end, datasz);
  cache[child_sym] = new sym_data_t(tokens, data, datasz, SYMDAT_PACKED);
  return child_sym;
}

//----------------------------------------------------------------------------
void remote_pdb_access_t::handle_fetch_response(
        const uchar **ptr,
        const uchar *end,
        qvector<DWORD> *ids_storage)
{
  // Build cache!
  uint32 nchildren = 0;
  unpack_obj(ptr, end, &nchildren, sizeof(nchildren));
  if ( ids_storage != NULL )
    ids_storage->reserve(nchildren);
  for ( uint32 i = 0; i < nchildren; i++ )
  {
    DWORD created = build_and_register_sym_data(ptr, end);
    if ( ids_storage != NULL )
      ids_storage->push_back(created);
  }
}

//----------------------------------------------------------------------------
ioctl_pdb_code_t remote_pdb_access_t::perform_op(
        int op_type,
        const bytevec_t &oper,
        void *data)
{
#define REPORT_ERROR(msg)                       \
  do                                            \
  {                                             \
    if ( outbuf != NULL )                       \
    {                                           \
      qfree(outbuf);                            \
      outbuf = NULL;                            \
    }                                           \
    qstrncpy(errbuf, msg, sizeof(errbuf));      \
    return pdb_error;                           \
  } while ( false )

  void *outbuf = NULL;
  ssize_t outsize = 0;
  ioctl_pdb_code_t rc = send_ioctl(op_type, oper.begin(), oper.size(), &outbuf, &outsize);
  if ( rc != pdb_ok )
    REPORT_ERROR("PDB symbol extraction is not supported by the remote server");

  // If operation is OPEN, then the result is delayed.
  // We need to start polling for completeness.
  if ( op_type == WIN32_IOCTL_PDB_OPEN )
  {
    // Now, do the polling game.
    bool done = false;
    while ( !done )
    {
      qfree(outbuf);
      outbuf = NULL;
      qsleep(100);
      wasBreak(); // refresh the output window
      rc = send_ioctl(WIN32_IOCTL_PDB_OPERATION_COMPLETE, NULL, 0, &outbuf, &outsize);
      switch ( rc )
      {
        case pdb_operation_complete:
          done = true;
          break;
        case pdb_operation_incomplete:
          break;
        case pdb_error:
          {
            const uchar *ptr = (const uchar *)outbuf;
            const uchar *end = ptr + outsize;
            const char *errmsg = unpack_str(&ptr, end);
            REPORT_ERROR(errmsg);
            // if opening pdb fails, win32_remote closes the pdb connection
            // automatically
            connection_is_open = false;
          }
        default:
          return pdb_error;
      }
    }
  }

  // msg(" ok\n");

  // By now, the operation will be done. Let's parse the contents
  // of the output buffer.
  const uchar *ptr = (const uchar *)outbuf;
  const uchar *end = ptr + outsize;
  switch ( op_type )
  {
    case WIN32_IOCTL_PDB_OPEN:
      {
        set_global_symbol_id(unpack_dd(&ptr, end));
        set_machine_type(unpack_dd(&ptr, end));
        set_dia_version(unpack_dd(&ptr, end));
        const char *fname = unpack_str(&ptr, end);
        msg("PDB: opened %s\n", fname);
      }
      break;
    case WIN32_IOCTL_PDB_FETCH_SYMBOL:
    case WIN32_IOCTL_PDB_FETCH_CHILDREN:
      QASSERT(30207, outsize >= (4 /*(unpacked) nchildren*/));
      handle_fetch_response(&ptr, end, (qvector<DWORD> *)data);
      break;
    default:
      INTERR(30208);
  }

  qfree(outbuf);

  return pdb_ok;
}

//----------------------------------------------------------------------------
ioctl_pdb_code_t remote_pdb_access_t::fetch_children_infos(
        pdb_sym_t &sym,
        enum SymTagEnum type,
        qvector<DWORD> *children_ids)
{
  bytevec_t oper;
  append_dd(oper, sym.data->get_id());
  append_dd(oper, type);
  // msg("Fetching children: 0x%x", sym);
  return perform_op(WIN32_IOCTL_PDB_FETCH_CHILDREN, oper, children_ids);
}

//----------------------------------------------------------------------------
sym_data_t *remote_pdb_access_t::get_sym_data_from_cache(DWORD id)
{
  typedef std::map<DWORD,sym_data_t*>::const_iterator citer;
  citer it = cache.find(id);
  if ( it != cache.end() )
    return it->second;
  return NULL;
}

//----------------------------------------------------------------------------
ioctl_pdb_code_t remote_pdb_access_t::get_sym_data(pdb_sym_t &sym, sym_data_t **out)
{
  DWORD id = sym.data->get_id();
  return get_sym_data(id, out);
}

//----------------------------------------------------------------------------
ioctl_pdb_code_t remote_pdb_access_t::get_sym_data(DWORD id, sym_data_t **out)
{
  sym_data_t *found = get_sym_data_from_cache(id);
  if ( found != NULL )
  {
    *out = found;
    return pdb_ok;
  }
  else
  {
    bytevec_t oper;
    append_dd(oper, id);
    ioctl_pdb_code_t rc = perform_op(WIN32_IOCTL_PDB_FETCH_SYMBOL, oper, NULL);
    if ( rc == pdb_ok )
    {
      rc = get_sym_data(id, out);
      QASSERT(30209, rc == pdb_ok);
    }
    return rc;
  }
}
