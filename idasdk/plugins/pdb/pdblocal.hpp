
#ifndef PDBLOCAL_HPP
#define PDBLOCAL_HPP

// The PDB related code that works on Windows and uses DIA

//----------------------------------------------------------------------------
class local_pdb_access_t : public pdb_access_t
{
public:
  local_pdb_access_t(
        const pdbargs_t &args,
        IDiaDataSource *pSource,
        IDiaSession *pSession,
        IDiaSymbol *pGlobal)
    : pdb_access_t(args),
      dia_source(pSource),
      dia_session(pSession),
      dia_global(pGlobal)
  {
  }

  virtual ~local_pdb_access_t()
  {
#define RELEASE(thing) do { if ( thing != NULL ) { (thing)->Release(); thing = NULL; } } while ( false )
    RELEASE(dia_global);
    RELEASE(dia_session);
    RELEASE(dia_source);
#undef RELEASE
    set_global_symbol_id(BADSYM);
  }

  HRESULT init()
  {
    DWORD id;
    HRESULT hr = dia_global->get_symIndexId(&id);
    if ( hr != S_OK )
      return hr;
    set_global_symbol_id(id);

    DWORD64 load_addr;
    hr = dia_session->get_loadAddress(&load_addr);
    if ( hr != S_OK )
      return hr;
    set_base_address(load_addr);

    return S_OK;
  }

  virtual HRESULT do_iterate_children(
        pdb_sym_t &sym,
        enum SymTagEnum type,
        children_visitor_t &visitor);
  virtual HRESULT load(pdb_sym_t &sym, DWORD id);

  IDiaDataSource *dia_source;
  IDiaSession    *dia_session;
  IDiaSymbol     *dia_global;

private:
  HRESULT _do_iterate_children(
        pdb_sym_t &sym,
        enum SymTagEnum type,
        children_visitor_t &visitor);
  DECLARE_UNCOPYABLE(local_pdb_access_t)
};


#endif // PDBLOCAL_HPP
