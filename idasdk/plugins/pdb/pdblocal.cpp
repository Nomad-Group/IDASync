
#ifdef __NT__

#include "pdblocal.hpp"

//----------------------------------------------------------------------------
template <typename T>
struct dia_ptr_t
{
  dia_ptr_t() : thing(NULL) {}

  ~dia_ptr_t()
  {
    if ( thing != NULL )
      thing->Release();
  }

  T *thing;
};

//----------------------------------------------------------------------------
HRESULT local_pdb_access_t::_do_iterate_children(
        pdb_sym_t &sym,
        enum SymTagEnum type,
        children_visitor_t &visitor)
{
  std::set<DWORD> seen;
  dia_ptr_t<IDiaEnumSymbols> pEnumSymbols;
  HRESULT hr = dia_session->findChildren(sym.data, type, NULL, nsNone, &pEnumSymbols.thing);
  if ( hr == S_OK )
  {
    while ( true )
    {
      ULONG celt = 0;
      IDiaSymbol *pChild = NULL;
      hr = pEnumSymbols.thing->Next(1, &pChild, &celt);
      if ( FAILED(hr) || celt != 1 )
      {
        hr = S_OK; // end of enumeration
        break;
      }
      pdb_sym_t child(*this, pChild, true);
      DWORD sym_id;
      hr = child.get_symIndexId(&sym_id);
      if ( hr != S_OK )
        break;
      // It seems we can, in some cases, iterate over the
      // same child more than once.
      // Fortunately, it appears to be the same symbol data;
      // and not another symbol w/ the same ID
      if ( seen.insert(sym_id).second )
      {
        hr = visitor.visit_child(child);
        if ( FAILED(hr) )
          break;
      }
    }
  }
  return hr;
}

//----------------------------------------------------------------------------
HRESULT local_pdb_access_t::do_iterate_children(
        pdb_sym_t &sym,
        enum SymTagEnum type,
        children_visitor_t &visitor)
{
  int code;
  HRESULT hr = E_FAIL;
  __try
  {
    hr = _do_iterate_children(sym, type, visitor);
  }
  __except ( code=GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER )
  {
    ask_for_feedback(
            "%s: %s\n"
            "Is the corresponding PDB file valid?",
            pdbargs.input_path.c_str(),
            winerr(code));
    error(NULL);
  }
  return hr;
}

//----------------------------------------------------------------------------
HRESULT local_pdb_access_t::load(pdb_sym_t &sym, DWORD id)
{
  IDiaSymbol *dia_sym;
  HRESULT hr = dia_session->symbolById(id, &dia_sym);
  if ( hr == S_OK )
    sym.set_symbol(dia_sym, true);
  return hr;
}

#endif // __NT__


