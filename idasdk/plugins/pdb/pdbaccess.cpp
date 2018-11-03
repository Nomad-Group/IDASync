
#include "pdbaccess.hpp"
#include "misc.cpp"

//----------------------------------------------------------------------------
pdb_sym_t::pdb_sym_t(pdb_access_t *_pdb_access, DWORD _sym_id)
  : pdb_access(_pdb_access)
{
  if ( pdb_access->load(*this, _sym_id) != S_OK )
  {
    qstring err;
    err.sprnt("Failed loading symbol data for ID %u", _sym_id);
    throw pdb_exception_t(err.c_str());
  }
}

//-------------------------------------------------------------------------
void pdb_sym_t::steal_data(pdb_sym_t &other)
{
#ifdef __NT__
  QASSERT(30503, other.own_sym && other.data != NULL && data == NULL);
  data = other.data;
  own_sym = other.own_sym;
  other.own_sym = false;
  other.data = NULL;
#else
  QASSERT(30492, other.data != NULL && data == NULL);
  data = other.data;
  // we don't want to set 'other.data = NULL', because in remote access,
  // the pdb_sym_t doesn't actually own the data anyway: it's part of
  // the cache.
#endif
}

//----------------------------------------------------------------------------
HRESULT pdb_access_t::iterate_subtags(
        pdb_sym_t &sym,
        enum SymTagEnum type,
        children_visitor_t &visitor)
{
  struct subtag_helper_t : children_visitor_t
  {
    pdb_access_t *tb;
    enum SymTagEnum type;
    children_visitor_t &visitor;
    virtual HRESULT visit_child(pdb_sym_t &_sym)
    {
      return tb->iterate_children(_sym, type, visitor);
    }
    subtag_helper_t(pdb_access_t *_tb, enum SymTagEnum t, children_visitor_t &_visitor)
      : tb(_tb),
        type(t),
        visitor(_visitor) {}
  };
  subtag_helper_t helper(this, type, visitor);
  return iterate_children(sym, SymTagCompiland, helper);
}

//----------------------------------------------------------------------------
HRESULT pdb_access_t::iterate_children(
        pdb_sym_t &sym,
        enum SymTagEnum type,
        children_visitor_t &visitor)
{
  visitor.parent = &sym;
  return do_iterate_children(sym, type, visitor);
}
