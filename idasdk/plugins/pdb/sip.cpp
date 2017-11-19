
#include "pdbreg.hpp"
#include "pdb.hpp"
#include "tilbuild.hpp"


//--------------------------------------------------------------------------
// Implementation of source information provider using PDB information
// and the DIA SDK

//--------------------------------------------------------------------------
// Information about a PDB module. Contains pointer to IDiaSession
// as well as a type cache, that'll last the same time as the
// DIA session.
struct pdb_modinfo_t
{
  pdb_modinfo_t(): type_cache(NULL) { }

  ~pdb_modinfo_t()
  {
    if ( type_cache != NULL )
      delete type_cache;
  }

  HRESULT open(const char *input_file, const char *user_spath, ea_t load_address)
  {
    QASSERT(30212, type_cache == NULL);
    pdbargs_t args;
    args.input_path = input_file;
    args.spath = user_spath;
    args.loaded_base = load_address;
    HRESULT hr = pdbref.open_session(args);
    if ( SUCCEEDED(hr) )
    {
      type_cache = new til_builder_t(idati, NULL);
      type_cache->set_pdb_access(pdbref.session->pdb_access);
    }
    return hr;
  }

  IDiaSession *get_session()
  {
    return pdbref.session->pdb_access->dia_session;
  }

  qstring path;
  ea_t base;
  asize_t size;
  bool opened;
  pdb_session_ref_t pdbref;
  til_builder_t *type_cache;
};
typedef std::map<ea_t, pdb_modinfo_t> pdb_modules_t;

//--------------------------------------------------------------------------
// Vector to hold DIA session and source file enumerator
struct pdb_fileenum_t
{
  pdb_modinfo_t *pdb_module;
  IDiaEnumSourceFiles *enumerator;
};
typedef qvector<pdb_fileenum_t> fileenumvec_t;

//--------------------------------------------------------------------------
typedef qvector<IDiaLineNumber *> lnvec_t;
typedef std::map<int, lnvec_t> lnmap_t;

//-------------------------------------------------------------------------
static bool get_pdb_register_info(int *p_reg, uint64 *p_mask, int machine, int reg)
{
  const char *name = print_pdb_register(machine, reg);
  if ( name == NULL )
    return false;
  reg_info_t ri;
  if ( !parse_reg_name(name, &ri) )
    return false;
  *p_reg = ri.reg;
  *p_mask = left_shift(uint64(1), 8*ri.size) - 1;
  return true;
}

//--------------------------------------------------------------------------
class pdb_symbol_t;

static pdb_symbol_t *new_pdb_symbol(
    pdb_modinfo_t *pdb_module,
    IDiaSymbol *sym,
    src_item_kind_t desired_kind=SRCIT_NONE);

//--------------------------------------------------------------------------
struct pdb_source_file_t : public source_file_t
{
  pdb_modinfo_t *pdb_module;
  IDiaSourceFile *file;
  qstring res;

  pdb_source_file_t(pdb_modinfo_t *_pdb_module, IDiaSourceFile *f)
    : pdb_module(_pdb_module),
      file(f) {}

  srcinfo_provider_t *idaapi get_provider(void) const;
  virtual ~pdb_source_file_t(void)
  {
    file->Release();
  }

  virtual void idaapi release() { delete this; }

  const char *idaapi get_path(qstring *errbuf)
  {
    BSTR filename;
    HRESULT hr = file->get_fileName(&filename);
    if ( FAILED(hr) )
    {
      if ( errbuf != NULL )
        *errbuf = winerr(hr);
      return NULL;
    }
    u2cstr(filename, &res);
    SysFreeString(filename);
    return res.c_str();
  }

  bool idaapi read_file(strvec_t *buf, qstring *errbuf)
  {
    buf->clear();
    const char *path = get_path(errbuf);
    if ( path == NULL )
      return false;

    // Always favor file mapping first.
    qstring mapbuf = path;
    callui(ui_dbg_map_source_path, &mapbuf);
    path = mapbuf.c_str();

    if ( !qfileexist(path) )
    {
      if ( errbuf != NULL )
        errbuf->sprnt("source file not found: %s", path);
      return false;
    }

    FILE *fp = fopenRT(path);
    if ( fp == NULL )
    {
      if ( errbuf != NULL )
        *errbuf = get_errdesc(path);
      return false;
    }

    char line[MAXSTR];
    int tabsize = get_tab_size(path);
    while ( qfgets(line, sizeof(line), fp) )
    {
      size_t len = strlen(line);
      if ( len > 0 && line[len-1] == '\n' )
        line[len-1] = '\0';

      simpleline_t &sl = buf->push_back();
      sl.line.clear();
      replace_tabs(&sl.line, line, tabsize);
    }

    qfclose(fp);
    return true;
  }

  TForm *open_srcview(strvec_t ** /*strvec*/, TCustomControl ** /*pview*/, int, int)
  {
    return NULL;
  }
};

//--------------------------------------------------------------------------
class pdb_file_iterator : public _source_file_iterator
{
  // We have a vector of source file enumerators
  fileenumvec_t files;

  // Enumerator index
  int idx;

  // Current source file item
  IDiaSourceFile *file;
public:

  pdb_file_iterator(fileenumvec_t *fv)
  {
    fv->swap(files);
    file = NULL;
  }

  virtual ~pdb_file_iterator(void)
  {
    for ( int i=0; i < files.size(); i++ )
      files[i].enumerator->Release();

    if ( file != NULL )
      file->Release();
  }

  void idaapi release(void) { delete this; }

  bool idaapi first(void)
  {
    idx = 0;
    if ( files.empty() )
      return false;
    files[0].enumerator->Reset();
    return next();
  }

  bool idaapi next(void)
  {
    if ( idx >= files.size() )
      return false;

    // Free previous item
    if ( file != NULL )
    {
      file->Release();
      file = NULL;
    }

    while ( true )
    {
      // Get next source file in this enumerator
      ULONG celt = 0;
      if ( SUCCEEDED(files[idx].enumerator->Next(1, &file, &celt)) && celt > 0 )
        break;

      // Advance to next enumerator
      if ( ++idx >= files.size() )
        return false;

      // Rewind enumerator
      files[idx].enumerator->Reset();
    }
    return true;
  }

  source_file_ptr idaapi operator *()
  {
    source_file_t *sf = new pdb_source_file_t(files[idx].pdb_module, file);
    file = NULL;
    return source_file_ptr(sf);
  }
};

//--------------------------------------------------------------------------
// Dummy source item: provides no information.
struct dummy_item_t : public source_item_t
{
  void idaapi release(void) { delete this; }
  virtual ~dummy_item_t(void) {}
  source_file_iterator idaapi get_source_files(void) { return source_file_iterator(NULL); }
  int idaapi get_lnnum() const { return -1; }
  int idaapi get_end_lnnum() const { return -1; }
  int idaapi get_colnum() const { return -1; }
  int idaapi get_end_colnum() const { return -1; }
  ea_t idaapi get_ea() const { return BADADDR; }
  asize_t idaapi get_size() const { return 0; }
  bool idaapi get_item_bounds(areaset_t *set) const
  {
    ea_t ea = get_ea();
    if ( ea == BADADDR )
      return false;
    asize_t size = get_size();
    set->add(area_t(ea, ea+size));
    return true;
  }
  source_item_ptr idaapi get_parent(src_item_kind_t) const { return source_item_ptr(NULL); }
  source_item_iterator idaapi create_children_iterator() { return source_item_iterator(NULL); }
  bool idaapi get_hint(const eval_ctx_t *, qstring *hint, int *nlines) const
  {
    // TODO: remove these test lines
    *hint = "test";
    *nlines = 1;
    return true;
  }
  bool idaapi evaluate(const eval_ctx_t *, idc_value_t *, qstring *) const { return false; }
  // bool idaapi get_stkvar_info(char *, size_t, uval_t *, ea_t) const { return false; }
  // bool idaapi get_regvar_info(char *, size_t) const { return false; }
  // bool idaapi get_rrlvar_info(char *, size_t, uval_t *) const { return false; }
  bool idaapi get_expr_tinfo(tinfo_t *) const { return false; }

  virtual bool idaapi get_location(argloc_t *, const eval_ctx_t *) const { return false; }

  virtual srcinfo_provider_t *idaapi get_provider(void) const;
};

//--------------------------------------------------------------------------
struct pdb_module_t : public dummy_item_t
{
  const pdb_modinfo_t *info;

  pdb_module_t(const pdb_modinfo_t *i) : info(i) {}

  ea_t idaapi get_ea() const
  {
    return info->base;
  }

  asize_t idaapi get_size() const
  {
    return info->size;
  }
};

//--------------------------------------------------------------------------
// helper class to work with lnnum enumerator
// A line number enumerator could be retrieved via dia_session->findLinesByVA for example
class pdb_lnnums_t
{
  int _get_colnum(IDiaLineNumber *lnnum) const
  {
    DWORD n = -1;
    if ( lnnum != NULL )
      lnnum->get_columnNumber(&n);
    return n;
  }

  int _get_lnnum(IDiaLineNumber *lnnum) const
  {
    DWORD n = -1;
    if ( lnnum != NULL )
      lnnum->get_lineNumber(&n);

    return n;
  }

  int _get_end_lnnum(IDiaLineNumber *lnnum) const
  {
    DWORD n = -1;
    if ( lnnum != NULL )
      lnnum->get_lineNumberEnd(&n);
    return n;
  }

public:
  IDiaEnumLineNumbers *enumerator;
  mutable IDiaLineNumber *first_line;
  mutable IDiaLineNumber *last_line;

  bool inited(void) const
  {
    return enumerator != NULL;
  }

  pdb_lnnums_t(IDiaEnumLineNumbers *e=NULL)
    : enumerator(e), first_line(NULL), last_line(NULL)
  {
  }

  ~pdb_lnnums_t(void)
  {
    term();
  }

  void term()
  {
    if ( inited() )
    {
      enumerator->Release();
      enumerator = NULL;
    }

    if ( first_line != NULL )
    {
      first_line->Release();
      first_line = NULL;
    }

    if ( last_line != NULL )
    {
      last_line->Release();
      last_line = NULL;
    }
  }

  IDiaLineNumber *get_first_lnnum_obj(void) const
  {
    if ( first_line == NULL )
      enumerator->Item(0, &first_line);

    return first_line;
  }

  IDiaLineNumber *get_last_lnnum_obj(void) const
  {
    if ( last_line == NULL )
    {
      LONG idx;
      HRESULT hr = enumerator->get_Count(&idx);
      if ( SUCCEEDED(hr) )
        enumerator->Item(--idx, &last_line);
    }
    return last_line;
  }

  bool get_item_bounds(areaset_t *set) const
  {
    if ( enumerator->Reset() != S_OK )
      return false;
    LONG idx = 0;
    if ( enumerator->get_Count(&idx) != S_OK )
      return false;

    IDiaLineNumber *lines[64];
    ULONG got = 0;
    for ( LONG i=0; i < idx; i += got )
    {
      // Fetch many line number information at once
      enumerator->Next(qnumber(lines), lines, &got);
      if ( got == 0 )
        break;

      for ( ULONG j=0; j < got; j++ )
      {
        DWORD length = 0;
        lines[j]->get_length(&length);

        ULONGLONG va = BADADDR;
        lines[j]->get_virtualAddress(&va);

        if ( va != BADADDR && length > 0 )
          set->add(va, va+length);

        lines[j]->Release();
      }
    }
    return !set->empty();
  }

  int idaapi get_lnnum() const
  {
    return _get_lnnum(get_first_lnnum_obj());
  }

  int idaapi get_colnum() const
  {
    return _get_colnum(get_first_lnnum_obj());
  }

  int idaapi get_end_lnnum() const
  {
    return _get_lnnum(get_last_lnnum_obj());
  }

  int idaapi get_end_colnum() const
  {
    return _get_colnum(get_last_lnnum_obj());
  }
};

//--------------------------------------------------------------------------
// source item based on dia symbol
class pdb_symbol_t : public dummy_item_t
{
  pdb_modinfo_t  *pdb_module;
  IDiaSymbol    *sym;
  // cached ptr to line number enumerator
  mutable pdb_lnnums_t lnnums;
  src_item_kind_t kind;

  bool init_lnnums() const
  {
    if ( !lnnums.inited() )
    {
      ULONGLONG va;
      if ( sym->get_virtualAddress(&va) == S_OK )
      {
        ULONGLONG length;
        sym->get_length(&length);
        pdb_module->get_session()->findLinesByVA(va, length, &lnnums.enumerator);
      }
    }
    return lnnums.inited();
  }

public:
  pdb_symbol_t(pdb_modinfo_t *_pdb_module,
               IDiaSymbol *symbol,
               src_item_kind_t k)
    : pdb_module(_pdb_module),
      sym(symbol),
      kind(k)
  {
  }

  virtual ~pdb_symbol_t(void)
  {
    sym->Release();
  }

  source_file_iterator idaapi get_source_files(void)
  {
    pdb_file_iterator *ret = NULL;
    // Retrieve source file name associated with the current symbol
    BSTR path;
    HRESULT hr = sym->get_sourceFileName(&path);
    if ( hr == S_OK ) // can not use SUCCEEDED(hr) because S_OK means success
    {
      IDiaEnumSourceFiles *files;
      hr = pdb_module->get_session()->findFile(NULL, path, nsfFNameExt, &files);
      SysFreeString(path);

      if ( SUCCEEDED(hr) )
      {
        fileenumvec_t fv;
        pdb_fileenum_t &pfenum = fv.push_back();

        pfenum.pdb_module = pdb_module;
        pfenum.enumerator = files;
        ret = new pdb_file_iterator(&fv);
      }
    }
    return source_file_iterator(ret);
  }

  bool idaapi get_name(qstring *buf) const
  {
    BSTR name;
    HRESULT code = sym->get_name(&name);
    if ( FAILED(code) )
      return false;
    u2cstr(name, buf);
    SysFreeString(name);
    return true;
  }

  int idaapi get_lnnum() const
  {
    return init_lnnums() ? lnnums.get_lnnum() : 0;
  }

  int idaapi get_end_lnnum() const
  {
    return init_lnnums() ? lnnums.get_end_lnnum() : 0;
  }

  int idaapi get_colnum() const
  {
    return init_lnnums() ? lnnums.get_colnum() : 0;
  }

  int idaapi get_end_colnum() const
  {
    if ( !init_lnnums() )
      return 0;
    return lnnums.get_end_colnum();
  }

  ea_t idaapi get_ea() const
  {
    ULONGLONG va;
    return FAILED(sym->get_virtualAddress(&va)) ? BADADDR : va;
  }

  asize_t idaapi get_size() const
  {
    ULONGLONG len;
    return FAILED(sym->get_length(&len)) ? BADADDR : len;
  }

  bool idaapi get_item_bounds(areaset_t *set) const
  {
    return init_lnnums() ? lnnums.get_item_bounds(set) : false;
  }

  source_item_ptr idaapi get_parent(src_item_kind_t /*max_kind*/) const
  {
    pdb_symbol_t *ret = NULL;
    IDiaSymbol *parent;
    HRESULT hr = sym->get_lexicalParent(&parent);
    if ( SUCCEEDED(hr) )
      ret = new_pdb_symbol(pdb_module, parent);

    return source_item_ptr(ret);
  }

  source_item_iterator idaapi create_children_iterator();

  // TODO: not implemented yet
  /*bool idaapi get_hint(const eval_ctx_t *ctx, qstring *hint, int *nlines) const
  {
    return false;
  }*/

  bool idaapi evaluate(const eval_ctx_t * /*ctx*/, idc_value_t * /*res*/, qstring * /*errbuf*/) const
  {
    // not implemented yet
    return false;
  }

  virtual src_item_kind_t idaapi get_item_kind() const
  {
    return kind;
  }

  virtual src_item_kind_t idaapi get_kind(const eval_ctx_t * /*ctx*/) const
  {
    return kind;
  }

  virtual bool idaapi get_location(argloc_t *out, const eval_ctx_t *) const
  {
    DWORD loctype = LocIsNull;
    HRESULT hr = sym->get_locationType(&loctype);
    if ( !SUCCEEDED(hr) )
      return false;
    bool ok = false;
    int machine = pdb_module->pdbref.session->pdb_access->get_machine_type();
    switch ( loctype )
    {
      case LocIsRegRel:
        {
          DWORD dwReg = 0;
          LONG lOffset;
          if ( sym->get_registerId(&dwReg) == S_OK
            && sym->get_offset(&lOffset) == S_OK )
          {
            int regno;
            uint64 mask;
            if ( get_pdb_register_info(&regno, &mask, machine, dwReg) )
            {
              rrel_t *rrel = new rrel_t();
              rrel->reg = regno;
              rrel->off = lOffset;
              out->consume_rrel(rrel);
              ok = true;
            }
          }
        }
        break;
      case LocIsEnregistered:
        {
          DWORD dwReg = 0;
          if ( sym->get_registerId(&dwReg) == S_OK )
          {
            int regno;
            uint64 mask;
            if ( get_pdb_register_info(&regno, &mask, machine, dwReg) )
            {
              out->set_reg1(regno, 0); // off=0?
              ok = true;
            }
          }
        }
        break;
      default:
        break;
    }
    return ok;
  }

  bool idaapi get_expr_tinfo(tinfo_t *tif) const
  {
    pdb_sym_t pdbsym(*pdb_module->type_cache->pdb_access, sym, false);
    til_builder_t::tpinfo_t tpi;
    bool res = pdb_module->type_cache->retrieve_type(&tpi, pdbsym, NULL, NULL);

    *tif = tpi.type;

    if ( (debug & IDA_DEBUG_SRCDBG) != 0 )
    {
      qstring type_str;
      tpi.type.print(&type_str);
      DWORD sym_id;
      pdbsym.get_symIndexId(&sym_id);
      qstring name;
      deb(IDA_DEBUG_SRCDBG, "Retrieved type for %s (symbol #%u): %s\n",
          get_name(&name) ? name.c_str() : "<unnamed>",
          sym_id,
          type_str.c_str());
    }

    return res;
  }

  bool idaapi equals(const source_item_t *othr) const
  {
    DWORD this_id, other_id;
    pdb_symbol_t *other = (pdb_symbol_t*) othr;
    return other != NULL
        && other->sym != NULL
        && sym->get_symIndexId(&this_id) == S_OK
        && other->sym->get_symIndexId(&other_id) == S_OK
        && this_id == other_id;
  }
};

//--------------------------------------------------------------------------
class pdb_item_iterator : public _source_item_iterator
{
  pdb_modinfo_t *pdb_module;
  IDiaEnumSymbols *pEnumSymbols;
  IDiaSymbol *item;
public:

  pdb_item_iterator(pdb_modinfo_t *_pdb_module, IDiaEnumSymbols *p)
    : pdb_module(_pdb_module), pEnumSymbols(p), item(NULL)
  {
  }

  virtual ~pdb_item_iterator(void)
  {
    pEnumSymbols->Release();
    if ( item != NULL )
      item->Release();
  }

  void idaapi release(void)
  {
    delete this;
  }

  bool idaapi first(void)
  {
    pEnumSymbols->Reset();
    return next();
  }

  bool idaapi next(void)
  {
    if ( item != NULL )
    {
      item->Release();
      item = NULL;
    }

    ULONG celt = 0;
    HRESULT hr = pEnumSymbols->Next(1, &item, &celt);
    return SUCCEEDED(hr) && celt == 1;
  }

  source_item_ptr idaapi operator *()
  {
    source_item_t *si = new_pdb_symbol(pdb_module, item);
    item = NULL;
    return source_item_ptr(si);
  }
};

//--------------------------------------------------------------------------
source_item_iterator idaapi pdb_symbol_t::create_children_iterator()
{
  pdb_item_iterator *ret = NULL;
  IDiaEnumSymbols *pEnumSymbols;
  HRESULT hr = sym->findChildren(SymTagNull, NULL, nsNone, &pEnumSymbols);
  if ( SUCCEEDED(hr) )
    ret = new pdb_item_iterator(pdb_module, pEnumSymbols);

  return source_item_iterator(ret);
}

//--------------------------------------------------------------------------
// source file iterator
class pdb_single_file_iterator : public _source_file_iterator
{
  pdb_modinfo_t *pdb_module;
  IDiaSourceFile *file;

public:

  pdb_single_file_iterator(pdb_modinfo_t *_pdb_module, IDiaSourceFile *f)
    : pdb_module(_pdb_module), file(f)
  {
  }

  virtual ~pdb_single_file_iterator(void)
  {
    if ( file != NULL )
      file->Release();
  }

  void idaapi release(void)
  {
    delete this;
  }

  bool idaapi first(void)
  {
    return file != NULL;
  }

  bool idaapi next(void)
  {
    return false;
  }

  source_file_ptr idaapi operator *()
  {
    source_file_t *sf = new pdb_source_file_t(pdb_module, file);
    file = NULL;
    return source_file_ptr(sf);
  }
};

//--------------------------------------------------------------------------
class pdb_lnnum_item_t : public dummy_item_t
{
  pdb_modinfo_t *pdb_module;
  IDiaLineNumber *lnnum;        // we do not own this pointer

public:
  pdb_lnnum_item_t(pdb_modinfo_t *_pdb_module, IDiaLineNumber *l)
    : pdb_module(_pdb_module),
      lnnum(l) {}

  virtual ~pdb_lnnum_item_t(void) {}

  source_file_iterator idaapi get_source_files(void)
  {
    pdb_single_file_iterator *ret = NULL;
    IDiaSourceFile *file;
    HRESULT hr = lnnum->get_sourceFile(&file);
    if ( SUCCEEDED(hr) )
      ret = new pdb_single_file_iterator(pdb_module, file);
    return source_file_iterator(ret);
  }

  bool idaapi get_name(qstring *) const
  {
    return false;
  }

  int idaapi get_lnnum() const
  {
    DWORD n = -1;
    lnnum->get_lineNumber(&n);
    return n;
  }

  int idaapi get_end_lnnum() const
  {
    DWORD n = -1;
    lnnum->get_lineNumberEnd(&n);
    return n;
  }

  int idaapi get_colnum() const
  {
    DWORD n = -1;
    lnnum->get_columnNumber(&n);
    return n;
  }

  int idaapi get_end_colnum() const
  {
    DWORD n = -1;
    lnnum->get_columnNumberEnd(&n);
    return n;
  }

  ea_t idaapi get_ea() const
  {
    ULONGLONG va = BADADDR;
    lnnum->get_virtualAddress(&va);
    return va;
  }

  asize_t idaapi get_size() const
  {
    DWORD len = 0;
    lnnum->get_length(&len);
    return len;
  }

  virtual src_item_kind_t idaapi get_item_kind() const
  {
    BOOL is_stmt = false;
    lnnum->get_statement(&is_stmt);
    return is_stmt ? SRCIT_STMT : SRCIT_EXPR;
  }

  virtual src_item_kind_t idaapi get_kind(const eval_ctx_t * /*ctx*/) const
  {
    return get_item_kind();
  }

  source_item_ptr idaapi get_parent(src_item_kind_t /*max_kind*/) const
  {
    source_item_t *ret = NULL;
    ea_t ea = get_ea();
    if ( ea != BADADDR )
    {
      // ;! we assume that the parent of a statement/expression is a function
      // i do not know how to get an enclosing block. if it is possible, we could
      // return it too
      LONG disp;
      IDiaSymbol *sym;
      HRESULT hr = pdb_module->get_session()->findSymbolByVAEx(ea, SymTagFunction, &sym, &disp);
      if ( SUCCEEDED(hr) )
        ret = new_pdb_symbol(pdb_module, sym);
    }
    return source_item_ptr(ret);
  }

  bool idaapi equals(const source_item_t *othr) const
  {
    ULONGLONG this_va, other_va;
    pdb_lnnum_item_t *other = (pdb_lnnum_item_t*) othr;
    return other != NULL
        && other->lnnum != NULL
        && lnnum->get_virtualAddress(&this_va) == S_OK
        && other->lnnum->get_virtualAddress(&other_va) == S_OK
        && this_va == other_va;
  }
};

//--------------------------------------------------------------------------
static pdb_symbol_t *new_pdb_symbol(
        pdb_modinfo_t *pdb_module,
        IDiaSymbol *sym,
        src_item_kind_t desired_kind)
{
  DWORD tag;
  HRESULT hr = sym->get_symTag(&tag);
  if ( SUCCEEDED(hr) )
  {
    src_item_kind_t kind = SRCIT_NONE;
    switch ( tag )
    {
      case SymTagFunction:
        kind = SRCIT_FUNC;
        break;

      case SymTagBlock:
        kind = SRCIT_STMT;
        break;

      case SymTagData:
      case SymTagPublicSymbol:
        {
          DWORD loctype = LocIsNull;
          sym->get_locationType(&loctype);
          switch ( loctype )
          {
            case LocIsStatic:
            case LocIsTLS:
              kind = SRCIT_STTVAR;
              break;

            case LocIsRegRel:
              DWORD dwReg;
              if ( sym->get_registerId(&dwReg) == S_OK
                && (dwReg == CV_REG_EBP || dwReg == CV_AMD64_RSP) )
                kind = SRCIT_LOCVAR;
              break;

            case LocIsEnregistered:
              kind = SRCIT_LOCVAR;
              break;
          }
        }
        break;
    }

    if ( kind != SRCIT_NONE )
    {
      if ( desired_kind == SRCIT_NONE || kind == desired_kind )
        return new pdb_symbol_t(pdb_module, sym, kind);
    }
  }
  sym->Release();
  return NULL;
}

//--------------------------------------------------------------------------
class pdb_provider_t : public srcinfo_provider_t
{
  pdb_modules_t modules;
  qstring search_path;
  pdb_modinfo_t *open_module(pdb_modules_t::iterator p)
  {
    pdb_modinfo_t &mod = p->second;
    if ( !mod.opened )
    {
      msg("PDBSRC: loading symbols for '%s'...\n", mod.path.c_str());
      HRESULT hr = mod.open(mod.path.c_str(), search_path.c_str(), mod.base);
      if ( !SUCCEEDED(hr) )
      { // failed to open the corresponding pdb file
        modules.erase(p);
        return NULL;
      }
      mod.opened = true;
    }
    return &mod;
  }
  pdb_modinfo_t *find_module(ea_t ea)
  {
    pdb_modules_t::iterator p = modules.lower_bound(ea);
    if ( p == modules.end() || p->first > ea )
    {
      if ( p == modules.begin() )
        return NULL; // could not find the module

      --p;
      if ( p->first > ea || p->first+p->second.size <= ea )
        return NULL;
    }
    return open_module(p);
  }

public:
  bool idaapi enable_provider(bool enable);
  const char *idaapi set_options(const char *keyword, int value_type, const void *value);
  void idaapi add_module(const char *path, ea_t base, asize_t size);
  void idaapi del_module(ea_t base);
  void idaapi get_ready(void);
  int idaapi get_change_flags(void);
  source_item_iterator idaapi find_source_items(ea_t ea, asize_t size, src_item_kind_t level, bool);
  source_item_iterator idaapi find_source_items(source_file_t *sf, int lnnum, int colnum);
  source_file_iterator idaapi create_file_iterator(const char *filename);
  source_item_iterator idaapi create_item_iterator(const source_file_t *sf);
  pdb_provider_t(const char *name, const char *display_name)
    : srcinfo_provider_t(name, display_name) {}
  virtual ~pdb_provider_t(void) {}
};

//--------------------------------------------------------------------------
bool idaapi pdb_provider_t::enable_provider(bool enable)
{
  if ( enable )
  {
    init_sympaths();
    if ( full_sympath[0] != '\0' )
      search_path = full_sympath;
    else
      search_path.qclear();
  }
  return true;
}

//--------------------------------------------------------------------------
const char *idaapi pdb_provider_t::set_options(
        const char * /*keyword*/,
        int /*value_type*/,
        const void * /*value*/)
{
  // todo: add option to set search path
  return IDPOPT_BADKEY;
}

//--------------------------------------------------------------------------
void idaapi pdb_provider_t::add_module(
        const char *path,
        ea_t base,
        asize_t size)
{
  pdb_modinfo_t &mod = modules[base];
  mod.path = path;
  mod.base = base;
  mod.size = size;
  // do not open the module immediately, we will do it only when we
  // really need the module
  mod.opened     = false;
  mod.type_cache = NULL;
}


//--------------------------------------------------------------------------
void idaapi pdb_provider_t::del_module(ea_t base)
{
  modules.erase(base);
}

//--------------------------------------------------------------------------
void idaapi pdb_provider_t::get_ready(void)
{
  // nothing to do
}

//--------------------------------------------------------------------------
int idaapi pdb_provider_t::get_change_flags(void)
{
  // nothing ever changes?
  return 0;
}

//--------------------------------------------------------------------------
static void clear_lnmap(lnmap_t *lnmap)
{
  for ( lnmap_t::iterator p=lnmap->begin(); p != lnmap->end(); ++p )
  {
    lnvec_t &vec = p->second;
    for ( int i=0; i < vec.size(); i++ )
      vec[i]->Release();
  }
}

//--------------------------------------------------------------------------
class pdb_global_item_iterator : public _source_item_iterator
{
  pdb_modinfo_t *pdb_module;
  ea_t ea, cur;
  asize_t size;
  enum SymTagEnum tag;
  IDiaSymbol *sym;
public:

  pdb_global_item_iterator(pdb_modinfo_t *_pdb_module, ea_t a, asize_t sz, enum SymTagEnum t)
    : pdb_module(_pdb_module), ea(a), size(sz), tag(t), sym(NULL)
  {
  }

  virtual ~pdb_global_item_iterator(void)
  {
    if ( sym != NULL )
      sym->Release();
  }

  void idaapi release(void)
  {
    delete this;
  }

  bool idaapi first(void)
  {
    cur = ea;
    return next();
  }

  bool idaapi next(void)
  {
    if ( sym != NULL )
    {
      sym->Release();
      sym = NULL;
    }

    if ( cur >= ea+size )
      return false;

    ea_t old = cur;
    qnotused(old);

    LONG disp;
    HRESULT hr = pdb_module->get_session()->findSymbolByVAEx(cur, tag, &sym, &disp);
    if ( FAILED(hr) || sym == NULL )
      return false;

    cur -= disp;

    ULONGLONG length = 0;
    sym->get_length(&length);
    cur += length;

    QASSERT(30169, cur > old); // to avoid endless loops - i do not know if they are possible
    return true;
  }

  source_item_ptr idaapi operator *()
  {
    source_item_t *si = new_pdb_symbol(pdb_module, sym);
    sym = NULL;
    return source_item_ptr(si);
  }
};

//--------------------------------------------------------------------------
// Retrieve the line numbers into a map
// 'enumerator' will be freed by this function
static void retrieve_lnnums(lnmap_t *map, IDiaEnumLineNumbers *enumerator)
{
  LONG lncnt = 0;
  enumerator->get_Count(&lncnt);

  if ( lncnt > 0 )
  {
    lnvec_t vec;
    vec.resize(lncnt);

    ULONG got = 0;
    enumerator->Next(lncnt, vec.begin(), &got);

    QASSERT(30170, got == lncnt);
    for ( ULONG j=0; j < got; j++ )
    {
      DWORD n;
      IDiaLineNumber *lnnum = vec[j];
      if ( SUCCEEDED(lnnum->get_lineNumber(&n)) )
        (*map)[n].push_back(lnnum);
    }
  }
  enumerator->Release();
}

//--------------------------------------------------------------------------
class pdb_lnmap_iterator : public _source_item_iterator
{
  pdb_modinfo_t *pdb_module;
  lnmap_t lnmap;        // lnnum -> lnvec_t
  IDiaLineNumber *item; // holds the answer after next()
  lnmap_t::iterator p;  // current lnnum
  size_t idx;           // current item on the line
public:

  pdb_lnmap_iterator(pdb_modinfo_t *_pdb_module, lnmap_t *map)
    : pdb_module(_pdb_module)
  {
    map->swap(lnmap);
  }

  virtual ~pdb_lnmap_iterator(void)
  {
    clear_lnmap(&lnmap);
  }

  void idaapi release(void)
  {
    delete this;
  }

  bool idaapi first(void)
  {
    p = lnmap.begin();
    idx = 0;
    return next();
  }

  bool idaapi next(void)
  {
    // at the end?
    if ( p == lnmap.end() )
      return false;

    size_t size = p->second.size();
    if ( idx >= size )
      return false;

    // remember the item to return when dereferenced
    item = p->second[idx];

    // advance pointer
    if ( ++idx >= size )
    {
      // go to next lnvec_t
      ++p;

      // reset the index in the vector
      idx = 0;
    }

    return true;
  }

  source_item_ptr idaapi operator *()
  {
    pdb_lnnum_item_t *ret = new pdb_lnnum_item_t(pdb_module, item);
    return source_item_ptr(ret);
  }
};

//--------------------------------------------------------------------------
source_item_iterator idaapi pdb_provider_t::find_source_items(
        ea_t ea,
        asize_t size,
        src_item_kind_t level,
        bool)
{
  pdb_global_item_iterator *ret = NULL;
  pdb_modinfo_t *pdb_module = find_module(ea);
  if ( pdb_module != NULL )
  {
    IDiaSession *session = pdb_module->get_session();
    enum SymTagEnum tag;
    switch ( level )
    {
      default:
        INTERR(30171);

      case SRCIT_STMT:       // a statement (if/while/for...)
      case SRCIT_EXPR:       // an expression (a+b*c)
        {
          pdb_lnmap_iterator *ret2 = NULL;
          IDiaEnumLineNumbers *enumerator;
          HRESULT hr = session->findLinesByVA(ea, size, &enumerator);
          if ( SUCCEEDED(hr) )
          {
            // Precompute the lines associated with the given address
            lnmap_t lnmap;
            retrieve_lnnums(&lnmap, enumerator);
            ret2 = new pdb_lnmap_iterator(pdb_module, &lnmap);
          }
          return source_item_iterator(ret2);
        }

      case SRCIT_FUNC:       // function
        tag = SymTagFunction;
        break;

      case SRCIT_LOCVAR:     // variable
        tag = SymTagData;
        break;
    }
    ret = new pdb_global_item_iterator(pdb_module, ea, size, tag);
  }
  return source_item_iterator(ret);
}

//--------------------------------------------------------------------------
source_item_iterator idaapi pdb_provider_t::find_source_items(
        source_file_t *sf,
        int lnnum,
        int colnum)
{
  pdb_lnmap_iterator *ret = NULL;
  IDiaEnumSymbols *syms;
  pdb_source_file_t *psf = (pdb_source_file_t *)sf;
  HRESULT hr = psf->file->get_compilands(&syms);
  if ( SUCCEEDED(hr) )
  {
    qvector<IDiaEnumLineNumbers *> enumvec;
    while ( true )
    {
      ULONG got = 0;
      IDiaSymbol *compiland;
      syms->Next(1, &compiland, &got);
      if ( got == 0 )
        break;

      IDiaEnumLineNumbers *enumerator;
      IDiaSession *dia_session = psf->pdb_module->get_session();
      if ( lnnum == 0 )
        hr = dia_session->findLines(compiland, psf->file, &enumerator);
      else
        hr = dia_session->findLinesByLinenum(compiland, psf->file, lnnum,
                                             colnum, &enumerator);
      compiland->Release();

      if ( SUCCEEDED(hr) )
        enumvec.push_back(enumerator);
    }

    syms->Release();

    if ( !enumvec.empty() )
    {
      // if multiple lines are requested, rearrange data by line numbers
      // lnnum -> vector<IDiaLineNumber*>
      lnmap_t lnmap;
      for ( int i=0; i < enumvec.size(); i++ )
      {
        IDiaEnumLineNumbers *enumerator = enumvec[i];
        retrieve_lnnums(&lnmap, enumerator);
      }
      ret = new pdb_lnmap_iterator(psf->pdb_module, &lnmap);
    }
  }
  return source_item_iterator(ret);
}

//--------------------------------------------------------------------------
static bool is_hexrays_filename(const char *fname)
{
  if ( fname != NULL && *fname == '$' )
  {
    while ( true )
    {
      char c = *++fname;
      if ( c == '\0' )
        return true;
      if ( qislower(c) || !qisxdigit(c) )
        break;
    }
  }
  return false;
}

//--------------------------------------------------------------------------
source_file_iterator idaapi pdb_provider_t::create_file_iterator(const char *filename)
{
  pdb_file_iterator *ret = NULL;
  // hack: check if the filename is like "$12345678"
  // if so, immediately return because such names are used by the decompiler sip
  if ( !is_hexrays_filename(filename) )
  {
    qwstring fnamebuf;
    wchar16_t *fname = NULL;
    if ( filename != NULL )
    {
      qstring fnametmp = filename;
      c2ustr(qstrlwr(&fnametmp[0]), &fnamebuf);
      fname = fnamebuf.begin();
    }

    // Get a source file item iterators from each module
    fileenumvec_t fv;
    for ( pdb_modules_t::iterator p=modules.begin(); p != modules.end(); )
    {
      pdb_modinfo_t *m = open_module(p++);
      if ( m != NULL )
      {
        pdb_fileenum_t pfe;
        pfe.pdb_module = m;
        IDiaSession *session = pfe.pdb_module->get_session();
        if ( session->findFile(NULL, fname, nsfFNameExt, &pfe.enumerator) == S_OK )
          fv.push_back(pfe);
      }
    }

    if ( !fv.empty() )
      ret = new pdb_file_iterator(&fv);
  }
  return source_file_iterator(ret);
}

//--------------------------------------------------------------------------
source_item_iterator idaapi pdb_provider_t::create_item_iterator(const source_file_t *sf)
{
  pdb_item_iterator *ret = NULL;
  pdb_source_file_t &psf = *(pdb_source_file_t *)&sf;
  IDiaEnumSymbols *syms;
  HRESULT hr = psf.file->get_compilands(&syms);
  if ( SUCCEEDED(hr) )
  {
    // enumerates compilands
    // it is possible to get their children and retrieve all symbols(?)
    ret = new pdb_item_iterator(psf.pdb_module, syms);
  }
  return source_item_iterator(ret);
}

//--------------------------------------------------------------------------
static pdb_provider_t g_pdb_provider("PDB", "PDB");

//----------------------------------------------------------------------------
srcinfo_provider_t *idaapi pdb_source_file_t::get_provider(void) const
{
  return &g_pdb_provider;
}

//----------------------------------------------------------------------------
srcinfo_provider_t *idaapi dummy_item_t::get_provider(void) const
{
  return &g_pdb_provider;
}
