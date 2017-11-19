
#ifndef TILBUILD_HPP
#define TILBUILD_HPP

//----------------------------------------------------------------------------
enum cvt_code_t
{
  cvt_failed,
  cvt_ok,
  cvt_typedef           // conversion resulted in a typedef to a named type
};

//----------------------------------------------------------------------------
class til_builder_t
{
public:

  //----------------------------------------------------------------------------
  struct tpinfo_t
  {
    cvt_code_t cvt_code;
    bool is_notype;
    tinfo_t type;
    til_t *ti;  // FIXME: do we need this?
    tpinfo_t(void) : cvt_code(cvt_ok), is_notype(false), ti(NULL) {}
    tpinfo_t(til_t *_ti, const tinfo_t &t) : cvt_code(cvt_ok), type(t), ti(_ti) {}
    const char *dstr(void) const
    {
      if ( cvt_code == cvt_failed )
        return "#cvt_failed";

      static qstring res;
      if ( !type.print(&res) )
        res = "#print_failed";
      return res.c_str();
    }
  };

  //----------------------------------------------------------------------------
  til_builder_t(til_t *_ti, pdb_access_t *_pa)
    : unnamed_idx(0),
      level(0),
      ti(_ti),
      pdb_access(NULL),
      enregistered_bug(false)
  {
    set_pdb_access(_pa);
  }

  virtual ~til_builder_t()
  {
    typemap.clear();
    idmap.clear();
    tpdefs.clear();
    handled.clear();
    creating.clear();
    unnamed_types.clear();
  }

  void set_pdb_access(pdb_access_t *_pdb_access)
  {
    pdb_access = _pdb_access;
  }

  typedef std::map<DWORD, tpinfo_t> typemap_t;
  typedef std::map<DWORD, uint32> idmap_t;
  typedef std::map<DWORD, qstring> tpdefs_t;
  typedef std::set<DWORD> idset_t;
  typedef std::map<qstring, int> creating_t;
  typedef std::set<uint32> unnamed_t;

  //      remove `anonymous-namespace'::
  // also remove `anonymous namespace'::
  void remove_anonymous_namespaces(qstring &storage);

  bool get_symbol_type(tpinfo_t *out, pdb_sym_t &sym, int *p_id);
  bool retrieve_type(tpinfo_t *out, pdb_sym_t &sym, pdb_sym_t *parent, int *p_id);
  bool retrieve_arguments(
        pdb_sym_t &sym,
        func_type_data_t &fi,
        pdb_sym_t *funcSym);
  cm_t convert_cc(DWORD cc0) const;
  bool get_variant_string_value(qstring *out, pdb_sym_t &sym) const;
  uint32 get_variant_long_value(pdb_sym_t &sym) const;
  bool begin_creation(DWORD tag, const qstring &name, uint32 *p_id);
  uint32 end_creation(const qstring &name);
  bool is_member_func(tinfo_t *class_type, pdb_sym_t &typeSym, pdb_sym_t *funcSym);
  bool is_frame_reg(int regnum) const;
  bool is_complex_return(pdb_sym_t &sym) const;
  bool is_unnamed_tag_typedef(const tinfo_t &tif) const;
  bool is_arm(DWORD machine_type) const;
  int get_symbol_funcarg_info(
        funcarg_t *out,
        pdb_sym_t &sym,
        DWORD /*dwDataKind*/,
        DWORD locType,
        int stack_off);
  void enum_function_args(pdb_sym_t &sym, func_type_data_t &args);
  cvt_code_t verify_union(
        udt_type_data_t *out,
        udt_type_data_t::iterator p1,
        udt_type_data_t::const_iterator p2) const;
  cvt_code_t create_union(
        tinfo_t *out,
        size_t *p_total_size,
        udt_type_data_t::iterator p1,
        udt_type_data_t::const_iterator p2) const;
  cvt_code_t convert_basetype(tpinfo_t *out, DWORD baseType, int size) const;
  cvt_code_t make_vtable_struct(tinfo_t *out, pdb_sym_t &sym);
  cvt_code_t convert_udt(tinfo_t *out, pdb_sym_t &sym, DWORD64 size);
  cvt_code_t create_udt(tinfo_t *out, udt_type_data_t *udt, int udtKind) const;
  cvt_code_t create_udt_ref(tinfo_t *out, udt_type_data_t *udt, int udt_kind) const;
  cvt_code_t really_convert_type(tpinfo_t *out, pdb_sym_t &sym, pdb_sym_t *parent, DWORD tag);
  cvt_code_t convert_type(
        tpinfo_t *out,
        pdb_sym_t &sym,
        pdb_sym_t *parent,
        DWORD type,
        DWORD tag);
  cvt_code_t handle_overlapping_members(udt_type_data_t *udt) const;
  // Will iterate on children, and call handle_function_child()
  HRESULT handle_symbols(pdb_sym_t &pGlobal);
  HRESULT handle_publics(pdb_sym_t &pGlobal);
  HRESULT handle_types(pdb_sym_t &pGlobal);
  HRESULT build(pdb_sym_t &pGlobal);
  ea_t  get_load_address() const { return pdb_access->get_base_address(); };
  HRESULT handle_symbol(pdb_sym_t &sym);
  size_t get_symbol_type_length(pdb_sym_t &sym) const;

  virtual HRESULT before_iterating(pdb_sym_t &global_sym);
  virtual HRESULT after_iterating(pdb_sym_t &global_sym);
  virtual bool iterate_symbols_once_more(pdb_sym_t & /*global_sym*/) { return false; }
  virtual bool get_symbol_name(pdb_sym_t &sym, qstring &storage);
  virtual bool handle_symbol_at_ea(
        pdb_sym_t &sym,
        DWORD tag,
        DWORD id,
        ea_t ea,
        qstring &name);
  virtual void type_created(ea_t /*ea*/, int /*id*/, const char * /*name*/, const tinfo_t & /*ptr*/) const;
  virtual void handle_function_type(pdb_sym_t &fun_sym, ea_t ea);
  virtual HRESULT handle_function_child(
        pdb_sym_t &fun_sym,
        ea_t ea,
        pdb_sym_t &child_sym,
        DWORD child_tag,
        DWORD child_loc_type);
  virtual cvt_code_t handle_unnamed_overlapping_member(
        udt_type_data_t * /*udt*/,
        qstack<qstring> * /*union_names*/,
        qstring * /*name*/) const
  {
    return cvt_ok;
  }

protected:
  typemap_t typemap;            // id -> type info
  idmap_t idmap;                // id -> type ordinal
  tpdefs_t tpdefs;              // id -> enum type defined in base til
  idset_t handled;              // set of handled symbols
  creating_t creating;
  unnamed_t unnamed_types;
  int unnamed_idx;
  int level;

public:
  til_t *ti;
  pdb_access_t *pdb_access;
  bool enregistered_bug;
};

#endif // TILBUILD_HPP
