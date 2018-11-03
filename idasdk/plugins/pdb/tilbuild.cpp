
#include "tilbuild.hpp"

//#define PDEB

static const char fake_vtable_type[] = "$vt";

//----------------------------------------------------------------------------
void til_builder_t::remove_anonymous_namespaces(qstring &buf)
{
  char *p = buf.begin();
  while ( true )
  {             // 1234567890
    p = strstr(p, "`anonymous");
    if ( p == NULL )
      break;
    const char *q = p + 10;
    if ( *q != '-' && *q != ' ' )
      break;
    if ( strncmp(q+1, "namespace'::", 12) != 0 )
      break;      // 123456789012
    size_t idx = p - buf.begin();
    buf.remove(idx, 10+1+12);
    p = buf.begin() + idx;
  }
}

//-------------------------------------------------------------------------
static inline bool ident_char(char c)
{
  return c == '_' || qisalnum(c);
}

//----------------------------------------------------------------------------
bool til_builder_t::get_symbol_name(pdb_sym_t &sym, qstring &buf)
{
  bool is_unnamed = false;
  sym.get_name(&buf);
  if ( buf.empty() )
  {
    is_unnamed = true;
  }
  else
  {
    //
    remove_anonymous_namespaces(buf);

    // <unnamed-tag>  => <unnamed_tag>
    // <unnamed-type-xxx> => <unnamed_type_xxx>
    char *p = buf.begin();
    while ( true )
    {
      //             012345678
      p = strstr(p, "<unnamed");
      if ( p == NULL )
        break;
      p += 8;
      while ( *p != '\0' )
      {
        if ( *p == '>' )
        {
          p++;
          break;
        }
        else if ( *p == '-' )
        {
          *p = '_';
        }
        p++;
      }
      is_unnamed = true;
    }
    if ( !is_unnamed )
    {
      const char *marker = strstr(buf.begin(), "__unnamed" );
      if ( marker != NULL
        // Is prev char not a valid identifier char?
        && (marker == buf.begin() ? true : !ident_char(marker[-1]))
        // Is next char not a valid identifier char?
        && !ident_char(marker[9]) )
      {
        is_unnamed = true;
      }
    }
  }
  return is_unnamed;
}

//----------------------------------------------------------------------------
bool til_builder_t::get_symbol_type(tpinfo_t *out, pdb_sym_t &sym, int *p_id)
{
  pdb_sym_t pType(pdb_access);
  if ( p_id != NULL )
    *p_id = -1;
  if ( sym.get_type(&pType) != S_OK )
    return false;
  return retrieve_type(out, pType, NULL, p_id);
}

//----------------------------------------------------------------------------
size_t til_builder_t::get_symbol_type_length(pdb_sym_t &sym) const
{
  DWORD64 size = 0;
  DWORD tag = 0;

  sym.get_symTag(&tag);
  if ( tag == SymTagData )
  {
    pdb_sym_t pType(pdb_access);
    if ( sym.get_type(&pType) == S_OK )
      pType.get_length(&size);
  }
  else
  {
    sym.get_length(&size);
  }
  return size_t(size);
}

//----------------------------------------------------------------------
cvt_code_t til_builder_t::convert_basetype(
        tpinfo_t *out,
        DWORD baseType,
        int size) const
{
  type_t bt = BTF_TYPEDEF;
  const char *name = NULL;
  switch ( baseType )
  {
    case btNoType:
      out->is_notype = true;
      // Fallthrough.
    default:
    case 0x12c304:                      // "impdir_entry" (guessed)
    case btBCD:
    case btBit:
      return cvt_failed;
    case btVoid:
      bt = BTF_VOID;
      break;
    case btChar:
      bt = BT_INT8|BTMT_CHAR;
      break;
    case btBool:
      bt = BT_BOOL;
      if ( size != inf.cc.size_b )
      {
        switch ( size )
        {
          case 1:
            bt |= BTMT_BOOL1;
            break;
          case 2:
            if ( inf.is_64bit() )
              goto MAKE_INT; // 64bit apps do not have BOOL2
            bt |= BTMT_BOOL2;
            break;
          case 4:
            bt |= BTMT_BOOL4;
            break;
          case 8:
            if ( !inf.is_64bit() )
              goto MAKE_INT; // 32bit apps do not have BOOL8
            bt |= BTMT_BOOL8;
            break;
          default:
            // can't make this bool size; make an int
            goto MAKE_INT;
        }
      }
      break;
MAKE_INT:
    case btInt:
    case btLong:     bt = get_scalar_bt(size);              break;
    case btUInt:
    case btULong:    bt = get_scalar_bt(size)|BTMT_USIGNED; break;
    case btFloat:
      if ( size == sizeof_ldbl() )
      {
        bt = BTMT_LNGDBL;
      }
      else
      {
        switch ( size )
        {
          case 4:  bt = BTMT_FLOAT;   break;
          default:
          case 8:  bt = BTMT_DOUBLE;  break;
          case 10: bt = BTMT_SPECFLT; break;
        }
      }
      bt |= BT_FLOAT;
      break;
    case btWChar:    name = "wchar_t";                         break;
    case btBSTR:     name = "BSTR";                            break;
    case btHresult:  name = "HRESULT";                         break;
    case btCurrency: name = "CURRENCY";                        break;
    case btVariant:  name = "VARIANT";                         break;
    case btComplex:  name = "complex";                         break;
    case btDate:     name = "DATE";                            break;
  }
  if ( name != NULL )
  {
    out->type.create_typedef(ti, name);
    return cvt_typedef;
  }
  else
  {
    out->type = tinfo_t(bt);
    return cvt_ok;
  }
}

//----------------------------------------------------------------------
bool til_builder_t::retrieve_arguments(
        pdb_sym_t &_sym,
        func_type_data_t &fi,
        pdb_sym_t *funcSym)
{
  struct type_name_collector_t : public pdb_access_t::children_visitor_t
  {
    func_type_data_t &fi;
    til_builder_t *tb;
    til_t *ti;
    HRESULT visit_child(pdb_sym_t &sym)
    {
      // check that it's a parameter
      DWORD dwDataKind;
      if ( sym.get_dataKind(&dwDataKind) == S_OK
        && dwDataKind != DataIsParam
        && dwDataKind != DataIsObjectPtr )
      {
        return S_OK;
      }
      tpinfo_t tpi;
      bool cvt_succeeded = tb->retrieve_type(&tpi, sym, parent, NULL);
      if ( cvt_succeeded || tpi.is_notype )
      {
        funcarg_t &arg = fi.push_back();
        arg.type = tpi.type;
        sym.get_name(&arg.name);
      }
      return S_OK;
    }
    type_name_collector_t(til_t *_ti, til_builder_t *_tb, func_type_data_t &_fi)
      : fi(_fi), tb(_tb), ti(_ti) {}
  };
  fi.clear();
  type_name_collector_t pp(ti, this, fi);
  HRESULT hr = pdb_access->iterate_children(_sym, SymTagNull, pp);
  if ( hr == S_OK && funcSym != NULL )
  {
    // get parameter names from the function symbol
    func_type_data_t args;
    args.flags = 0;
    enum_function_args(*funcSym, args);
//    QASSERT(497, args.empty() || args.size() == fi.size() );
    bool custom_cc = false;
    for ( int i = 0; i < fi.size(); i++ )
    {
      if ( i < args.size() )
      {
        if ( fi[i].name.empty() )
          fi[i].name = args[i].name;
        argloc_t &cur_argloc = args[i].argloc;
        fi[i].argloc = cur_argloc;
        if ( !custom_cc && cur_argloc.is_reg1() )
        {
          if ( pdb_access->get_machine_type() == CV_CFL_80386 )
          {
            if ( fi.cc == CM_CC_FASTCALL
              && cur_argloc.regoff() == 0
              && (cur_argloc.reg1() == R_cx && i == 0
               || cur_argloc.reg1() == R_dx && i == 1) )
            {
              // ignore ecx and edx for fastcall
            }
            else if ( fi.cc == CM_CC_THISCALL
                   && cur_argloc.regoff() == 0
                   && cur_argloc.reg1() == R_cx && i == 0 )
            {
              // ignore ecx for thiscall
            }
            else
            {
              custom_cc = true;
            }
          }
        }
        //ask_for_feedback("pdb: register arguments are not supported for machine type %d", machine_type);
      }
    }
    if ( custom_cc )
    {
      // we have some register params; need to convert function to custom cc
      fi.cc = (is_purging_cc(fi.cc) || fi.cc == CM_CC_THISCALL || fi.cc == CM_CC_FASTCALL)
            ? CM_CC_SPECIALP
            : CM_CC_SPECIAL;
    }
    return true;
  }
  return false;
}

//----------------------------------------------------------------------
cm_t til_builder_t::convert_cc(DWORD cc0) const
{
  switch ( cc0 )
  {
    case CV_CALL_GENERIC    :
    case CV_CALL_NEAR_C     :
    case CV_CALL_FAR_C      : return inf.is_64bit()
                                   ? CM_CC_FASTCALL
                                   : CM_CC_CDECL;
    case CV_CALL_NEAR_PASCAL:
    case CV_CALL_FAR_PASCAL : return CM_CC_PASCAL;
    case CV_CALL_NEAR_FAST  :
    case CV_CALL_FAR_FAST   : return CM_CC_FASTCALL;
//    case CV_CALL_SKIPPED    :
    case CV_CALL_NEAR_STD   :
    case CV_CALL_FAR_STD    :
    case CV_CALL_ARMCALL    : return CM_CC_STDCALL;
    case CV_CALL_THISCALL   : return CM_CC_THISCALL;
//    case CV_CALL_NEAR_SYS   :
//    case CV_CALL_FAR_SYS    :
//    case CV_CALL_MIPSCALL   :
//    case CV_CALL_ALPHACALL  :
//    case CV_CALL_PPCCALL    :
//    case CV_CALL_SHCALL     :
//    case CV_CALL_ARMCALL    :
//    case CV_CALL_AM33CALL   :
//    case CV_CALL_TRICALL    :
//    case CV_CALL_SH5CALL    :
//    case CV_CALL_M32RCALL   :
  }
  return CM_CC_UNKNOWN;
}

//----------------------------------------------------------------------
bool til_builder_t::get_variant_string_value(qstring *out, pdb_sym_t &sym) const
{
  bool ok = false;
  VARIANT value;
  VariantInit(&value);
  if ( sym.get_value(&value) == S_OK && value.vt == VT_BSTR )
  {
    utf16_utf8(out, (wchar16_t*) value.bstrVal);
    ok = true;
  }
  VariantClear(&value);
  return ok;
}

//----------------------------------------------------------------------
uint32 til_builder_t::get_variant_long_value(pdb_sym_t &sym) const
{
  uint32 v = 0;
  VARIANT value;
  VariantInit(&value);
  if ( sym.get_value(&value) == S_OK )
  {
    switch ( value.vt )
    {
      case VT_I1:   v = value.cVal; break;
      case VT_I2:   v = value.iVal; break;
      case VT_I4:   v = value.lVal; break;
      case VT_I8:   v = value.llVal; break;
      case VT_INT:  v = value.intVal; break;
      case VT_UI1:  v = value.bVal; break;
      case VT_UI2:  v = value.uiVal; break;
      case VT_UI4:  v = value.ulVal; break;
      case VT_UI8:  v = value.ullVal; break;
      case VT_UINT: v = value.uintVal; break;
      default:
        ask_for_feedback("pdb: unsupported VARIANT type %d", value.vt);
        break;
    }
  }
  VariantClear(&value);
  return v;
}

//----------------------------------------------------------------------
// funcSym is Function, typeSym is FunctionType
bool til_builder_t::is_member_func(tinfo_t *class_type, pdb_sym_t &typeSym, pdb_sym_t *funcSym)
{
  // make sure we retrieve class type first
  pdb_sym_t pParent(pdb_access);
  if ( typeSym.get_classParent(&pParent) != S_OK || pParent.data == NULL )
    return false;

  tpinfo_t tpi;
  if ( !retrieve_type(&tpi, pParent, NULL, NULL) )
    return false; // failed to retrieve the parent's type

  class_type->swap(tpi.type);

  // then check if it's static
  BOOL bIsStatic = false;
  if ( funcSym != NULL
    && pdb_access->get_dia_version() >= 800
    && funcSym->get_isStatic(&bIsStatic) == S_OK )
  {
    return !bIsStatic;
  }
  return true;
}

//----------------------------------------------------------------------------
bool til_builder_t::is_arm(DWORD machine_type) const
{
  return machine_type == CV_CFL_ARM3
      || machine_type == CV_CFL_ARM4
      || machine_type == CV_CFL_ARM4T
      || machine_type == CV_CFL_ARM5
      || machine_type == CV_CFL_ARM5T
      || machine_type == CV_CFL_ARM6
      || machine_type == CV_CFL_ARM7
      || machine_type == CV_CFL_ARMNT
      || machine_type == CV_CFL_ARM_XMAC
      || machine_type == CV_CFL_ARM_WMMX
      || machine_type == CV_CFL_THUMB;
}

//----------------------------------------------------------------------
bool til_builder_t::is_frame_reg(int reg) const
{
  if ( pdb_access->get_machine_type() == CV_CFL_80386 )
    return reg == CV_REG_EBP;
  else if ( is_arm(pdb_access->get_machine_type()) )
    return reg == CV_ARM_R11 || reg == CV_ARM_SP;
  return false;
}

//----------------------------------------------------------------------------
int til_builder_t::get_symbol_funcarg_info(
        funcarg_t *out,
        pdb_sym_t &sym,
        DWORD /*dwDataKind*/,
        DWORD locType,
        int stack_off)
{
  sym.get_name(&out->name);
  tpinfo_t tpi;
  get_symbol_type(&tpi, sym, NULL);
  out->type = tpi.type;
  if ( locType == LocIsEnregistered )
  {
    DWORD dwReg;
    if ( sym.get_registerId(&dwReg) == S_OK )
    {
      if ( enregistered_bug && dwReg > 0 )
        dwReg--;
      const char *regname = print_pdb_register(pdb_access->get_machine_type(), dwReg);
      out->argloc._set_reg1(str2reg(regname));
    }
  }
  else if ( locType == LocIsRegRel )
  {
    DWORD dwReg;
    LONG lOffset;
    if ( sym.get_registerId(&dwReg) == S_OK
      && sym.get_offset(&lOffset) == S_OK
      && is_frame_reg(dwReg) )
    {
      uint32 align;
      out->argloc._set_stkoff(stack_off);
      size_t argsz = out->type.get_size(&align);
      if ( align > argsz )
        argsz = align;
      stack_off += argsz;
    }
  }
  else
  {
    ask_for_feedback("pdb: unsupported location type %d", locType);
  }
  return stack_off;
}

//----------------------------------------------------------------------
void til_builder_t::enum_function_args(pdb_sym_t &_sym, func_type_data_t &args)
{
  // enumerate all function parameters and gather their names
  struct param_enumerator_t : public pdb_access_t::children_visitor_t
  {
    func_type_data_t &args;
    til_builder_t *tb;
    int stack_off;
    virtual HRESULT visit_child(pdb_sym_t &sym)
    {
      DWORD tag = 0;
      HRESULT hr = sym.get_symTag(&tag);
      if ( FAILED(hr) )
        return hr;

      switch ( tag )
      {
        case SymTagBlock: // nested blocks
          return tb->pdb_access->iterate_children(sym, SymTagNull, *this);
        case SymTagFuncDebugStart:
        case SymTagFuncDebugEnd:
          return S_OK;    // ignore these for the moment
      }

      DWORD dwDataKind, locType;
      if ( sym.get_dataKind(&dwDataKind) == S_OK
        && dwDataKind == DataIsParam
        && sym.get_locationType(&locType) == S_OK )
      {
        funcarg_t &fa = args.push_back();
        stack_off = tb->get_symbol_funcarg_info(&fa, sym, dwDataKind, locType, stack_off);
      }
      return S_OK; // continue enumeration
    }
    param_enumerator_t(func_type_data_t &_args, til_builder_t *_tb)
      : args(_args), tb(_tb), stack_off(0) {}
  };
  param_enumerator_t pen(args, this);
  pdb_access->iterate_children(_sym, SymTagData, pen);
}

//----------------------------------------------------------------------
// verify unions that would be created out of [p1, p2) members.
// The [p1, p2) members are spoiled by the function.
// Create substructures if necessary. Returns the result in out (can be the same
// vector as [p1, p2)
cvt_code_t til_builder_t::verify_union(
        udt_type_data_t *out,
        udt_type_data_t::iterator p1,
        udt_type_data_t::const_iterator p2) const
{
  if ( p1 == p2 )
    return cvt_ok;

  QASSERT(498, p2 > p1);
  uint64 off = p1->offset;
  typedef qvector<udt_type_data_t> stems_t;
  stems_t stems; // each stem is a member of the future union
  for ( udt_type_data_t::iterator q=p1; q != p2; ++q )
  {
    udt_type_data_t *best = NULL;
    q->offset -= off;
    if ( q->offset != 0 )
    { // find best suited stem: the one with end() closest to our offset
      uint64 bestend = 0;
      for ( stems_t::iterator s=stems.begin(); s != stems.end(); ++s )
      {
        udt_type_data_t &sm = *s;
        udt_member_t &lastmem = sm.back();
        uint64 smend = lastmem.end();
        if ( lastmem.is_bitfield() == q->is_bitfield()
          && smend <= q->begin()
          && (best == NULL || bestend < smend) )
        {
          best = &sm;
          bestend = smend;
        }
      }
    }
    if ( best == NULL )
      best = &stems.push_back();
    uint64 qend;
    if ( q->is_bitfield() )
    {
      bitfield_type_data_t bi;
      q->type.get_bitfield_details(&bi);
      size_t size = bi.nbytes * 8;
      QASSERT(30385, size == 8 || size == 16 || size == 32 || size == 64);
      qend = align_down(q->offset, size) + size;
    }
    else
    {
      qend = q->offset + q->size + 7;
    }
    qend /= 8;
    if ( best->total_size < qend )
      best->total_size = qend;
    qswap(best->push_back(), *q);
  }

  // all non-trivial stems must be converted to structures
  for ( stems_t::iterator s=stems.begin(); s != stems.end(); ++s )
  {
    if ( s->size() == 1 && s->begin()->offset == 0 && !s->begin()->is_bitfield() )
      continue;
#ifdef PDEB
    msg("CREATE STEM\n");
    for ( udt_type_data_t::iterator p=s->begin(); p != s->end(); ++p )
      msg("  %" FMT_64 "x %s %s\n", p->offset, p->type.dstr(), p->name.c_str());
#endif
    tinfo_t tif;
    int total_size = s->total_size;
    cvt_code_t code = create_udt_ref(&tif, s, UdtStruct);
    if ( code != cvt_ok )
      return code;
    s->resize(1);
    udt_member_t &sm = s->front();
    sm.offset = 0;
    sm.size = uint64(total_size) * 8;
    sm.name.sprnt("__s%u", uint(s-stems.begin()));
    sm.type = tif;
  }

  // collect the results
  out->resize(stems.size());
  for ( int i=0; i < stems.size(); i++ )
  {
    QASSERT(499, stems[i].size() == 1);
    qswap(out->at(i), *stems[i].begin());
  }
  return cvt_ok;
}

//----------------------------------------------------------------------
// create a union out of [p1, p2) members. they are spoiled by the function.
// returns type of the new union and its fields
// this function also creates substructures if necessary
cvt_code_t til_builder_t::create_union(
        tinfo_t *out,
        size_t *p_total_size,
        udt_type_data_t::iterator p1,
        udt_type_data_t::const_iterator p2) const
{
#ifdef PDEB
  msg("CREATE UNION\n");
  for ( udt_type_data_t::iterator p=p1; p != p2; ++p )
    msg("  %" FMT_64 "x %s %s\n", p->offset, p->type.dstr(), p->name.c_str());
#endif
  udt_type_data_t unimems;
  cvt_code_t code = verify_union(&unimems, p1, p2);
  if ( code != cvt_ok )
    return code;
  // calculate the total size
  for ( int i=0; i < unimems.size(); i++ )
  {
    udt_member_t &udm = unimems[i];
    size_t nbytes = (udm.end() + 7) / 8;
    if ( nbytes > unimems.total_size )
      unimems.total_size = nbytes;
  }
  if ( p_total_size != NULL )
    *p_total_size = unimems.total_size;
  return create_udt_ref(out, &unimems, UdtUnion);
}

//----------------------------------------------------------------------
// enumerate virtual functions of class sym and create a vtable structure
// with function pointers
cvt_code_t til_builder_t::make_vtable_struct(tinfo_t *out, pdb_sym_t &_sym)
{
  struct virtual_func_visitor_t : public pdb_access_t::children_visitor_t
  {
    til_builder_t *tb;
    udt_type_data_t &udt;
    qstring &classprefix;
    virtual HRESULT visit_child(pdb_sym_t &sym)
    {
      BOOL b;
      // skip non-virtual functions
      if ( sym.get_virtual(&b) != S_OK || !b )
        return S_OK;
      DWORD offset = -1;
      if ( sym.get_virtualBaseOffset(&offset) != S_OK )
        return S_OK; // skip

      // TODO: add RVA as a comment?
      // ULONGLONG dwRVA = -1;
      // tb->sym.get_virtualAddress(sym, &dwRVA);

      // if this offset was used before, replace the member
      // this often happens when virtual class::~class
      // is later redefined as __vecDelDtor()
      ssize_t memidx = -1;
      for ( size_t i=0; memidx == -1 && i < udt.size(); ++i )
      {
        if ( udt[i].offset == offset )
          memidx = i;
      }

      qstring name;
      sym.get_name(&name);
      // remove 'class_name::'
      if ( !classprefix.empty() )
      {
        size_t pos = name.find(classprefix);
        if ( pos != qstring::npos )
          name.remove(pos, classprefix.length());
      }

      tpinfo_t tpi;
      if ( tb->retrieve_type(&tpi, sym, parent, NULL) )
      {
        tpi.type.create_ptr(tpi.type); // the field is a pointer to function
        asize_t size = tpi.type.get_size();
        udt_member_t &udm = memidx == -1 ? udt.push_back() : udt[memidx];
        udm.offset = uint64(offset) * 8;
        udm.size = uint64(size) * 8;
        udm.type = tpi.type;
        udm.name.swap(name);
        if ( udt.total_size < offset+size )
          udt.total_size = offset+size;
      }
      return S_OK;
    }
    virtual_func_visitor_t(til_builder_t *_tb, udt_type_data_t &m, qstring &cp) : tb(_tb), udt(m), classprefix(cp) {}
  };

  udt_type_data_t udt;
  qstring classprefix;
  _sym.get_name(&classprefix);
  if ( !classprefix.empty() )
    classprefix += "::";
  virtual_func_visitor_t pp(this, udt, classprefix);
  pdb_access->iterate_children(_sym, SymTagFunction, pp);
  if ( udt.empty() )
    return cvt_failed;
  std::sort(udt.begin(), udt.end());
  return create_udt(out, &udt, UdtStruct);
}

//----------------------------------------------------------------------
cvt_code_t til_builder_t::convert_udt(
        tinfo_t *out,
        pdb_sym_t &_sym,
        DWORD64 size)
{
  DWORD udtKind;
  if ( _sym.get_udtKind(&udtKind) != S_OK )
    return cvt_failed;

  // retrieve member names, types, offsets
  struct type_name_collector_t : public pdb_access_t::children_visitor_t
  {
    til_builder_t *tb;
    udt_type_data_t &udt;
    bool has_virtbases;
    HRESULT visit_child(pdb_sym_t &sym)
    {
      DWORD dwLocType = LocIsNull;
      sym.get_locationType(&dwLocType); // may fail, just ignore

      LONG offset = 0;
      if ( sym.get_offset(&offset) != S_OK )
        return S_OK;

      asize_t memsize = tb->get_symbol_type_length(sym);
      tpinfo_t tpi;
      if ( tb->retrieve_type(&tpi, sym, parent, NULL) )
      {
        qstring name;
        DWORD tag = SymTagNull;
        sym.get_symTag(&tag);
        bool is_base = true;
        BOOL is_virtbase = false;
        if ( tag == SymTagBaseClass )
        {
          // determine if the base is virtual
          sym.get_isVirtualBaseClass(&is_virtbase);
        }
        else
        {
          is_base = false;
          sym.get_name(&name);
          if ( tag == SymTagVTable )
          {
            qstring tname;
            if ( tpi.type.get_type_name(&tname) && tname == fake_vtable_type )
              tpi.type = tinfo_t::get_stock(STI_PVOID);
            else // type is a structure, while the field is a pointer to it
              tpi.type.create_ptr(tpi.type);
            if ( name.empty() )
            {
              if ( offset == 0 )
                name = "vfptr";
              else
                name.sprnt("vfptr%x", offset);
            }
            memsize = tpi.type.get_size();
          }
        }
        udt_member_t &udm = udt.push_back();
        DWORD64 ulLen = DWORD64(memsize) * 8;
        DWORD dwBitPos = 0;
        if ( dwLocType == LocIsBitField )
        {
          sym.get_bitPosition(&dwBitPos);
          sym.get_length(&ulLen);
          bool is_unsigned = tpi.type.is_unsigned();
          udm.type.create_bitfield(memsize, ulLen, is_unsigned);
        }
        else
        {
          udm.type = tpi.type;
        }
        udm.size = ulLen;
        udm.offset = uint64(offset) * 8 + dwBitPos;
        udm.name.swap(name);
        if ( is_base )
          udm.set_baseclass();
        if ( is_virtbase )
        {
          udm.tafld_bits |= TAFLD_VIRTBASE;
          has_virtbases = true;
        }
      }
      return S_OK;
    }
    type_name_collector_t(til_builder_t *_tb, udt_type_data_t &m)
      : tb(_tb), udt(m), has_virtbases(false) {}
  };

  udt_type_data_t udt;
  type_name_collector_t pp(this, udt);
  pdb_access->iterate_children(_sym, SymTagNull, pp);
  // if we inherit from c++ object, we are too a c++ object
  bool is_cppobj = false;
  if ( size > 0 )
  {
    if ( udt.empty() )
      is_cppobj = true;
    if ( udt.size() == 1
      && udt[0].is_baseclass()
      && udt[0].type.is_empty_udt() )
    {
      is_cppobj = true;
    }
  }
  if ( is_cppobj )
  {
    udt.taudt_bits |= TAUDT_CPPOBJ;
  }
  else if ( udt.empty() )
  { // create forward ref
    qstring name;
    get_symbol_name(_sym, name);
    type_t bt = udtKind == UdtUnion ? BTF_UNION : BTF_STRUCT;
    out->create_typedef(ti, name.c_str(), bt);
    return cvt_typedef;
  }
  udt.total_size = size;
  std::stable_sort(udt.begin(), udt.end());
  BOOL cppobj;
  if ( _sym.get_constructor(&cppobj) == S_OK && cppobj > 0 )
    udt.taudt_bits |= TAUDT_CPPOBJ;
  return create_udt(out, &udt, udtKind);
}

//----------------------------------------------------------------------
static bool set_array_type(udt_member_t *udm, int nbytes)
{
  bool ok = udm->type.create_array(tinfo_t(BT_UNK_BYTE), nbytes);
  if ( ok )
    udm->size = nbytes * 8;
  return ok;
}

//----------------------------------------------------------------------
cvt_code_t til_builder_t::create_udt(tinfo_t *out, udt_type_data_t *udt, int udtKind) const
{
  cvt_code_t code;
  if ( udtKind == UdtUnion )
  {
    udt->is_union = true;
    code = verify_union(udt, udt->begin(), udt->end());
  }
  else
  {
    // find overlapping members and convert into subunions (anonymous union would be great)
    udt->is_union = false;
    code = handle_overlapping_members(udt);
  }
  if ( code != cvt_ok )
    return code;

  // validate the type sizes, for the following reasons:
  //   - pdb information may be misleading (see pc_pdb_redefined_type.pe)
  //   - the same type name can be used for different types
  //   - invalid arrays happen (pc_pdb_wow.pe)
  for ( int i=0; i < udt->size(); i++ )
  {
    udt_member_t &udm = udt->at(i);
    if ( udm.is_bitfield() )
      continue;
    int gts_code = GTS_NESTED | (udm.is_baseclass() ? GTS_BASECLASS : 0);
    size_t nbytes = udm.type.get_size(NULL, gts_code);
    if ( nbytes == BADSIZE )
      continue; // can not verify, the type is not ready yet
    if ( uint64(nbytes)*8 != udm.size )
    {
      if ( nbytes != 0 )
      {
        if ( !set_array_type(&udm, udm.size/8) )
          return cvt_failed;
      }
      else if ( udm.is_baseclass() || udm.type.is_array() )
      { // nbytes==0
        udm.size = 0; // correct the base class size
      }
    }
  }

  if ( udt->total_size == 0 && !udt->empty() )
  { // msdia did not provide the udt size. use the end of the last element
    udt_member_t &udm = udt->back();
    udt->total_size = (udm.end() + 7) / 8;
  }

  // the kernel can not handle virtual base classes yet, so we remove them
  // also check for overlapping members and members that go past the udt end
  uint64 last = 0;
  uint64 total_bits = uint64(udt->total_size) * 8;
  for ( int i=0; i < udt->size(); i++ )
  {
    udt_member_t &udm = udt->at(i);
    if ( udm.offset < last || udm.end() > total_bits )
    {
      if ( udm.end() > total_bits )
        udm.size = total_bits - udm.offset;
      int nbytes = (udm.end() + 7 - last) / 8;
      if ( nbytes > 0 )
      { // replace with byte array
        if ( !set_array_type(&udm, nbytes) )
          return cvt_failed;
        udm.offset = last;
        udm.clr_baseclass();
        udm.clr_virtbase();
      }
      else
      { // we do not need this member
        udt->erase(udt->begin()+i);
        --i;
        continue;
      }
    }
    if ( udtKind != UdtUnion )
      last = udm.end();
  }

  type_t bt = udt->is_union ? BTF_UNION : BTF_STRUCT;
  out->create_udt(*udt, bt);
  if ( !out->calc_udt_aligns(SUDT_GAPS|SUDT_UNEX) )
  {
    QASSERT(30380, (inf.s_cmtflg & SW_TESTMODE) == 0);
    ask_for_feedback("Failed to calculate struct member alignments");
  }
  return cvt_ok;
}

//----------------------------------------------------------------------
// is the return type complex?
// if so, a pointer to return value will be passed as a hidden parameter
bool til_builder_t::is_complex_return(pdb_sym_t &sym) const
{
  pdb_sym_t pType(pdb_access);
  bool complex = false;
  if ( sym.get_type(&pType) == S_OK )
  {
    DWORD tag = 0;
    complex = pType.get_symTag(&tag) == S_OK && tag == SymTagUDT;
    if ( complex )
    {
      ULONGLONG size;
      complex = pType.get_length(&size) == S_OK && size > 8;
    }
    if ( !complex && tag == SymTagUDT )
    {
      // we've got a small UDT which possibly fits into a register (or two)
      // but it has to be a POD for that, i.e. should have no constructor or assignment operators
      BOOL b;
      if ( (pType.get_constructor          (&b) == S_OK) && b
        || (pType.get_hasAssignmentOperator(&b) == S_OK) && b
        || (pType.get_hasCastOperator      (&b) == S_OK) && b )
        complex = true;
    }
  }
  return complex;
}


//----------------------------------------------------------------------------
bool til_builder_t::is_unnamed_tag_typedef(const tinfo_t &tif) const
{
  uint32 id = tif.get_ordinal();
  if ( id == 0 )
    return false;

  return unnamed_types.find(id) != unnamed_types.end();
}


//----------------------------------------------------------------------
// borland does not like this structure to be defined inside a function.
// this is the only reason why it is in the file scope.
struct this_seeker_t : public pdb_access_t::children_visitor_t
{
  funcarg_t thisarg;
  til_builder_t *tb;
  virtual HRESULT visit_child(pdb_sym_t &sym)
  {
    DWORD dwDataKind, locType;
    if ( sym.get_dataKind(&dwDataKind) == S_OK
      && dwDataKind == DataIsObjectPtr
      && sym.get_locationType(&locType) == S_OK )
    {
      tb->get_symbol_funcarg_info(&thisarg, sym, dwDataKind, locType, 0);
      return S_FALSE; // Stop enum.
    }
    return S_OK;
  }
  this_seeker_t(til_builder_t *_tb) : thisarg(), tb(_tb) {}
};

//----------------------------------------------------------------------
cvt_code_t til_builder_t::really_convert_type(
        tpinfo_t *out,
        pdb_sym_t &sym,
        pdb_sym_t *parent,
        DWORD tag)
{
  // retrieve type modifiers
  type_t mods = 0;
  BOOL bSet;
  if ( sym.get_constType(&bSet) == S_OK && bSet )
    mods |= BTM_CONST;

  if ( sym.get_volatileType(&bSet) == S_OK && bSet )
    mods |= BTM_VOLATILE;

  DWORD64 size = 0;
  sym.get_length(&size);
  DWORD bt, count;
  cvt_code_t code = cvt_ok;
  switch ( tag )
  {
    default:
    case SymTagNull:
      deb(IDA_DEBUG_PLUGIN, "unsupported tag %s\n", symtag_to_string(tag));
      code = cvt_failed;
      break;

    case SymTagBaseType:
      if ( sym.get_baseType(&bt) != S_OK )
        code = cvt_failed;
      else
        code = convert_basetype(out, bt, int(size));
      break;

    case SymTagPointerType:
      {
        tpinfo_t obj;
        if ( !get_symbol_type(&obj, sym, NULL) )
        {
          code = cvt_failed;
          break;
        }
        tinfo_t tif;
        tif.create_ptr(obj.type);
        int s2 = tif.get_size();
        if ( size != s2 )
        {
          if ( size == 4 || size == 8 )
          { // use __ptr32 or __ptr64
            ptr_type_data_t pi;
            pi.obj_type = obj.type;
            pi.taptr_bits = size == 4 ? TAPTR_PTR32 : TAPTR_PTR64;
            tif.create_ptr(pi);
          }
          else
          { // revert to int
            type_t inttype = get_scalar_bt(size);
            if ( inttype == BT_UNK )
            {
              code = cvt_failed;
              break;
            }
            tif = tinfo_t(inttype);
          }
        }
        out->type.swap(tif);
      }
      break;

    case SymTagArrayType:
      {
        tpinfo_t el;
        if ( !get_symbol_type(&el, sym, NULL) )
        {
FAILED_ARRAY:
          code = cvt_failed;
          break;
        }
        if ( sym.get_count(&count) != S_OK )
          goto FAILED_ARRAY;
        mods |= el.type.get_modifiers(); // propagate element type to array
        if ( !out->type.create_array(el.type, count) )
          goto FAILED_ARRAY;
      }
      break;

    case SymTagFunctionType:
      {
        tpinfo_t itp2;
        if ( !get_symbol_type(&itp2, sym, NULL) ) // return type
        {
          code = cvt_failed;
          break;
        }
        func_type_data_t fi;
        fi.rettype = itp2.type;
        if ( fi.rettype.is_array() )
        {
          code = cvt_failed; // arrays can not be returned
          break;
        }
        DWORD cc0;
        fi.cc = CM_CC_UNKNOWN;
        if ( sym.get_callingConvention(&cc0) == S_OK )
          fi.cc = convert_cc(cc0);

        if ( get_cc(fi.cc) != CM_CC_VOIDARG )
        {
          retrieve_arguments(sym, fi, parent);
          // if arg has unknown/invalid argument => convert to ellipsis
          for ( func_type_data_t::iterator i = fi.begin(); i != fi.end(); i++ )
          {
            if ( i->type.empty() )
            {
              // If the CC is cdecl, empty arguments represent an ellipsis.
              // Otherwise, it's likely to be a C-type function
              // with unknown number of arguments, such as 'foo()'
              // (as opposed to 'foo(void)'), and which might not have a cdecl
              // calling convention. E.g., pc_win32_appcall.pe's 'FARPROC':
              // "int (FAR WINAPI * FARPROC) ()", which is a stdcall.
              cm_t cc = get_cc(fi.cc);
              if ( cc == CM_CC_CDECL || inf.is_64bit() && cc == CM_CC_FASTCALL )
                fi.cc = CM_CC_ELLIPSIS;
              // remove the ellipsis and any trailing arguments
              fi.erase(i, fi.end());
              break;
            }
          }
          // is there an implicit "result" pointer passed?
          if ( is_complex_return(sym) )
          {
            // complex return type: what's returned is actually a pointer
            fi.rettype.create_ptr(fi.rettype);
            funcarg_t retarg;
            retarg.type = fi.rettype;
            retarg.name = "result";
            fi.insert(fi.begin(), retarg);
          }
          // is there an implicit "this" passed?
          // N.B.: 'this' is passed before the implicit result, if both are present
          tinfo_t class_type;
          if ( is_member_func(&class_type, sym, parent) )
          {
            class_type.create_ptr(class_type);
            funcarg_t thisarg;
            thisarg.type = class_type;
            thisarg.name = "this";
            if ( parent != NULL )
            {
              this_seeker_t ts(this);
              pdb_access->iterate_children(*parent, SymTagData, ts);
              thisarg.argloc = ts.thisarg.argloc;
              if ( thisarg.argloc.is_stkoff() )
              { // shift the remaining stkargs
                int delta = thisarg.type.get_size();
                for ( int i=0; i < fi.size(); i++ )
                {
                  funcarg_t &fa = fi[i];
                  if ( fa.argloc.is_stkoff() )
                    fa.argloc.set_stkoff(fa.argloc.stkoff()+delta);
                }
              }
            }
            fi.insert(fi.begin(), thisarg);
          }
          if ( is_user_cc(fi.cc) )
          {
            // specify argloc for the return value
            size_t retsize = fi.rettype.get_size();
            if ( retsize <= 1 )
              fi.retloc._set_reg1(R_al);
            else if ( retsize <= 4 )
              fi.retloc._set_reg1(R_ax);
            else
              fi.retloc._set_reg2(R_ax, R_dx);

            // __usercall must have all its arguments location
            // specified.
            // It happens that some PDB information,
            // generated at compile-time, does _not_ hold info
            // about all the parameters. For example,
            // a function declared as:
            //   void BlockOpVPSDec(char *p, uint32 dwLength, char btXorKey, char /*foo*/)
            // will end up having only its first three arguments
            // properly defined in the PDB (because the fourth is
            // not used, its location is not defined.)
            // Still, in order for 'build_func_type2()' to work,
            // it requires all valid argloc_t instances. Thus,
            // we remove invalid ones completely.
            for ( int i = fi.size() - 1; i >= 0; --i )
              if ( fi[i].argloc.is_badloc() )
                fi.erase(fi.begin() + i);
          }
          out->type.create_func(fi);
        }
      }
      break;

    case SymTagUDT:
    case SymTagBaseClass:
      code = convert_udt(&out->type, sym, size);
      break;
    case SymTagEnum:
      {
        struct name_value_collector_t : public pdb_access_t::children_visitor_t
        {
          const til_builder_t *tb;
          enum_type_data_t ei;
          const type_t *idatype;
          HRESULT visit_child(pdb_sym_t &child)
          {
            enum_member_t &em = ei.push_back();
            child.get_name(&em.name);
            em.value = tb->get_variant_long_value(child);
            if ( get_named_type(tb->ti, em.name.c_str(), NTF_SYMM, &idatype) )
              return E_FAIL;
            return S_OK;
          }
          name_value_collector_t(const til_builder_t *_tb)
            : tb(_tb), idatype(NULL) {}
        };
        name_value_collector_t nvc(this);
        HRESULT hr = pdb_access->iterate_children(sym, SymTagNull, nvc);
        if ( FAILED(hr) )               // symbol already exists?
        {                               // just reuse the existing enum
          if ( !out->type.deserialize(ti, &nvc.idatype) ) // this is not quite correct
            INTERR(30407);
          qstring n1;
          if ( out->type.get_type_name(&n1) )
          {
            qstring nm;
            get_symbol_name(sym, nm);
            if ( nm == n1 )
              code = cvt_typedef;       // avoid circular dependencies
          }
        }
        else
        {
          out->type.create_enum(nvc.ei);
        }
      }
      break;

    case SymTagTypedef:
    case SymTagFunctionArgType:
    case SymTagFunction:
    case SymTagData:
      if ( !get_symbol_type(out, sym, NULL) )
        code = cvt_failed;
      else if ( out->type.is_decl_typedef() )
        code = cvt_typedef; // signal that this is a typedef
      break;

    case SymTagVTable:
      if ( parent == NULL || make_vtable_struct(&out->type, *parent) != cvt_ok )
        out->type.create_typedef(ti, fake_vtable_type);
      break;
  }
  if ( code != cvt_failed && mods != 0 )
    out->type.set_modifiers(mods);
  // todo: check that the type has the expected size
  return code;
}

//----------------------------------------------------------------------
cvt_code_t til_builder_t::convert_type(
        tpinfo_t *out,
        pdb_sym_t &sym,
        pdb_sym_t *parent,
        DWORD type,
        DWORD tag)
{
  if ( level == 200 )
    return cvt_failed;
  level++;
  typemap_t::iterator p = typemap.find(type);
  if ( p == typemap.end() )
  {
    tpinfo_t tpi;
    tpi.cvt_code = really_convert_type(&tpi, sym, parent, tag);
    p = typemap.insert(std::make_pair(type, tpi)).first;
  }
  tpinfo_t &tpi = p->second;
  *out = tpi;
  level--;
  return tpi.cvt_code;
}

//----------------------------------------------------------------------
bool til_builder_t::begin_creation(DWORD tag, const qstring &name, uint32 *p_id)
{
  if ( tag != SymTagFunction )
  {
    uint32 id = *p_id;
    creating_t::iterator c = creating.find(name);
    if ( c != creating.end() ) // recursive call
    {
      if ( !c->second )        // allocated?
      {
        if ( id == 0 )
          id = alloc_type_ordinal(ti); // have to create the type id immediately
        c->second = id;
        QASSERT(490, id != 0);
//        msg("%d %s: prematurely mapped to %d\n", type, name.c_str(), c->second);
      }
      *p_id = c->second;
      return false;
    }
    creating.insert(std::make_pair(name, id)); // add to the 'creating' list
  }
  return true;
}

//----------------------------------------------------------------------------
uint32 til_builder_t::end_creation(const qstring &name)
{
  uint32 id = 0;
  creating_t::iterator c = creating.find(name);
  if ( c != creating.end() )
  {
    id = c->second;
    creating.erase(c);
  }
  if ( id == 0 )
  {
    id = alloc_type_ordinal(ti); // have to create the type id immediately
    QASSERT(491, id != 0);
//    msg("%d %s: mapped to %d\n", type, name.c_str(), id);
  }
  return id;
}


//----------------------------------------------------------------------------
cvt_code_t til_builder_t::handle_overlapping_members(udt_type_data_t *udt) const
{
  qstack<qstring> union_names;
  udt_type_data_t::iterator end = udt->end();
  udt_type_data_t::iterator first = end; // !=end => collecting union members
  udt_type_data_t::iterator last = end;  // member with highest ending offset so far
  for ( udt_type_data_t::iterator p=udt->begin(); ; ++p )
  {
    if ( p != udt->end() )
    {
      if ( is_unnamed_tag_typedef(p->type) )
        handle_unnamed_overlapping_member(udt, &union_names, &p->name);
      if ( last == end )
      {
        last = p;
        continue;
      }
      if ( last->end() > p->begin() )
      { // found an overlap. however, we ignore base classes, in order
        // not to convert them into unions
        if ( first == end && !last->is_baseclass() )
          first = last;
        goto NEXT;
      }
    }
    if ( first != end )
    {
      int fidx = first - udt->begin();
      uval_t off = first->offset;
      // if we have a bitfield, include the adjacent bitfields in the new type
      int bf_typesize = 0;
      for ( udt_type_data_t::iterator q=first; q != p; ++q )
      {
        if ( q->is_bitfield() )
        {
          bf_typesize = q->type.get_size();
          break;
        }
      }
      if ( bf_typesize != 0 )
      {
        while ( fidx > 0
             && (first-1)->is_bitfield()
             && (first-1)->type.get_size() == bf_typesize )
        {
          --fidx;
          --first;
          off = first->offset;
        }
        while ( p != end
             && p->is_bitfield()
             && p->type.get_size() == bf_typesize )
        {
          ++p;
        }
      }
      // range [first, p) is overlapping, create a new type for it
      tinfo_t unitif;
      size_t union_size;
      cvt_code_t code = create_union(&unitif, &union_size, first, p);
      if ( code != cvt_ok )
        return code;
      udt->erase(first+1, p);
      end = udt->end();
      first = end;
      last = end;
      p = udt->begin() + fidx;
      p->offset = off & ~7;
      p->size = uint64(union_size) * 8;
      if ( union_names.empty() )
        p->name.sprnt("___u%d", fidx);
      else
        p->name = union_names.pop();
      p->type = unitif;
    }
    if ( p == end )
      break;
NEXT:
    if ( last->end() < p->end() )
      last = p;
  }
  return cvt_ok;
}


//----------------------------------------------------------------------------
void til_builder_t::handle_function_type(pdb_sym_t &fun_sym, ea_t ea)
{
  struct local_data_creator_t : public pdb_access_t::children_visitor_t
  {
    virtual HRESULT visit_child(pdb_sym_t &sym)
    {
      DWORD tag = 0;
      HRESULT hr = sym.get_symTag(&tag);
      if ( FAILED(hr) )
        return hr;

      switch ( tag )
      {
        case SymTagBlock: // nested blocks
          return tb->pdb_access->iterate_children(sym, SymTagNull, *this);
        case SymTagFuncDebugStart:
        case SymTagFuncDebugEnd:
          return S_OK;    // ignore these for the moment
      }

      DWORD loc_type;
      if ( sym.get_locationType(&loc_type) != S_OK )
        return S_OK; // optimized away?

      return tb->handle_function_child(fun_sym, ea, sym, tag, loc_type);
    }
    local_data_creator_t(til_builder_t *_tb, pdb_sym_t &_fun_sym, ea_t _ea) :
      tb(_tb), fun_sym(_fun_sym), ea(_ea) {}
    til_builder_t *tb;
    pdb_sym_t &fun_sym;
    ea_t ea;
  };
  local_data_creator_t ldc(this, fun_sym, ea);
  pdb_access->iterate_children(fun_sym, SymTagNull, ldc);
}


//----------------------------------------------------------------------------
void til_builder_t::type_created(
        ea_t /*ea*/,
        int /*id*/,
        const char * /*name*/,
        const tinfo_t & /*ptr*/) const
{
}


//----------------------------------------------------------------------------
HRESULT til_builder_t::handle_function_child(
        pdb_sym_t & /*fun_sym*/,
        ea_t ea,
        pdb_sym_t &child_sym,
        DWORD child_tag,
        DWORD child_loc_type)
{
  switch ( child_loc_type )
  {
    case LocIsConstant:
      break; // we ignore function level constants

    case LocIsStatic:
    case LocIsTLS:              // not tested
      handle_symbol(child_sym);
      break;

    case LocIsEnregistered:
    case LocIsRegRel:
      break;

    default:
      ask_for_feedback("pdb: unsupported location type %d, tag %d at %a", child_loc_type, child_tag, ea);
      break;
  }
  return S_OK;
}


//----------------------------------------------------------------------------
cvt_code_t til_builder_t::create_udt_ref(tinfo_t *out, udt_type_data_t *udt, int udt_kind) const
{
  tinfo_t tif;
  cvt_code_t code = create_udt(&tif, udt, udt_kind);
  if ( code != cvt_ok )
    return code;

  qtype type, fields;
  tif.serialize(&type, &fields);

  qstring name;
  build_anon_type_name(&name, type.begin(), fields.begin());
  uint32 id = get_type_ordinal(ti, name.c_str());
  if ( id == 0 )
  {
    id = alloc_type_ordinal(ti);
    if ( set_numbered_type(ti, id, NTF_NOBASE|NTF_FIXNAME, name.c_str(), type.begin(), fields.begin()) != TERR_OK )
      return cvt_failed;
    type_created(BADADDR, id, NULL, tif);
  }

  out->create_typedef(ti, id);
  return cvt_ok;
}

//----------------------------------------------------------------------------
bool til_builder_t::retrieve_type(
        tpinfo_t *out,
        pdb_sym_t &sym,
        pdb_sym_t *parent,
        int *p_id)
{
  if ( p_id != NULL )
    *p_id = -1;

  // id -> unknown typedef?
  DWORD sym_id = 0;
  sym.get_symIndexId(&sym_id);
  tpdefs_t::iterator q = tpdefs.find(sym_id);
  if ( q != tpdefs.end() )
  {
    const char *name = q->second.c_str();
    out->type.create_typedef(ti, name);
    return true;
  }

  uint32 id = idmap[sym_id];
  if ( id == 0 )
  {
    DWORD tag = 0;
    HRESULT hr = sym.get_symTag(&tag);
    if ( FAILED(hr) )
      return false;

    qstring ns;
    bool is_unnamed = get_symbol_name(sym, ns);
    //msg("ID: %d -> %s\n", sym_id, ns.begin());
    if ( tag == SymTagVTable && ns.empty() )
    {
      if ( parent != NULL )
        get_symbol_name(*parent, ns);

      if ( ns.empty() )
        ns.sprnt("vtable-%d", unnamed_idx++);
      else
        ns.append("Vtbl");

      is_unnamed = false;
    }

    // udt fields and simple types are converted without allocating
    // an ordinal number
    if ( tag == SymTagData || ns.empty() )
      return convert_type(out, sym, parent, sym_id, tag) != cvt_failed;

    // give a unique name to unnamed types so they can be told apart
    // this is a temporary name, it will be replaced by $hex..
    if ( is_unnamed )
      ns.sprnt("unnamed-%d", unnamed_idx++);
    else
      validate_name(&ns, VNT_TYPE);

    // some types can be defined multiple times. check if the name is already defined
    bool defined_correctly = false;
    bool defined_wrongly = false;
    id = get_type_ordinal(ti, ns.c_str());
    if ( id != 0 )
    {
      tinfo_t tif;
      tif.create_typedef(ti, id);
      if ( tif.get_realtype() == BT_UNK )
        defined_wrongly = true;
      else
        defined_correctly = true;
    }
    if ( !defined_correctly && begin_creation(tag, ns, &id) )
    {
      // now convert the type information, recursive types won't bomb
      tpinfo_t tpi2;
      cvt_code_t cc = convert_type(&tpi2, sym, parent, sym_id, tag);
      if ( cc != cvt_ok ) // failed or typedef
      {
        creating.erase(ns);
        if ( cc == cvt_failed )
          return false;
        // cvt_typedef
        tpdefs[sym_id] = ns; // reference to unknown typedef
RETT2:
        out->type = tpi2.type;
        return true;
      }

      qtype type, fields;
      if ( !tpi2.type.serialize(&type, &fields) )
        INTERR(30408);

      // Function types are saved as symbols
      if ( tag == SymTagFunction )
      {
        // the following may fail because of c++ overloaded functions
        // do not check the error code - we can not help it
        tpi2.type.set_symbol_type(ti, ns.c_str(), NTF_SYMM);
        type_created(BADADDR, 0, ns.c_str(), tpi2.type);
        goto RETT2;
      }

      bool reuse_anon_type = false;
      if ( is_unnamed ) // this type will be referenced, so create a name for it
      {
        build_anon_type_name(&ns, type.begin(), fields.begin());
        id = get_type_ordinal(ti, ns.c_str());
        if ( id != 0 ) // this type already exists, just reuse it
        {
          creating.erase(ns);
          reuse_anon_type = true;
        }
      }
      if ( !reuse_anon_type )
      {
        id = end_creation(ns);
        int ntf_flags = NTF_NOBASE|NTF_FIXNAME;
        if ( defined_wrongly )
          ntf_flags |= NTF_REPLACE;
        if ( set_numbered_type(ti, id, ntf_flags,
                               ns.empty() ? NULL : ns.c_str(),
                               type.begin(),
                               fields.begin()) != TERR_OK )
        {
          return 0;
        }
      }
      if ( is_unnamed )
        unnamed_types.insert(id);
//      msg("%d: %s\n  name: %s\n", id, tpi2.dstr(), ns.c_str());
      type_created(BADADDR, id, NULL, tpi2.type);
    }
  }
  if ( p_id != NULL )
    *p_id = id;
  out->type.create_typedef(ti, id);
  return true;
}


//----------------------------------------------------------------------------
bool til_builder_t::handle_symbol_at_ea(pdb_sym_t &/*sym*/, DWORD /*tag*/, DWORD /*id*/, ea_t /*ea*/, qstring & /*name*/)
{
  return true;
}


//----------------------------------------------------------------------------
HRESULT til_builder_t::handle_symbol(pdb_sym_t &sym)
{
  DWORD id;
  HRESULT hr = sym.get_symIndexId(&id);
  if ( FAILED(hr) )
    return hr;

  if ( handled.find(id) != handled.end() )
    return S_OK;
  handled.insert(id);

  DWORD tag = 0;
  hr = sym.get_symTag(&tag);
  if ( FAILED(hr) )
    return hr;

  switch ( tag )
  {
    case SymTagNull:
    case SymTagExe:
    case SymTagCompiland:
    case SymTagCompilandEnv:
    case SymTagCustom:
    case SymTagCustomType:
    case SymTagManagedType:
    case SymTagUDT:
    case SymTagEnum:
    case SymTagFunctionType:
    case SymTagPointerType:
    case SymTagArrayType:
    case SymTagBaseType:
    case SymTagTypedef:
    case SymTagBaseClass:
    case SymTagFunctionArgType:
    case SymTagUsingNamespace:
    case SymTagVTableShape:
    case SymTagDimension:
      return S_OK;
    case SymTagCompilandDetails:
      {
        DWORD backEndVer;
        if ( pdb_access->get_machine_type() == CV_CFL_80386 && sym.get_backEndMajor(&backEndVer) == S_OK )
          enregistered_bug = backEndVer <= 13;
      }
      return S_OK;
    default:
      break;
  }

  DWORD off = 0;
  hr = sym.get_relativeVirtualAddress(&off);
  if ( hr == S_OK )
  {
    ea_t ea = get_load_address() + off;
    if ( ea != 0 )
    {
      qstring name;
      sym.get_name(&name);
      handle_symbol_at_ea(sym, tag, id, ea, name);
    }
  }
  return S_OK;
}


//----------------------------------------------------------------------
// Each time we encounter a toplevel type/func/whatever, we want to make
// sure the UI has had a chance to refresh itself.
struct toplevel_children_visitor_t : public pdb_access_t::children_visitor_t
{
  virtual HRESULT visit_child(pdb_sym_t &sym)
  {
    user_cancelled();
    return do_visit_child(sym);
  }

  virtual HRESULT do_visit_child(pdb_sym_t &sym) = 0;
};

//-------------------------------------------------------------------------
struct symbol_handler_t : public toplevel_children_visitor_t
{
  virtual HRESULT do_visit_child(pdb_sym_t &sym)
  {
    return tb->handle_symbol(sym);
  }
  symbol_handler_t(til_builder_t *_tb) : tb(_tb) {}
  til_builder_t *tb;
};

//-------------------------------------------------------------------------
HRESULT til_builder_t::handle_symbols(pdb_sym_t &global_sym)
{
  symbol_handler_t cp(this);
  HRESULT hr;
  while ( true )
  {
    hr = pdb_access->iterate_subtags(global_sym, SymTagNull, cp);
    if ( FAILED(hr) )
      break;
    if ( !iterate_symbols_once_more(global_sym) )
      break;
  }
  return hr;
}

//-------------------------------------------------------------------------
HRESULT til_builder_t::handle_publics(pdb_sym_t &global_sym)
{
  symbol_handler_t cp(this);
  return pdb_access->iterate_children(global_sym, SymTagPublicSymbol, cp);
}

//-------------------------------------------------------------------------
HRESULT til_builder_t::handle_globals(pdb_sym_t &global_sym)
{
  symbol_handler_t cp(this);
  return pdb_access->iterate_children(global_sym, SymTagData, cp);
}


//----------------------------------------------------------------------
HRESULT til_builder_t::handle_types(pdb_sym_t &global_sym)
{
  struct type_importer_t : public toplevel_children_visitor_t
  {
    til_builder_t *tb;
    int counter;
    virtual HRESULT do_visit_child(pdb_sym_t &sym)
    {
      tpinfo_t tpi;
      if ( tb->retrieve_type(&tpi, sym, parent, NULL) )
        counter++;
      return S_OK;
    }
    type_importer_t(til_builder_t *_tb) : tb(_tb), counter(0) {}
  };
  type_importer_t timp(this);
  HRESULT hr = pdb_access->iterate_children(global_sym, SymTagEnum, timp);
  if ( hr == S_OK )
    hr = pdb_access->iterate_children(global_sym, SymTagUDT, timp);
  if ( hr == S_OK )
    hr = pdb_access->iterate_children(global_sym, SymTagTypedef, timp);
  msg("PDB: loaded %d type%s\n", timp.counter, timp.counter != 1 ? "s" : "");
  return hr;
}


//----------------------------------------------------------------------------
HRESULT til_builder_t::before_iterating(pdb_sym_t &)
{
  return S_OK;
}


//----------------------------------------------------------------------------
HRESULT til_builder_t::after_iterating(pdb_sym_t &)
{
  return S_OK;
}

//----------------------------------------------------------------------------
HRESULT til_builder_t::build(pdb_sym_t &global_sym)
{
  HRESULT hr = before_iterating(global_sym);
  if ( hr == S_OK )
    hr = handle_types(global_sym);
  if ( (pdb_access->pdbargs.flags & PDBFLG_ONLY_TYPES) == 0 )
  {
    if ( hr == S_OK )
      hr = handle_symbols(global_sym);
    if ( hr == S_OK )
      hr = handle_globals(global_sym);
    // handle_globals() will set the type and undecorated name for globals,
    // and handle_publics() will set the decorated name for public symbols.
    // We want both the type (from handle_globals()) and the decorated symbol
    // name (from handle_publics()), since that gives the user more information
    // about the variable and enables FLIRT to match rulefuncs based on the
    // symbol name.
    // For example, @__security_check_cookie@4 is used as a rulefunc by FLIRT,
    // and that won't match with the undecorated name __security_check_cookie.
    // Therefore, handle_publics() must be called *after* handle_globals().
    if ( hr == S_OK )
      hr = handle_publics(global_sym);
  }
  if ( hr == S_OK )
    hr = after_iterating(global_sym);
  return hr;
}
