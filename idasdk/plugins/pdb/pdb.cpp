
// IDA plugin to load function name information from PDB files
//      26-02-2008 Complete rewrite to use DIA API

#include <set>
#include <map>

#ifndef __NT__
#  define ENABLE_REMOTEPDB
#endif
#define PDB_PLUGIN

#include "cvconst.h"

#include <ida.hpp>
#include <idp.hpp>
#include <err.h>
#include <md5.h>
#include <dbg.hpp>
#include <auto.hpp>
#include <name.hpp>
#include <frame.hpp>
#include <loader.hpp>
#include <diskio.hpp>
#include <struct.hpp>
#include <typeinf.hpp>
#include <demangle.hpp>
#include "../../ldr/pe/pe.h"
#include "../../include/intel.hpp"
#include "common.h"
#include <workarounds.hpp>

// PDB search path (in _NT_SYMBOL_PATH format)
static char full_sympath[QMAXPATH];
static void init_sympaths(void);

#ifndef ENABLE_REMOTEPDB
#  include "oldpdb.h"
#  ifdef ENABLE_SRCDBG
#    include "sip.cpp"
#  endif
#else
#  include "../../ldr/pe/mycor.h"
#endif
#include "common.cpp"

#include "pdbreg.hpp"
#include "pdb.hpp"

static peheader_t pe;
static char download_path[QMAXPATH];
static char pdb_remote_server[QMAXPATH];
//lint -esym(551,pdb_remote_port)
static int  pdb_remote_port = DEBUGGER_PORT_NUMBER;
//lint -esym(551,pdb_remote_port_64)
static int  pdb_remote_port_64 = -1;
static char pdb_remote_passwd[QMAXPATH];

typedef std::map<ea_t, qstring> namelist_t;
static namelist_t namelist;

#define MAX_DISP_PATH 80

#ifndef ENABLE_REMOTEPDB

inline bool is_mips(DWORD machineType)
{
  return machineType == CV_CFL_MIPS
      || machineType == CV_CFL_MIPSR4000
      || machineType == CV_CFL_MIPS16
      || machineType == CV_CFL_MIPS32
      || machineType == CV_CFL_MIPS64
      || machineType == CV_CFL_MIPSI
      || machineType == CV_CFL_MIPSII
      || machineType == CV_CFL_MIPSIII
      || machineType == CV_CFL_MIPSIV
      || machineType == CV_CFL_MIPSV;
}

#endif // #ifndef ENABLE_REMOTEPDB

//-------------------------------------------------------------------------
//#define  CHECK_CREATED_TYPES
#ifdef CHECK_CREATED_TYPES
struct type_to_check_t
{
  // one of the following 3 will be valid:
  ea_t ea;
  int id;
  qstring name;

  // the type itself
  tinfo_t type;
};
DECLARE_MOVABLE_TYPE(type_to_check_t);

static qvector<type_to_check_t> types_to_check;

static void check_tinfo(ea_t ea, int id, const char *name, const tinfo_t &tif)
{
  type_to_check_t &tc = types_to_check.push_back();
  tc.ea = ea;
  tc.id = id;
  tc.name = name;
  tc.type = tif;
}

static void check_added_types(void)
{
  static int n = 0;
  for ( int i=0; i < types_to_check.size(); i++ )
  {
    type_to_check_t &tc = types_to_check[i];
    if ( !tif.is_correct() )
    {
      msg("%d: INCORRECT TYPE ", n);
      if ( !tc.name.empty() )
        msg("%s", tc.name.begin());
      else if ( tc.ea != BADADDR )
        msg("%a", tc.ea);
      else
        msg("#%d", tc.id);
      qstring res;
      tif.print(&res);
      msg(": %s\n", res.c_str());
      n++;
    }
  }
}
#else
inline void check_tinfo(ea_t,int,const char*,const tinfo_t &) {}
inline void check_added_types(void) {}
#endif

//----------------------------------------------------------------------
bool looks_like_function_name(const char *name)
{
  // this is not quite correct: the presence of an opening brace
  // in the demangled name indicates a function
  // we can have a pointer to a function and there will be a brace
  // but this logic is not applied to data segments
  if ( strchr(name, '(') != NULL )
    return true;

  // check various function keywords
  static const char *const keywords[] =
  {
    "__cdecl ",
    "public: ",
    "virtual ",
    "operator ",
    "__pascal ",
    "__stdcall ",
    "__thiscall ",
  };
  for ( int i=0; i < qnumber(keywords); i++ )
    if ( strstr(name, keywords[i]) != NULL )
      return true;
  return false;
}

//----------------------------------------------------------------------
bool check_for_ids(ea_t ea, const char *name)
{
  // Seems to be a GUID?
  const char *ptr = name;
  while ( *ptr == '_' )
    ptr++;

  static const char *const guids[] = { "IID", "DIID", "GUID", "CLSID", "LIBID", NULL };
  static const char *const sids[] = { "SID", NULL };

  struct id_info_t
  {
    const char *const *names;
    const char *type;
  };
  static const id_info_t ids[] =
  {
    { guids, "GUID x;" },
    { sids,  "SID x;" },
  };
  static bool checked_types = false;
  static bool has_sid       = false;
  if ( !checked_types )
  {
    if ( default_compiler() == COMP_UNK )
      set_compiler_id(COMP_MS);
    if ( get_named_type(idati, "GUID", NTF_TYPE) == 0 )
    {
      static const char decl[] = "typedef struct _GUID { unsigned long  Data1; unsigned short Data2; unsigned short Data3; unsigned char Data4[8];} GUID;";
      h2ti(idati, NULL, decl, HTI_DCL, NULL, NULL, msg);
    }
    // SID type is pretty complex, so we won't add it manually but just check if it exists
    has_sid = get_named_type(idati, "SID", NTF_TYPE) != 0;
    checked_types = true;
  }
  for ( int k=0; k < qnumber(ids); k++ )
  {
    if ( k == 1 && !has_sid )
      continue;
    for ( const char *const *p2=ids[k].names; *p2; p2++ )
    {
      const char *guid = *p2;
      size_t len = strlen(guid);
      if ( strncmp(ptr, guid, len) == 0
        && (ptr[len] == '_' || ptr[len] == ' ') ) // space can be in demangled names
      {
        if ( ph.ti() )
          apply_cdecl2(idati, ea, ids[k].type);
        return true;
      }
    }
  }
  if ( strncmp(name, "_guid", 5) == 0 )
  {
    if ( ph.ti() )
      apply_cdecl2(idati, ea, ids[0].type);
    return true;
  }
  return false;
}

//----------------------------------------------------------------------
static bool is_data_prefix(ea_t ea, const char *name)
{
  static const char *const data_prefixes[] =
  {
    "__IMPORT_DESCRIPTOR",
    //"__imp_",             //imported function pointer
  };
  for ( int i=0; i < qnumber(data_prefixes); i++ )
    if ( strncmp(name, data_prefixes[i], strlen(data_prefixes[i])) == 0 )
      return true;

  // __real@xxxxxxxx            - floating point number, 4 bytes
  // __real@xxxxxxxxxxxxxxxx    - floating point number, 8 bytes
  if ( strncmp(name, "__real@", 7) == 0 )
  {
    const char *ptr = name + 7;
    const char *hex = ptr;
    while ( qisxdigit(*ptr) )
      ptr++;
    size_t len = ptr - hex;
    if ( len == 8 )
    {
      doFloat(ea, 4);
      return true;
    }
    if ( len == 16 )
    {
      doDouble(ea, 8);
      return true;
    }
    if ( len == 20 )
    { // i haven't seen this, but probably it exists too
      doTbyt(ea, 10);
      return true;
    }
  }
  return false;
}

//----------------------------------------------------------------------
// maybe_func: -1:no, 0-maybe, 1-yes, 2:no,but iscode
bool apply_name_in_idb(ea_t ea, const qstring &name, int maybe_func, uint32 the_machine_type)
{
  showAddr(ea); // so the user doesn't get bored

  char buf[MAXSTR];
  buf[0] = '\0';
  // check for meaningless 'string' names
  if ( strncmp(name.c_str(), "??_C@_", 6) == 0 )
  {
      // ansi:    ??_C@_0<len>@xxx
      // unicode: ??_C@_1<len>@xxx
      // TODO: parse length?
      make_ascii_string(ea, 0, name[6]=='1' ? ASCSTR_UNICODE : ASCSTR_C );
      return true;
  }
  if ( maybe_func <= 0 && demangle(buf, sizeof(buf), name.c_str(), MNG_SHORT_FORM) > 0 )
  {
    if ( strcmp(buf, "`string'") == 0 )
    {
      size_t s1 = get_max_ascii_length(ea, ASCSTR_C);
      size_t s2 = get_max_ascii_length(ea, ASCSTR_UNICODE);
      make_ascii_string(ea, 0, s1 >= s2 ? ASCSTR_C : ASCSTR_UNICODE);
      return true;
    }
  }

  // Renaming things immediately right here can lead to bad things.
  // For example, if the name is a well known function name, then
  // ida will immediately try to create a function. This is a bad idea
  // because IDA does not know exact function boundaries and will try
  // to guess them. Since the database has little information yet, there
  // is a big chance that the function will end up to be way too long.
  // That's why we collect names here and will rename them later.
  namelist[ea] = name;

  if ( check_for_ids(ea, name.c_str())
    || check_for_ids(ea, buf)
    || is_data_prefix(ea, name.c_str())
    || maybe_func < 0 )
  {
    set_notcode(ea); // should not be code
    return true;
  }
  if ( maybe_func == 0 && get_mangled_name_type(name.c_str()) == MANGLED_DATA )
  {
    // NB: don't call set_notcode() here
    // since demangler may give false positives
    return true;
  }

  // do not automatically create functions in debugger segments
  segment_t *s = getseg(ea);
  if ( s == NULL || !s->is_loader_segm() )
    return true;

  // ARMv7 PDBs don't use bit 0 for Thumb mode
  if ( (ph.id == PLFM_ARM && the_machine_type != CV_CFL_ARM7) || ph.id == PLFM_MIPS )
  {
    // low bit is Thumb/MIPS16 mode
    bool func16 = (ea & 1) != 0;
    ea &= ~1;
    if ( func16 )
    {
      // move the entry in namelist
      namelist.erase(ea|1);
      namelist[ea] = name;
    }
  }

  if ( maybe_func == 0 )
  {
    do
    {
      // check for function telltales
      if ( segtype(ea) != SEG_DATA
        && demangle(buf, sizeof(buf), name.c_str(), MNG_LONG_FORM) > 0
        && looks_like_function_name(buf) )
      {
        maybe_func = 1;
        break;
      }

      int stype = segtype(ea);
      if ( stype != SEG_NORM && stype != SEG_CODE ) // only for code or normal segments
        break;

      if ( !decode_insn(ea) )
        break;

      if ( !ph.notify(ph.is_sane_insn, 1) )
        break;
      maybe_func = 1;
    } while ( false );

    if ( maybe_func == 1 )
      auto_make_proc(ea); // fixme: when we will implement lvars, we have to process these request
                          // before handling lvars
  }
  return true;
}


// Because we need to be able to call the 'old' pdb plugin
// code, which knows nothing about the til_builder_t (and
// thus its 'machine_type' field, and also because, at the
// very time we call the old pdb code, our til_builder_t
// instance will have been long forgotten and destroyed,
// we must keep this machine type information somewhere.
static uint32 g_machine_type = CV_CFL_80386;

//----------------------------------------------------------------------------
bool apply_name(ea_t ea, const qstring &name, int maybe_func)
{
  return apply_name_in_idb(ea, name, maybe_func, g_machine_type);
}

//----------------------------------------------------------------------
void load_vc_til(void)
{
  // We managed to load the PDB file.
  // It is very probably that the file comes from VC
  // Load the corresponding type library immediately
  if ( ph.id == PLFM_386 && pe.signature == PEEXE_ID )
  {
    if ( pe.is_userland() )
      add_til2(pe.is_pe_plus() ? "vc10_64" : "mssdk", ADDTIL_INCOMP);
    else
      add_til2(pe.is_pe_plus() ? "ntddk64" : "ntddk", ADDTIL_INCOMP);
  }
}

//----------------------------------------------------------------------------
class pdb_til_builder_t : public til_builder_t
{
  int npass;
public:
  pdb_til_builder_t(til_t *_ti, pdb_access_t *_pa)
    : til_builder_t(_ti, _pa), npass(0) {}

  virtual HRESULT before_iterating(pdb_sym_t &global_sym);
  virtual bool iterate_symbols_once_more(pdb_sym_t & /*global_sym*/)
  {
    handled.clear();
    return ++npass == 1;
  }
  virtual void type_created(ea_t ea, int id, const char *name, const tinfo_t &tif) const;
  virtual bool handle_symbol_at_ea(pdb_sym_t &sym, DWORD tag, DWORD id, ea_t ea, qstring &name);
  virtual void handle_function_type(pdb_sym_t &fun_sym, ea_t ea);
  virtual HRESULT handle_function_child(
        pdb_sym_t &fun_sym,
        ea_t ea,
        pdb_sym_t &child_sym,
        DWORD child_tag,
        DWORD child_loc_type);
};

//----------------------------------------------------------------------------
HRESULT pdb_til_builder_t::before_iterating(pdb_sym_t &)
{
  load_vc_til();
  return S_OK;
}

//----------------------------------------------------------------------------
void pdb_til_builder_t::type_created(ea_t ea, int id, const char *name, const tinfo_t &tif) const
{
  check_tinfo(ea, id, name, tif);
}

//----------------------------------------------------------------------------
// add the annotation strings to 'ea'
// following types are commonly used in windows drivers
// 1) assertion:
// #define NT_ASSERT(_exp)
//     ((!(_exp)) ?
//         (__annotation(L"Debug", L"AssertFail", L#_exp),
//          DbgRaiseAssertionFailure(), FALSE) :
//         TRUE)
// 2) trace message
//
//   TMF:
//   2158e7d3-9867-cde3-18b5-9713c628abdf TEEDriver // SRC=Queue.c MJ= MN=
//   #typev Queue_c2319 207 "%0PowerDown = %10!x!" //   LEVEL=TRACE_LEVEL_VERBOSE FLAGS=TRACE_QUEUE
//   {
//   devExt->powerDown, ItemLong -- 10
//   }, Constant
//
// 3) trace message control
// WPP_DEFINE_CONTROL_GUID(Name,Guid,Bits) __annotation(L"TMC:", WPP_GUID_WTEXT Guid, _WPPW(WPP_STRINGIZE(Name)) Bits WPP_TMC_ANNOT_SUFIX);
//  expands into:
//
//  TMC:
//  0b67e6f7-ae91-470c-b4b6-dcd6a9034e18
//  TEEDriverTraceGuid
//  MYDRIVER_ALL_INFO
//  TRACE_DRIVER
//  TRACE_DEVICE
//  [..]
//  TRACE_BUS_DRIVER_LAYER
//
// In all other cases we just use plain __annotation(a,b,c,...)
// TODO: use anterior lines for big annotations (over 1KB)
static void apply_annotation(ea_t ea, const qstrvec_t &params)
{
  if ( params.empty() )
    return;

  qstring full_cmt;
  if ( params.size() >= 3 && params[0] == "Debug" && params[1] == "AssertFail" )
  {
    full_cmt.sprnt("NT_ASSERT(\"%s\"", params[2].c_str());
    for ( size_t i = 3; i < params.size(); i++ )
      full_cmt.cat_sprnt(",\n  \"%s\"", params[i].c_str());
    full_cmt.append(")");
  }
  else if ( params[0] == "TMF:" )
  {
    full_cmt = "__annotation(\"TMF:\"";
    bool add_newline = true;
    for ( size_t i = 1; i < params.size(); i++ )
    {
      full_cmt.cat_sprnt(",%s\"%s\"", add_newline ? "\n  " : " ", params[i].c_str());
      // print args betwen { } on one line
      if ( params[i] == "{" )
        add_newline = false;
      else if ( params[i] == "}" )
        add_newline = true;
    }
    full_cmt.append(")");
  }
  else
  {
    full_cmt.sprnt("__annotation(\"%s\"", params[0].c_str());
    for ( size_t i = 1; i < params.size(); i++ )
      full_cmt.cat_sprnt(", \"%s\"", params[i].c_str());
    full_cmt.append(")");
  }
  set_cmt(ea, full_cmt.c_str(), false);
}

//----------------------------------------------------------------------------
bool pdb_til_builder_t::handle_symbol_at_ea(
        pdb_sym_t &sym,
        DWORD tag, DWORD /*id*/,
        ea_t ea,
        qstring &name)
{
  int maybe_func = 0;
  switch ( tag )
  {
    case SymTagFunction:
    case SymTagThunk:
      maybe_func = 1;
      break;
    case SymTagBlock:
    case SymTagLabel:
    case SymTagFuncDebugStart:
    case SymTagFuncDebugEnd:
      maybe_func = 2;
      break;
    case SymTagData:
    case SymTagVTable:
      maybe_func = -1;
      break;
    case SymTagPublicSymbol:
      {
        BOOL b;
        if ( sym.get_function(&b) == S_OK && b )
          maybe_func = 1;
      }
      break;
    case SymTagAnnotation:
      {
        struct annotation_value_collector_t : public pdb_access_t::children_visitor_t
        {
          const til_builder_t *tb;
          qstrvec_t ann_params;
          HRESULT visit_child(pdb_sym_t &child)
          {
            qstring v;
            if ( tb->get_variant_string_value(&v, child) )
              //set_cmt(ea, v.c_str(), false);
              ann_params.push_back(v);
            return S_OK;
          }
          annotation_value_collector_t(const til_builder_t *_tb)
            : tb(_tb) {}
        };
        annotation_value_collector_t avc(this);
        pdb_access->iterate_children(sym, SymTagNull, avc);
        apply_annotation(ea, avc.ann_params);
        maybe_func = segtype(ea) == SEG_CODE ? 2 /*no func, but code*/ : 0 /*unclear*/;
      }
      break;
    default:
      break;
  }

  // symbols starting with __imp__ can not be functions
  if ( strncmp(name.c_str(), "__imp__", 7) == 0 )
  {
    doDwrd(ea, 4);
    maybe_func = -1;
  }

  BOOL is_code;
  if ( sym.get_code(&is_code) == S_OK && !is_code )
  {
    // not a function
    maybe_func = -1;
  }

  tpinfo_t tpi;
  if ( get_symbol_type(&tpi, sym, NULL) )
  {
    // Apparently _NAME_ is a wrong symbol generated for file names
    // It has wrong type information, so correct it
    if ( tag == SymTagData && name == "_NAME_" && tpi.type.get_decltype() == BTF_CHAR )
      tpi.type = tinfo_t::get_stock(STI_ACHAR); // char []
    if ( tag == SymTagFunction )
    {
      // convert the type again, this time passing function symbol
      // this allows us to get parameter names and handle static class methods
      pdb_sym_t func_sym(*pdb_access);
      if ( sym.get_type(&func_sym) == S_OK )
      {
        tpinfo_t tpi2;
        if ( really_convert_type(&tpi2, func_sym, &sym, SymTagFunctionType) == cvt_ok )
          tpi.type.swap(tpi2.type); // successfully retrieved
      }
    }
    if ( tpi.type.is_func() || tag == SymTagFunction )
    {
      maybe_func = 1;
      handle_function_type(sym, ea);
    }
    else
    {
      maybe_func = -1;
    }
    if ( npass != 0 )
    {
      bool use_ti = true;
      func_type_data_t fti;
      if ( tpi.type.get_func_details(&fti)
         && fti.empty()
         && fti.rettype.is_decl_void() )
      { // sometimes there are functions with linked FunctionType but no parameter or return type info in it
        // we get better results by not forcing type info on them
        use_ti = false;
      }
      if ( use_ti )
      {
        type_created(ea, 0, NULL, tpi.type);
        apply_tinfo2(ea, tpi.type, 0);
      }
    }
  }
  else if ( maybe_func == 1 )
  {
    auto_make_proc(ea); // certainly a func
  }
  apply_name_in_idb(ea, name, maybe_func, pdb_access->get_machine_type());
  return true;
}

//---------------------------------------------------------------------------
HRESULT pdb_til_builder_t::handle_function_child(
        pdb_sym_t &fun_sym,
        ea_t ea,
        pdb_sym_t &child_sym,
        DWORD child_tag,
        DWORD child_loc_type)
{
  LONG offset;
  DWORD reg_id;
  switch ( child_loc_type )
  {
    case LocIsEnregistered:
      if ( child_sym.get_registerId(&reg_id) == S_OK )
      {
        if ( enregistered_bug && reg_id > 0 )
          reg_id--;
        func_t *pfn = get_func(ea);
        qstring name;
        child_sym.get_name(&name);
        const char *canon = print_pdb_register(pdb_access->get_machine_type(), reg_id);
        if ( pfn != NULL )
          add_regvar(pfn, pfn->startEA, pfn->endEA, canon, name.c_str(), NULL);
      }
      break;

    case LocIsRegRel:
      if ( child_sym.get_registerId(&reg_id) == S_OK
        && child_sym.get_offset(&offset) == S_OK
        && reg_id == CV_REG_EBP )     // we can handle only ebp for the moment
      {
        func_t *pfn = get_func(ea);
        if ( pfn != NULL )
        {
          qstring name;
          child_sym.get_name(&name);
          tpinfo_t tpi;
          if ( get_symbol_type(&tpi, child_sym, NULL) )
          {
            opinfo_t mt;
            size_t size;
            flags_t flags;
            if ( get_idainfo_by_type3(tpi.type, &size, &flags, &mt, NULL) )
            {
              // DIA's offset is bp-based, not frame-based like in IDA
              offset -= pfn->fpd;
              if ( is_arm(pdb_access->get_machine_type()) && reg_id == CV_ARM_SP )
                offset -= pfn->frsize;
              // make sure the new variable is not overwriting the return address
              // for some reason some PDBs have bogus offsets for some params/locals...
              if ( pdb_access->get_machine_type() != CV_CFL_80386
                || offset > 0
                || size <= -offset )
              {
                if ( add_stkvar2(pfn, name.c_str(), offset, flags, &mt, size) )
                {
                  cmd.ea = pfn->startEA;
                  member_t *mptr = get_stkvar(*(op_t*)NULL, offset, NULL); //lint !e413 deref null ptr
                  if ( mptr != NULL )
                  {
                    struc_t *sptr = get_frame(pfn);
                    set_member_tinfo2(sptr, mptr, 0, tpi.type, 0);
                    set_userti(mptr->id);
                  }
                  cmd.ea = BADADDR;
                }
              }
            }
          }
          else // no type info...
          {
            msg("%a: stkvar '%s' with no type info\n", ea, name.c_str());
          }
        }
      }
      break;
    default:
      return til_builder_t::handle_function_child
        (fun_sym, ea, child_sym, child_tag, child_loc_type);
  }
  return S_OK;
}

//---------------------------------------------------------------------------
void pdb_til_builder_t::handle_function_type(pdb_sym_t &sym, ea_t ea)
{
  if ( npass == 0 )
  {
    if ( !create_insn(ea) )
      return;

    // add the address to the queue - this will help to determine better function boundaries
    auto_make_proc(ea);
  }
  else
  {
    ea_t end = BADADDR;
    DWORD64 ulLen;
    if ( sym.get_length(&ulLen) == S_OK )
      end = ea + asize_t(ulLen);
    ea_t next_planned = peek_auto_queue(ea+1, AU_PROC);

    // before adding a function, try to create all its instructions.
    // without this the frame analysis may fail.
    func_t fn;
    clear_func_struct(&fn);
    fn.startEA = ea;
    find_func_bounds(ea, &fn, FIND_FUNC_DEFINE);

    bool created = false;
    bool acceptable_end = end <= next_planned;   // end is wrong for fragmented functions
    if ( acceptable_end )
      created = add_func(ea, end);
    if ( !created )
      add_func(ea, BADADDR);

    til_builder_t::handle_function_type(sym, ea);
  }
}

//---------------------------------------------------------------------------
static HRESULT common_handler(pdb_access_t &pdb_access)
{
  try
  {
    pdb_til_builder_t builder(idati, &pdb_access);
    pdb_sym_t global(pdb_access, pdb_access.get_global_symbol_id());
    return builder.build(global);
  }
  catch ( const pdb_exception_t &e )
  {
    msg("Couldn't parse PDB data: %s\n", e.what.c_str());
    return E_FAIL;
  }
}

//---------------------------------------------------------------------------
#ifdef ENABLE_REMOTEPDB
// On Unix computers use remote_pdb_access
static HRESULT remote_handler(const pdbargs_t &args)
{
  int chosen_remote_port = pdb_remote_port;
  if ( pdb_remote_port_64 != -1 && inf.is_64bit() )
    chosen_remote_port = pdb_remote_port_64;
  remote_pdb_access_t remote_pdb_access(args,
                                        pdb_remote_server,
                                        chosen_remote_port,
                                        pdb_remote_passwd);
  HRESULT hr = remote_pdb_access.open_connection();
  if ( hr == S_OK )
    hr = common_handler(remote_pdb_access);
  return hr;
}

#endif


/*====================================================================
                      IDA PRO INTERFACE START HERE
====================================================================*/

//--------------------------------------------------------------------------
// terminate
void idaapi term(void)
{
  namelist.clear();
#ifndef ENABLE_REMOTEPDB
#ifdef ENABLE_SRCDBG
  unregister_srcinfo_provider(&g_pdb_provider);
#endif
#endif
}

//--------------------------------------------------------------------------
// callback for parsing config file
const char *idaapi parse_options(
        const char *keyword,
        int value_type,
        const void *value)
{
  {
    bool is_port = false, is_port_64 = false;
    if ( strcmp(keyword, "PDB_REMOTE_PORT") == 0 )
    {
      is_port = true;
    }
    else if ( strcmp(keyword, "PDB_REMOTE_PORT_64") == 0 )
    {
      is_port = true;
      is_port_64 = true;
    }
    if ( is_port )
    {
      if ( value_type != IDPOPT_NUM )
        return IDPOPT_BADTYPE;
      uval_t val = *(uval_t*)value;
      if ( val == 0 || val > 65535 )
        return IDPOPT_BADVALUE;
      if ( is_port_64 )
        pdb_remote_port_64 = int(val);
      else
        pdb_remote_port = int(val);
      return IDPOPT_OK;
    }
  }

  if ( value_type != IDPOPT_STR )
    return IDPOPT_BADTYPE;

  if ( strcmp(keyword, "PDBSYM_DOWNLOAD_PATH") == 0 )
  {
    qstrncpy(download_path, (const char *)value, sizeof(download_path));
    // empty string used for ida program directory
    if ( download_path[0] != '\0' && !qisdir(download_path) )
      return IDPOPT_BADVALUE;
  }
  else if ( strcmp(keyword, "PDBSYM_SYMPATH") == 0 )
  {
    qstrncpy(full_sympath, (const char *)value, sizeof(full_sympath));
    return IDPOPT_OK;
  }
  else if ( strcmp(keyword, "PDB_REMOTE_SERVER") == 0 )
  {
    qstrncpy(pdb_remote_server, (const char *)value, sizeof(pdb_remote_server));
    // empty string used for ida program directory
    if ( pdb_remote_server[0] == '\0' )
      return IDPOPT_BADVALUE;
  }
  else if ( strcmp(keyword, "PDB_REMOTE_PASSWD") == 0 )
  {
    qstrncpy(pdb_remote_passwd, (const char *)value, sizeof(pdb_remote_passwd));
    // empty string used for ida program directory
    if ( pdb_remote_server[0] == '\0' )
      return IDPOPT_BADVALUE;
  }
  else
  {
    return IDPOPT_BADKEY;
  }


  return IDPOPT_OK;
}

//----------------------------------------------------------------------
uint32 get_machine_from_idb()
{
  uint32 mt;
  switch ( ph.id )
  {
    case PLFM_ARM:
      mt = CV_CFL_ARM6;
      break;
    case PLFM_MIPS:
      mt = CV_CFL_MIPSR4000;
      break;
    case PLFM_PPC:
      mt = inf.mf ? CV_CFL_PPCBE : CV_CFL_PPCFP;
      break;
    case PLFM_SH:
      mt = CV_CFL_SH4;
      break;
    case PLFM_IA64:
      mt = CV_CFL_IA64;
      break;
    case PLFM_386:
    default:
      mt = CV_CFL_80386;
      break;
  }
  return mt;
}

//----------------------------------------------------------------------
static void init_sympaths()
{
  // user specified symbol path?
  download_path[0] = '\0';
  full_sympath[0] = '\0';
  read_user_config_file("pdb", parse_options);

  // if download path is set, format the path for Microsoft symbol server
  if ( full_sympath[0] == '\0' && download_path[0] != '\0' )
    qsnprintf(full_sympath, sizeof(full_sympath), "%s%s%s", spath_prefix, download_path, spath_suffix);
}

//----------------------------------------------------------------------
#ifndef ENABLE_REMOTEPDB
// If path name is too long then replace some directories with "...."
static qstring truncate_path(const qstring &path)
{
  qstring str = path;
  int len = str.length();
  if ( len > MAX_DISP_PATH )
  {
    char slash = '\\';
    size_t start =  str.find(slash);
    if ( start == qstring::npos )
    {
      slash = '/';
      start =  str.find(slash);
    }
    if ( start != qstring::npos )
    {
      size_t end = str.rfind(slash);
      size_t prev_start;
      do
      {
        prev_start = start;
        start = str.find(slash, start + 1);
      } while ( len - (end - start) < MAX_DISP_PATH );
      start = prev_start + 1;
      if  ( end > start )
      {
        str.remove(start, end - start);
        str.insert(start, "....");
      }
    }
  }
  return str;
}
#endif

//----------------------------------------------------------------------------
static bool read_pdb_signature(pdb_signature_t *pdb_sign)
{
  netnode penode(PE_NODE);
  rsds_t rsds;
  size_t size = sizeof(rsds_t);
  if ( penode.getblob(&rsds, &size, 0, RSDS_TAG) != NULL && size == sizeof(rsds_t) ) //RSDS
  {
    pdb_sign->age = rsds.age;
    pdb_sign->sig = 0;
    memcpy(pdb_sign->guid, &rsds.guid, sizeof(pdb_sign->guid));
    CASSERT(sizeof(pdb_sign->guid) == sizeof(rsds.guid));
  }
  else
  {
    cv_info_pdb20_t nb10;
    size = sizeof(nb10);
    if ( penode.getblob(&nb10, &size, 0, NB10_TAG) != NULL && size == sizeof(nb10) ) // NB10
    {
      pdb_sign->age = nb10.age;
      pdb_sign->sig = nb10.signature;
    }
    else
    {
      return false;
    }
  }
  return true;
}

//----------------------------------------------------------------------------
// moved into a separate function to diminish the stack consumption
static qstring get_input_path()
{
  char input_path[QMAXPATH];
  if ( get_input_file_path(input_path, sizeof(input_path)) <= 0 )
    input_path[0] = '\0';
  return input_path;
}

//----------------------------------------------------------------------------
// moved into a separate function to diminish the stack consumption
static qstring get_supval(netnode node, uval_t idx)
{
  char buf[QMAXPATH];
  if ( node.supstr(idx, buf, sizeof(buf)) <= 0 )
    buf[0] = '\0';
  return buf;
}

//--------------------------------------------------------------------------
static int idaapi details_modcb(int fid, form_actions_t &fa)
{
  switch ( fid )
  {
    // "Types only"
    case 20:
      {
        ushort c;
        if ( fa.get_checkbox_value(20, &c) )
          fa.enable_field(10, c == 0); // enable/disable address field
      }
      break;
  }

  return 1;
}

//-------------------------------------------------------------------------
static void set_file_by_ext(pdbargs_t *args, const char *buf)
{
  const char *ext = get_file_ext(buf);
  if ( ext != NULL && strieq(ext, "pdb") )
  {
    args->pdb_path = buf;
    args->input_path.clear();
  }
  else
  {
    args->input_path = buf;
    args->pdb_path.clear();
  }
}

//----------------------------------------------------------------------------
// moved into a separate function to diminish the stack consumption
static bool ask_pdb_details(pdbargs_t *args)
{
  static const char form[] =
    "Load PDB file\n"
    "%/"
    "<#Specify the path to the file to load symbols for#~I~nput file:f:0:64::>\n"
    "<#Specify the loading address of the exe/dll file#~A~ddress   :N10::64::>\n"
    "<#Load only types, do not rename program locations#~T~ypes only:C20>>\n"
    "Note: you can specify either a .pdb, or an .exe/.dll file name.\n"
    "In the latter case, IDA will try to find and load\n"
    "the PDB specified in its debug directory.\n"
    "\n";

  char buf[QMAXPATH];
  const char *src = NULL;
  if ( !args->pdb_path.empty() )
    src = args->pdb_path.begin();
  else if ( !args->input_path.empty() )
    src = args->input_path.begin();
  if ( src == NULL )
    buf[0] = '\0';
  else
    qstrncpy(buf, src, sizeof(buf));

  CASSERT(sizeof(args->loaded_base) == sizeof(ea_t));
  sval_t typesonly = (args->flags & PDBFLG_ONLY_TYPES) != 0;
  if ( !AskUsingForm_c(form, details_modcb, buf, &args->loaded_base, &typesonly) )
    return false;

  set_file_by_ext(args, buf);

  setflag(args->flags, PDBFLG_ONLY_TYPES, typesonly != 0);
  return true;
}

//----------------------------------------------------------------------------
// Main function: do the real job here
void idaapi run(int _call_code)
{
  pdbargs_t pdbargs;
  if ( inf.filetype != f_PE && !is_miniidb() )
    pdbargs.flags |= PDBFLG_ONLY_TYPES;

  netnode pdbnode;
  pdbnode.create(PDB_NODE_NAME);

  netnode penode(PE_NODE);
  penode.valobj(&pe, sizeof(pe));

  pdb_callcode_t call_code = (pdb_callcode_t)_call_code;
  pdbargs.pdb_path = get_supval(penode, PE_SUPSTR_PDBNM);

  // loading additional dll?
  if ( call_code == PDB_CC_DBG_MODULE_LOAD )
  { // user explicitly asked to load debug info for a module
    pdbargs.flags |= PDBFLG_DBG_MODULE;
    pdbargs.loaded_base = pdbnode.altval(PDB_DLLBASE_NODE_IDX);
    QASSERT(30168, pdbargs.loaded_base != 0);
    pdbargs.input_path = get_supval(pdbnode, PDB_DLLNAME_NODE_IDX);
    PLUGIN.flags &= ~PLUGIN_UNL;
  }
  else
  {
    pdbargs.input_path = get_input_path();
    pdbargs.loaded_base = penode.altval(PE_ALT_IMAGEBASE);
    if ( call_code == PDB_CC_USER ) // user explicitly invoked the plugin?
    {
      if ( !ask_pdb_details(&pdbargs) )
        return;
    }
    else if ( call_code == PDB_CC_USER_WITH_DATA )
    {
      pdbargs.loaded_base = pdbnode.altval(PDB_DLLBASE_NODE_IDX);
      QASSERT(30479, pdbargs.loaded_base != 0);
      qstring tmp = get_supval(pdbnode, PDB_DLLNAME_NODE_IDX);
      set_file_by_ext(&pdbargs, tmp.c_str());
    }
    else
    {
      if ( call_code == PDB_CC_IDA )
      {
        const char *fname = pdbargs.fname();
        if ( askyn_c(ASKBTN_YES,
                     "AUTOHIDE REGISTRY\nHIDECANCEL\n"
                     "IDA has determined that the input file was linked with debug information, and the symbol filename is:\n"
                     "'%s'\n"
                     "Do you want to look for this file at the local symbol store\n"
                     "and the Microsoft Symbol Server?", fname) != ASKBTN_YES )
        {
          return;
        }
      }
    }
    // read pdb signature from the database, if any
    if ( !read_pdb_signature(&pdbargs.pdb_sign) )
    {
      // make it invalid but not empty
      // so that check_and_load_pdb() does not fail silently
      pdbargs.pdb_sign.age = 0xFFFFFFFF;
    }
  }


  init_sympaths();
  if ( full_sympath[0] != '\0' )
    pdbargs.spath = full_sympath;

  bool ok = true;

#ifdef ENABLE_REMOTEPDB
  HRESULT hr = remote_handler(pdbargs);
#else
LOAD_PDB:
  HRESULT hr;
  bool was_load_error = false;
  try
  {
    pdb_session_ref_t ref;
    hr = ref.open_session(pdbargs);
    if ( SUCCEEDED(hr) )
      hr = common_handler(*ref.session->pdb_access);
  }
  catch ( const std::bad_alloc & )
  {
    warning("It appears IDA has run out of memory while loading the PDB file.\n"
            "This can happen when using the DIA SDK dll with big and/or corrupt PDBs.\n"
            "While you will now be able to continue your work, IDA cannot proceed with PDB parsing, sorry.\n\n"
            "It is also HIGHLY recommended that you save the database as soon as possible,\n"
            "quit, and restart IDA with that database.");
    hr = E_PDB_OUT_OF_MEMORY;
    was_load_error = true;
  }
#endif

  if ( pdbargs.input_path.empty() )
    pdbargs.input_path = pdbargs.pdb_path;

  if ( FAILED(hr) )
  {
    ok = false;
#ifndef ENABLE_REMOTEPDB
    const char *err_str = pdberr(hr);
    msg("PDB: could not process file %s with DIA: %s\n", pdbargs.input_path.c_str(), err_str);
    pdberr_suggest_vs_runtime(hr);

    // DIA interface failed, try the old methods
    if ( hr != E_PDB_INVALID_SIG
      && hr != E_PDB_INVALID_AGE
      && hr != E_PDB_NOT_FOUND
      && hr != E_PDB_INVALID_EXECUTABLE )
    {
      g_machine_type = get_machine_from_idb(); // See 'g_machine_type' comment above
      ok = old_pdb_plugin(pdbargs.loaded_base, pdbargs.input_path.c_str(), pdbargs.spath);
      if ( ok )
        msg("Old method of loading PDB files (dbghelp) was successful\n");
    }
    if ( !was_load_error && !ok )
    {
      was_load_error = true;
      qstring disp_path = truncate_path(pdbargs.input_path);
      if ( askyn_c(ASKBTN_YES,
                   "HIDECANCEL\nAUTOHIDE REGISTRY\n%s: failed to load pdb info.\n%s\n"
                   "Do you want to browse for the pdb file on disk?",
                   disp_path.c_str(),
                   err_str == NULL ? "" : err_str) == ASKBTN_YES )
      {
        char *pdb_file = askfile_c(false, "*.pdb", "Choose PDB file");
        if ( pdb_file != NULL )
        {
          pdbargs.pdb_path = pdb_file;
          goto LOAD_PDB;
        }
      }
    }
#endif
  }

  if ( ok && (pdbargs.flags & PDBFLG_ONLY_TYPES) == 0 )
  {
    // Now all information is loaded into the database (except names)
    // We are ready to use names.
    int counter = 0;
    for ( namelist_t::iterator p=namelist.begin(); p != namelist.end(); ++p )
    {
      if ( pdbargs.is_dbg_module() )
        counter += set_debug_name(p->first, p->second.c_str());
      else
        counter += do_name_anyway(p->first, p->second.c_str());
      // Every now & then, make sure the UI has had a chance to refresh.
      if ( (counter % 10) == 0 )
        wasBreak();
    }
    namelist.clear();
    msg("PDB: total %d symbol%s loaded for %s\n",
        counter,
        counter != 1 ? "s" : "",
        pdbargs.input_path.c_str());
  }

  pdbnode.altset(PDB_DLLBASE_NODE_IDX, ok);
  check_added_types();
}

//--------------------------------------------------------------------------
// initialize plugin
int idaapi init(void)
{
  const char *opts = get_plugin_options("pdb");
  if ( opts != NULL && strcmp(opts, "off") == 0 )
    return PLUGIN_SKIP;
#if !defined(ENABLE_REMOTEPDB) && defined(ENABLE_SRCDBG)
  if ( register_srcinfo_provider(&g_pdb_provider) )
    return PLUGIN_KEEP;
  else
#endif
    return PLUGIN_OK;
}

//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_MOD | PLUGIN_HIDE, // plugin flags:
  init,                 // initialize

  term,                 // terminate. this pointer may be NULL.

  run,          // invoke plugin

  // long comment about the plugin
  // it could appear in the status line
  // or as a hint
  "Load debug information from a PDB file",

  // multiline help about the plugin
  "PDB file loader\n"
  "\n"
  "This module allows you to load debug information about function names\n"
  "from a PDB file.\n"
  "\n"
  "The PDB file should be in the same directory as the input file\n",

  // the preferred short name of the plugin
  "Load PDB file (dbghelp 4.1+)",
  // the preferred hotkey to run the plugin
  ""
};


//lint -esym(766, md5.h, diskio.hpp) Unused header files.
